from __future__ import annotations

import gzip
import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "src" / "stackscan" / "data" / "cve.json.gz"
BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PRODUCTS: dict[str, str] = {
    "nginx": "f5:nginx",
    "apache": "apache:http_server",
    "tomcat": "apache:tomcat",
    "openssh": "openbsd:openssh",
    "php": "php:php",
    "openssl": "openssl:openssl",
    "exim": "exim:exim",
    "proftpd": "proftpd:proftpd",
    "jquery": "jquery:jquery",
    "wordpress": "wordpress:wordpress",
    "drupal": "drupal:drupal",
    "joomla": "joomla:joomla",
    "mysql": "oracle:mysql",
    "mariadb": "mariadb:mariadb",
    "postgresql": "postgresql:postgresql",
    "redis": "redis:redis",
    "mongodb": "mongodb:mongodb",
    "elasticsearch": "elastic:elasticsearch",
    "nodejs": "nodejs:node.js",
    "lighttpd": "lighttpd:lighttpd",
    "haproxy": "haproxy:haproxy",
    "iis": "microsoft:internet_information_services",
    "dovecot": "dovecot:dovecot",
    "postfix": "postfix:postfix",
    "bind": "isc:bind",
    "squid": "squid-cache:squid",
    "grafana": "grafana:grafana",
    "gitlab": "gitlab:gitlab",
    "jenkins": "jenkins:jenkins",
    "phpmyadmin": "phpmyadmin:phpmyadmin",
    "vsftpd": "vsftpd_project:vsftpd",
}
_PAGE = 2000
_MAX_SUMMARY = 260


def _headers() -> dict[str, str]:
    headers = {"User-Agent": "stackscan-cve-builder/2.0"}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers


def fetch_page(vendor_product: str, start: int) -> dict[str, Any]:
    cpe = f"cpe:2.3:a:{vendor_product}"
    url = f"{BASE}?virtualMatchString={quote(cpe)}&resultsPerPage={_PAGE}&startIndex={start}"
    request = Request(url, headers=_headers())
    for attempt in range(5):
        try:
            with urlopen(request, timeout=60) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as exc:
            if exc.code in (403, 429, 503) and attempt < 4:
                time.sleep(12 * (attempt + 1))
                continue
            raise
        except (URLError, TimeoutError):
            if attempt < 4:
                time.sleep(6 * (attempt + 1))
                continue
            raise
    raise RuntimeError(f"exhausted retries for {vendor_product}@{start}")


def best_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = metrics.get(key)
        if entries:
            data = entries[0]["cvssData"]
            return (float(data["baseScore"]), str(data["baseSeverity"]).upper())
    entries = metrics.get("cvssMetricV2")
    if entries:
        data = entries[0]
        score = float(data["cvssData"]["baseScore"])
        return (score, str(data.get("baseSeverity", "")).upper() or _band(score))
    return (None, None)


def _band(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "NONE"


def english_summary(descriptions: list[dict[str, str]]) -> str:
    for desc in descriptions:
        if desc.get("lang") == "en":
            return " ".join(desc["value"].split())[:_MAX_SUMMARY]
    return ""


def ranges_for(cve: dict[str, Any], needle: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for conf in cve.get("configurations", []):
        for node in conf.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                criteria = cpe.get("criteria", "")
                if needle not in criteria:
                    continue
                entry: dict[str, str] = {}
                if cpe.get("versionStartIncluding"):
                    entry["start_incl"] = cpe["versionStartIncluding"]
                if cpe.get("versionStartExcluding"):
                    entry["start_excl"] = cpe["versionStartExcluding"]
                if cpe.get("versionEndIncluding"):
                    entry["end_incl"] = cpe["versionEndIncluding"]
                if cpe.get("versionEndExcluding"):
                    entry["end_excl"] = cpe["versionEndExcluding"]
                parts = criteria.split(":")
                if not entry and len(parts) > 5 and (parts[5] not in ("*", "-")):
                    entry["start_incl"] = parts[5]
                    entry["end_incl"] = parts[5]
                if entry and entry not in out:
                    out.append(entry)
    return out


def _skip_entry(cve: dict[str, Any]) -> bool:
    status = str(cve.get("vulnStatus", "")).upper()
    if status in {"REJECTED", "REPLACED", "DEPRECATED"}:
        return True
    descriptions = cve.get("descriptions") or []
    if not english_summary(descriptions):
        return True
    return False


def collect(product: str, vendor_product: str, throttle: float) -> list[dict[str, Any]]:
    needle = ":" + vendor_product + ":"
    entries: list[dict[str, Any]] = []
    start = 0
    total = None
    while total is None or start < total:
        payload = fetch_page(vendor_product, start)
        total = int(payload.get("totalResults", 0))
        vulns = payload.get("vulnerabilities") or []
        for wrapper in vulns:
            cve = wrapper["cve"]
            if _skip_entry(cve):
                continue
            ranges = ranges_for(cve, needle)
            if not ranges:
                continue
            score, severity = best_cvss(cve.get("metrics", {}))
            entries.append(
                {
                    "id": cve["id"],
                    "cvss": score,
                    "severity": severity or "UNKNOWN",
                    "summary": english_summary(cve.get("descriptions", [])),
                    "ranges": ranges,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve['id']}",
                }
            )
        got = len(vulns)
        start += got if got else _PAGE
        print(
            f"  {product}: {min(start, total or start)}/{total} (kept {len(entries)})", flush=True
        )
        if got:
            time.sleep(throttle)
    entries.sort(key=lambda e: e["id"], reverse=True)
    return entries


def main() -> None:
    throttle = 0.7 if os.environ.get("NVD_API_KEY") else 6.5
    products: dict[str, list[dict[str, Any]]] = {}
    for product, vendor_product in PRODUCTS.items():
        print(f"fetching {product} ({vendor_product})...", flush=True)
        try:
            products[product] = collect(product, vendor_product, throttle)
        except Exception as exc:
            print(f"  !! {product} failed: {exc}")
            products[product] = []
        time.sleep(throttle)
    dataset = {
        "source": "NVD 2.0 API (https://services.nvd.nist.gov)",
        "note": "All CVEs per product with parsed version ranges; scan-time matching is offline.",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "products": products,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(dataset, ensure_ascii=False).encode("utf-8")
    with gzip.open(OUT, "wb", compresslevel=9) as fh:
        fh.write(payload)
    total = sum(len(v) for v in products.values())
    print(f"wrote {total} CVEs across {len(products)} products -> {OUT}")


if __name__ == "__main__":
    main()
