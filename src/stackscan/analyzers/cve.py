from __future__ import annotations

import asyncio
import gzip
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import resources
from typing import Any, cast

from stackscan.types import CveMatch, Headers, PortScan, Software

CveEntry = dict[str, Any]
_BACKPORT_DISTRO_RE = re.compile(
    r"(0?ubuntu0?[._]\d[\d.]+)"
    r"|(\+deb\d+u?\d*)"
    r"|(-\d+ubuntu\d+(?![\d._]))"
    r"|\b(ubuntu|debian|centos|rhel|fedora|amzn|raspbian|alpine|rocky|almalinux)\b"
    r"|(el\d+)"
    r"|(\.fc\d+)"
    r"|(~bpo\d+\+[\w]+)",
    re.I,
)
CveDb = dict[str, list[CveEntry]]
_NAME_MAP: dict[str, str] = {
    "nginx": "nginx",
    "apache": "apache",
    "httpd": "apache",
    "php": "php",
    "openssl": "openssl",
    "exim": "exim",
    "tomcat": "tomcat",
    "coyote": "tomcat",
    "proftpd": "proftpd",
    "openssh": "openssh",
    "jquery": "jquery",
    "wordpress": "wordpress",
    "drupal": "drupal",
    "joomla": "joomla",
    "mysql": "mysql",
    "mariadb": "mariadb",
    "postgresql": "postgresql",
    "postgres": "postgresql",
    "redis": "redis",
    "mongodb": "mongodb",
    "elasticsearch": "elasticsearch",
    "node": "nodejs",
    "nodejs": "nodejs",
    "lighttpd": "lighttpd",
    "haproxy": "haproxy",
    "iis": "iis",
    "microsoft-iis": "iis",
    "dovecot": "dovecot",
    "postfix": "postfix",
    "bind": "bind",
    "squid": "squid",
    "grafana": "grafana",
    "gitlab": "gitlab",
    "jenkins": "jenkins",
    "phpmyadmin": "phpmyadmin",
    "vsftpd": "vsftpd",
}
_CPE_MAP: dict[str, str] = {
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
_TOKEN_RE = re.compile("([A-Za-z][A-Za-z0-9._+-]*?)[/ ]v?(\\d+(?:\\.\\d+){0,3})")
_JQUERY_RE = re.compile("jquery[-/]?v?(\\d+\\.\\d+(?:\\.\\d+)?)", re.IGNORECASE)
_GENERATOR_RE = re.compile(
    "<meta[^>]+name=[\\\"']generator[\\\"'][^>]+content=[\\\"']([^\\\"']+)[\\\"']", re.IGNORECASE
)
_SSH_RE = re.compile("openssh[_/-]?(\\d+\\.\\d+(?:p\\d+)?)", re.IGNORECASE)


@lru_cache(maxsize=1)
def load_cve_db() -> CveDb:
    empty: CveDb = {}
    try:
        raw = resources.files("stackscan.data").joinpath("cve.json.gz").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return empty
    try:
        data = cast("dict[str, Any]", json.loads(gzip.decompress(raw)))
    except (OSError, json.JSONDecodeError):
        return empty
    products = data.get("products")
    if not isinstance(products, dict):
        return empty
    return cast("CveDb", products)


def _distro_tag(text: str) -> str:
    match = _BACKPORT_DISTRO_RE.search(text)
    return match.group(0) if match else ""


def _parse_version(value: str) -> tuple[tuple[int, str], ...]:
    parts: list[tuple[int, str]] = []
    for chunk in re.split("[.\\-_]", value.strip()):
        match = re.match("(\\d*)(.*)", chunk)
        number = int(match.group(1)) if match and match.group(1) else 0
        suffix = (match.group(2) if match else "").lower()
        parts.append((number, suffix))
    return tuple(parts)


def _cmp(a: str, b: str) -> int:
    va, vb = (_parse_version(a), _parse_version(b))
    width = max(len(va), len(vb))
    pad = ((0, ""),)
    va += pad * (width - len(va))
    vb += pad * (width - len(vb))
    return (va > vb) - (va < vb)


def _in_range(version: str, rng: dict[str, str]) -> bool:
    if "start_incl" in rng and _cmp(version, rng["start_incl"]) < 0:
        return False
    if "start_excl" in rng and _cmp(version, rng["start_excl"]) <= 0:
        return False
    if "end_incl" in rng and _cmp(version, rng["end_incl"]) > 0:
        return False
    if "end_excl" in rng and _cmp(version, rng["end_excl"]) >= 0:
        return False
    return bool(rng)


def _tokens(value: str, source: str, location: str, os: str = "") -> list[Software]:
    found: list[Software] = []
    for name, version in _TOKEN_RE.findall(value):
        found.append(
            Software(name=name.lower(), version=version, source=source, location=location, os=os)
        )
    return found


def extract_software(headers: Headers, body: str, location: str = "") -> list[Software]:
    software: list[Software] = []
    seen: set[tuple[str, str | None]] = set()

    def add(item: Software) -> None:
        key = (item.name, item.version)
        if key not in seen:
            seen.add(key)
            software.append(item)

    server = headers.get("server")
    if server:
        server_os = _distro_tag(server)
        for item in _tokens(server, "header:server", location, os=server_os):
            add(item)
    powered = headers.get("x-powered-by")
    if powered:
        for item in _tokens(powered, "header:x-powered-by", location):
            add(item)
    jquery = _JQUERY_RE.search(body)
    if jquery:
        add(Software(name="jquery", version=jquery.group(1), source="script", location=location))
    generator = _GENERATOR_RE.search(body)
    if generator:
        text = generator.group(1).strip()
        gmatch = re.match("([A-Za-z][A-Za-z0-9 ]*?)\\s+(\\d+(?:\\.\\d+){0,3})", text)
        if gmatch:
            add(
                Software(
                    name=gmatch.group(1).strip().lower().replace(" ", ""),
                    version=gmatch.group(2),
                    source="meta:generator",
                    location=location,
                )
            )
    return software


def software_from_ports(scan: PortScan | None) -> list[Software]:
    if scan is None:
        return []
    out: list[Software] = []
    for port in scan.ports:
        blob = " ".join(filter(None, (port.product, port.version, port.service)))
        if not blob:
            continue
        location = f"{port.host}:{port.port}" if port.host else f":{port.port}"
        ssh = _SSH_RE.search(blob)
        if ssh:
            out.append(
                Software(
                    name="openssh",
                    version=ssh.group(1),
                    source="port-banner",
                    location=location,
                    os=port.os,
                )
            )
            continue
        if port.product and port.version:
            out.append(
                Software(
                    name=port.product.lower().split()[0],
                    version=port.version,
                    source="port-banner",
                    location=location,
                    os=port.os,
                )
            )
    return out


_AUTHORITATIVE = {"header:server", "header:x-powered-by", "port-banner"}
_SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _confidence(version: str, rng: dict[str, str], source: str) -> int:
    comps = len([c for c in re.split("[.\\-_]", version) if c[:1].isdigit()])
    bounded = ("start_incl" in rng or "start_excl" in rng) and (
        "end_incl" in rng or "end_excl" in rng
    )
    authoritative = source in _AUTHORITATIVE
    if authoritative and bounded and comps >= 3:
        return 98
    if (authoritative or bounded) and comps >= 2:
        return 91
    return 85


@dataclass
class _CveAgg:
    id: str
    product: str
    version: str | None
    severity: str
    cvss: float | None
    confidence: int
    summary: str
    url: str | None
    locations: set[str] = field(default_factory=set[str])
    sources: set[str] = field(default_factory=set[str])
    unconfirmed: bool = False
    caveat: str = ""


def _match_entries(
    item: Software,
    product_key: str,
    entries: list[CveEntry],
    agg: dict[str, _CveAgg],
) -> None:
    version = item.version
    if not version:
        return
    backported = bool(item.os)
    caveat = "distro backport likely — patchlevel not in banner" if backported else ""
    for entry in entries:
        ranges = cast("list[dict[str, str]]", entry.get("ranges") or [])
        hit_rng = next((r for r in ranges if _in_range(version, r)), None)
        if hit_rng is None:
            continue
        cve_id = str(entry["id"])
        confidence = 40 if backported else _confidence(version, hit_rng, item.source)
        record = agg.get(cve_id)
        if record is None:
            record = _CveAgg(
                id=cve_id,
                product=product_key,
                version=version,
                severity=str(entry.get("severity", "UNKNOWN")),
                cvss=entry.get("cvss"),
                confidence=confidence,
                summary=str(entry.get("summary", "")),
                url=entry.get("url"),
                unconfirmed=backported,
                caveat=caveat,
            )
            agg[cve_id] = record
        if item.location:
            record.locations.add(item.location)
        if item.source:
            record.sources.add(item.source)
        if backported:
            record.unconfirmed = True
            record.caveat = caveat
            record.confidence = min(record.confidence, 40)
        elif confidence > record.confidence:
            record.confidence = confidence
            record.version = version


def _agg_to_matches(agg: dict[str, _CveAgg]) -> list[CveMatch]:
    matches = [
        CveMatch(
            id=r.id,
            product=r.product,
            version=r.version,
            severity=r.severity,
            cvss=r.cvss,
            confidence=r.confidence,
            summary=r.summary,
            url=r.url,
            locations=tuple(sorted(r.locations)),
            sources=tuple(sorted(r.sources)),
            unconfirmed=r.unconfirmed,
            caveat=r.caveat,
        )
        for r in agg.values()
    ]
    return _sort_matches(matches)


def _sort_matches(matches: list[CveMatch]) -> list[CveMatch]:
    matches.sort(
        key=lambda m: (
            _SEVERITY_RANK.get(m.severity.upper(), 4),
            -(m.cvss or 0.0),
            -m.confidence,
            m.id,
        )
    )
    return matches


def merge_cve_matches(offline: list[CveMatch], online: list[CveMatch]) -> list[CveMatch]:
    from dataclasses import replace

    by_id: dict[str, CveMatch] = {}
    for match in (*offline, *online):
        existing = by_id.get(match.id)
        if existing is None:
            by_id[match.id] = match
        else:
            locations = tuple(sorted(set(existing.locations) | set(match.locations)))
            sources = tuple(sorted(set(existing.sources) | set(match.sources)))
            by_id[match.id] = replace(existing, locations=locations, sources=sources)
    return _sort_matches(list(by_id.values()))


def match_cves(software: list[Software]) -> list[CveMatch]:
    db = load_cve_db()
    agg: dict[str, _CveAgg] = {}
    for item in software:
        if not item.version:
            continue
        product_key = _NAME_MAP.get(item.name, item.name)
        entries = db.get(product_key)
        if entries:
            _match_entries(item, product_key, entries, agg)
    return _agg_to_matches(agg)


_NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _nvd_entries(payload: dict[str, Any], needle: str) -> list[CveEntry]:
    entries: list[CveEntry] = []
    vulns = cast("list[dict[str, Any]]", payload.get("vulnerabilities") or [])
    for wrapper in vulns:
        cve = cast("dict[str, Any]", wrapper.get("cve") or {})
        ranges = _nvd_ranges(cve, needle)
        if not ranges:
            continue
        score, severity = _nvd_cvss(cast("dict[str, Any]", cve.get("metrics") or {}))
        entries.append(
            {
                "id": cve.get("id", ""),
                "cvss": score,
                "severity": severity or "UNKNOWN",
                "summary": _nvd_summary(
                    cast("list[dict[str, str]]", cve.get("descriptions") or [])
                ),
                "ranges": ranges,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve.get('id', '')}",
            }
        )
    return entries


def _nvd_ranges(cve: dict[str, Any], needle: str) -> list[dict[str, str]]:
    out: list[dict[str, str]] = []
    for conf in cast("list[dict[str, Any]]", cve.get("configurations") or []):
        for node in cast("list[dict[str, Any]]", conf.get("nodes") or []):
            for cpe in cast("list[dict[str, Any]]", node.get("cpeMatch") or []):
                criteria = str(cpe.get("criteria", ""))
                if needle not in criteria:
                    continue
                entry: dict[str, str] = {}
                for src, dst in (
                    ("versionStartIncluding", "start_incl"),
                    ("versionStartExcluding", "start_excl"),
                    ("versionEndIncluding", "end_incl"),
                    ("versionEndExcluding", "end_excl"),
                ):
                    if cpe.get(src):
                        entry[dst] = str(cpe[src])
                parts = criteria.split(":")
                if not entry and len(parts) > 5 and (parts[5] not in ("*", "-")):
                    entry["start_incl"] = parts[5]
                    entry["end_incl"] = parts[5]
                if entry and entry not in out:
                    out.append(entry)
    return out


def _nvd_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30"):
        entries = cast("list[dict[str, Any]]", metrics.get(key) or [])
        if entries:
            data = cast("dict[str, Any]", entries[0]["cvssData"])
            return (float(data["baseScore"]), str(data["baseSeverity"]).upper())
    v2 = cast("list[dict[str, Any]]", metrics.get("cvssMetricV2") or [])
    if v2:
        data = cast("dict[str, Any]", v2[0]["cvssData"])
        return (float(data["baseScore"]), str(v2[0].get("baseSeverity", "")).upper() or None)
    return (None, None)


def _nvd_summary(descriptions: list[dict[str, str]]) -> str:
    for desc in descriptions:
        if desc.get("lang") == "en":
            return " ".join(desc["value"].split())[:260]
    return ""


async def match_cves_online(
    software: list[Software], *, timeout: float = 25.0, workers: int = 3
) -> list[CveMatch]:
    import aiohttp

    products: dict[str, Software] = {}
    for item in software:
        if not item.version:
            continue
        key = _NAME_MAP.get(item.name, item.name)
        if key in _CPE_MAP:
            products.setdefault(key, item)
    if not products:
        return []
    semaphore = asyncio.Semaphore(max(workers, 1))
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:

        async def lookup(product_key: str, item: Software) -> list[CveEntry]:
            vendor_product = _CPE_MAP[product_key]
            params = {"virtualMatchString": f"cpe:2.3:a:{vendor_product}", "resultsPerPage": "2000"}
            async with semaphore:
                try:
                    async with session.get(
                        _NVD_URL, params=params, headers={"User-Agent": "stackscan"}
                    ) as resp:
                        if resp.status != 200:
                            return []
                        payload = cast("dict[str, Any]", await resp.json())
                except (aiohttp.ClientError, TimeoutError, ValueError, OSError):
                    return []
            return _nvd_entries(payload, ":" + vendor_product + ":")

        gathered = await asyncio.gather(*(lookup(key, item) for key, item in products.items()))
    agg: dict[str, _CveAgg] = {}
    for (product_key, item), entries in zip(products.items(), gathered, strict=True):
        if entries:
            _match_entries(item, product_key, entries, agg)
    return _agg_to_matches(agg)
