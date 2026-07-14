from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from stackscan.types import FetchResult, Technology
from stackscan.utils import host_of

if TYPE_CHECKING:
    from sigdb.core import SigDBMatcher
    from sigdb.types import SigDBItem, SigDBMatchResult
_META_RE = re.compile("<meta\\b([^>]*)>", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile("<script\\b[^>]*\\bsrc\\s*=\\s*[\\\"']?([^\\\"'\\s>]+)", re.IGNORECASE)
_ATTR_RE = re.compile(
    "([a-zA-Z_:][\\w:.-]*)\\s*=\\s*(?:\\\"([^\\\"]*)\\\"|'([^']*)'|([^\\s\\\"'=<>`]+))"
)


def _meta_pairs(html: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    for match in _META_RE.finditer(html):
        attrs: dict[str, str] = {}
        for attr in _ATTR_RE.finditer(match.group(1)):
            name = attr.group(1).lower()
            value = attr.group(2) or attr.group(3) or attr.group(4) or ""
            attrs[name] = value
        key = attrs.get("name") or attrs.get("http-equiv") or attrs.get("property")
        content = attrs.get("content")
        if key and content:
            pairs.append((key.lower(), content))
    return pairs


def _script_srcs(html: str) -> list[str]:
    return [match.group(1) for match in _SCRIPT_SRC_RE.finditer(html)]


_CLASS_ATTR_RE = re.compile(r'\bclass\s*=\s*"([^"]*)"|\bclass\s*=\s*\'([^\']*)\'', re.I)


def _framework_tokens(html: str) -> tuple[str, ...]:
    tokens: set[str] = set()
    for match in _CLASS_ATTR_RE.finditer(html):
        value = match.group(1) or match.group(2)
        if not value:
            continue
        for token in value.split():
            token = token.strip()
            if len(token) >= 3:
                tokens.add(token)
    return tuple(tokens)


@dataclass
class _Hit:
    name: str
    category: str | None = None
    evidence: list[str] = field(default_factory=list[str])
    item: SigDBItem | None = None


_EVIDENCE_WEIGHTS: tuple[tuple[str, int], ...] = (
    ("header:", 100),
    ("cookie:", 95),
    ("meta:", 90),
    ("script_src", 85),
    ("html", 80),
    ("url", 75),
    ("body", 70),
)


def _evidence_weight(evidence: str) -> int:
    for prefix, weight in _EVIDENCE_WEIGHTS:
        if evidence.startswith(prefix):
            return weight
    return 60


def _confidence(evidence: list[str]) -> int:
    if not evidence:
        return 60
    best = max(_evidence_weight(item) for item in evidence)
    return min(100, best + 2 * (len(set(evidence)) - 1))


_VERSION_RE = re.compile(r"(\d+\.\d+(?:\.\d+)?(?:[-+.]?[a-zA-Z0-9]+)?)")


def _version_key(version: str) -> tuple[int, int, int, int]:
    parts: list[int] = []
    for chunk in re.split(r"[.\-_+]", version):
        num = ""
        for ch in chunk:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    while len(parts) < 4:
        parts.append(0)
    return (parts[0], parts[1], parts[2], parts[3])


def _infer_version(item: SigDBItem | None, evidence: list[str]) -> str | None:
    if item is None:
        return _version_from_evidence(evidence)
    versions: dict[str, Any] = getattr(item, "versions", None) or {}
    if versions:
        inferred = _version_from_sigdb(versions, evidence)
        if inferred:
            return inferred
    return _version_from_evidence(evidence)


def _version_from_sigdb(versions: dict[str, Any], evidence: list[str]) -> str | None:
    matched: list[str] = []
    for ev in evidence:
        group, _, signal = ev.partition(":")
        signal = signal.strip()
        if not signal:
            continue
        group_map = versions.get(group)
        if not isinstance(group_map, dict):
            continue
        group_dict = cast(dict[str, Any], group_map)
        constraint = group_dict.get(signal)
        if not isinstance(constraint, dict):
            continue
        constraint_dict = cast(dict[str, Any], constraint)
        since = constraint_dict.get("since")
        if isinstance(since, str):
            matched.append(since)
    if not matched:
        return None
    return max(matched, key=_version_key)


def _version_from_evidence(evidence: list[str]) -> str | None:
    candidates: list[str] = []
    for ev in evidence:
        value = ev.split(":", 1)[-1]
        for match in _VERSION_RE.finditer(value):
            candidate = match.group(1)
            if len(candidate) >= 3 and not candidate.startswith("0."):
                candidates.append(candidate)
    if not candidates:
        return None
    return max(candidates, key=_version_key)


_HEADER_TECH: tuple[tuple[str, str | None, str, str], ...] = (
    ("x-powered-by", "php", "PHP", "backend"),
    ("x-powered-by", "asp.net", "ASP.NET", "backend"),
    ("x-powered-by", "express", "Express", "backend"),
    ("x-powered-by", "next.js", "Next.js", "frontend"),
    ("x-powered-by", "nuxt", "Nuxt.js", "frontend"),
    ("x-powered-by", "servlet", "Java Servlet", "backend"),
    ("x-powered-by", "plesk", "Plesk", "infrastructure"),
    ("x-aspnet-version", None, "ASP.NET", "backend"),
    ("x-aspnetmvc-version", None, "ASP.NET MVC", "backend"),
    ("x-drupal-cache", None, "Drupal", "cms"),
    ("x-drupal-dynamic-cache", None, "Drupal", "cms"),
    ("x-generator", "drupal", "Drupal", "cms"),
    ("x-shopify-stage", None, "Shopify", "ecommerce"),
    ("x-shopid", None, "Shopify", "ecommerce"),
    ("x-magento-cache-debug", None, "Magento", "ecommerce"),
    ("x-wix-request-id", None, "Wix", "cms"),
    ("x-jenkins", None, "Jenkins", "ci"),
    ("x-turbo-charged-by", "litespeed", "LiteSpeed", "proxy"),
    ("x-litespeed-cache", None, "LiteSpeed Cache", "cms"),
    ("x-varnish", None, "Varnish", "proxy"),
    ("x-envoy-upstream-service-time", None, "Envoy", "proxy"),
    ("x-vercel-id", None, "Vercel", "infrastructure"),
    ("x-nextjs-cache", None, "Next.js", "frontend"),
    ("fastly-io-info", None, "Fastly", "cdn"),
)
_COOKIE_TECH: tuple[tuple[str, str, str], ...] = (
    ("phpsessid", "PHP", "backend"),
    ("laravel_session", "Laravel", "backend"),
    ("ci_session", "CodeIgniter", "backend"),
    ("csrftoken", "Django", "backend"),
    ("django_language", "Django", "backend"),
    ("jsessionid", "Java", "backend"),
    ("asp.net_sessionid", "ASP.NET", "backend"),
    (".aspxauth", "ASP.NET", "backend"),
    ("wordpress_", "WordPress", "cms"),
    ("wp-settings", "WordPress", "cms"),
    ("_shopify", "Shopify", "ecommerce"),
    ("prestashop", "PrestaShop", "ecommerce"),
    ("connect.sid", "Express", "backend"),
    ("incap_ses", "Imperva Incapsula", "security"),
    ("visid_incap", "Imperva Incapsula", "security"),
)


class TechAnalyzer:
    def __init__(self, matchers: list[SigDBMatcher]) -> None:
        self._matchers = matchers

    def _add(self, acc: dict[str, _Hit], match: SigDBMatchResult, evidence: str) -> None:
        if not match.result or match.item is None:
            return
        key = match.item.key
        headers = getattr(match.item, "headers", {}) or {}
        hit = acc.get(key)
        if hit is None:
            hit = _Hit(
                name=headers.get("_name") or key,
                category=headers.get("_category"),
                item=match.item,
            )
            acc[key] = hit
        if evidence not in hit.evidence:
            hit.evidence.append(evidence)

    def detect(self, result: FetchResult) -> list[Technology]:
        acc: dict[str, _Hit] = {}
        location = host_of(result.url) if result.url else ""
        for matcher in self._matchers:
            for name, value in result.headers.items():
                if name == "_raw":
                    continue
                self._add(acc, matcher.match_group("headers", value, name=name), f"header:{name}")
            for raw_cookie in result.cookies:
                segment = raw_cookie.split(";", 1)[0].strip()
                if "=" not in segment:
                    continue
                cname, _, cvalue = segment.partition("=")
                cname = cname.strip().lower()
                self._add(
                    acc, matcher.match_group("headers", cvalue, name=cname), f"cookie:{cname}"
                )
            for key, content in _meta_pairs(result.body):
                self._add(acc, matcher.match_group("meta", content, name=key), f"meta:{key}")
            for src in _script_srcs(result.body):
                self._add(acc, matcher.match_group("script_src", src), "script_src")
                self._add(acc, matcher.match(src), "script_src")
            self._add(acc, matcher.match_html(result.body), "html")
            self._add(acc, matcher.match(result.body), "body")
            self._add(acc, matcher.match(result.url), "url")
            for token in _framework_tokens(result.body):
                self._add(
                    acc, matcher.match_search({"framework": token}), f"framework:{token}"
                )
        self._curated(acc, result)
        by_name: dict[str, _Hit] = {}
        for hit in acc.values():
            existing = by_name.get(hit.name.lower())
            if existing is None:
                by_name[hit.name.lower()] = hit
            else:
                for ev in hit.evidence:
                    if ev not in existing.evidence:
                        existing.evidence.append(ev)
                existing.category = existing.category or hit.category
        technologies = [
            Technology(
                name=hit.name,
                categories=(hit.category,) if hit.category else (),
                evidence=tuple(hit.evidence),
                location=location,
                confidence=_confidence(hit.evidence),
                version=_infer_version(hit.item, hit.evidence),
            )
            for hit in by_name.values()
        ]
        technologies.sort(key=lambda tech: tech.name.lower())
        return technologies

    def _curated(self, acc: dict[str, _Hit], result: FetchResult) -> None:

        def add(name: str, category: str, evidence: str) -> None:
            key = f"curated:{name.lower()}"
            hit = acc.get(key)
            if hit is None:
                hit = _Hit(name=name, category=category)
                acc[key] = hit
            if evidence not in hit.evidence:
                hit.evidence.append(evidence)

        for header, needle, name, category in _HEADER_TECH:
            value = result.headers.get(header)
            if value is None:
                continue
            if needle is None or needle in value.lower():
                add(name, category, f"header:{header}")
        for raw_cookie in result.cookies:
            cname = raw_cookie.split("=", 1)[0].split(";", 1)[0].strip().lower()
            if not cname:
                continue
            for prefix, name, category in _COOKIE_TECH:
                if cname.startswith(prefix):
                    add(name, category, f"cookie:{cname}")
