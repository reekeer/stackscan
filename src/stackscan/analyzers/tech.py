from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from stackscan.types import FetchResult, Technology
from stackscan.utils import host_of

if TYPE_CHECKING:
    from sigdb.core import SigDBMatcher
    from sigdb.types import SigDBMatchResult
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


@dataclass
class _Hit:
    name: str
    category: str | None = None
    evidence: list[str] = field(default_factory=list[str])


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
            hit = _Hit(name=headers.get("_name") or key, category=headers.get("_category"))
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
