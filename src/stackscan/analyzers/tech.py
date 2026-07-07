"""Technology detection driven by one or more sigdb databases."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from stackscan.types import FetchResult, Technology

if TYPE_CHECKING:
    from sigdb.core import SigDBMatcher
    from sigdb.types import SigDBItem

_META_RE = re.compile(r"<meta\b([^>]*)>", re.IGNORECASE)
_SCRIPT_SRC_RE = re.compile(r"<script\b[^>]*\bsrc\s*=\s*[\"']?([^\"'\s>]+)", re.IGNORECASE)
_ATTR_RE = re.compile(r"([a-zA-Z_:][\w:.-]*)\s*=\s*(?:\"([^\"]*)\"|'([^']*)'|([^\s\"'=<>`]+))")


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
class _Acc:
    categories: set[str] = field(default_factory=set[str])
    evidence: list[str] = field(default_factory=list[str])


class TechAnalyzer:
    """Detects technologies by querying every configured sigdb matcher."""

    def __init__(self, matchers: list[SigDBMatcher]) -> None:
        self._matchers = matchers

    def _add(self, acc: dict[str, _Acc], items: list[SigDBItem], evidence: str) -> None:
        for item in items:
            entry = acc.setdefault(item.key, _Acc())
            entry.categories.update(item.categories)
            if evidence not in entry.evidence:
                entry.evidence.append(evidence)

    def detect(self, result: FetchResult) -> list[Technology]:
        acc: dict[str, _Acc] = {}

        for matcher in self._matchers:
            for name, value in result.headers.items():
                if name == "_raw":
                    continue
                self._add(
                    acc, matcher.match_group_all("headers", value, name=name), f"header:{name}"
                )

            for raw_cookie in result.cookies:
                segment = raw_cookie.split(";", 1)[0].strip()
                if "=" not in segment:
                    continue
                cname, _, cvalue = segment.partition("=")
                cname = cname.strip().lower()
                self._add(
                    acc,
                    matcher.match_group_all("headers", cvalue, name=cname),
                    f"cookie:{cname}",
                )

            for key, content in _meta_pairs(result.body):
                self._add(acc, matcher.match_group_all("meta", content, name=key), f"meta:{key}")

            for src in _script_srcs(result.body):
                self._add(acc, matcher.match_group_all("script_src", src), "script_src")
                self._add(acc, matcher.match_text(src), "script_src")

            self._add(acc, matcher.match_html_all(result.body), "html")

            # Raw substring scan of the response body catches content-style
            # signatures (inline scripts, script URLs, HTML markers) imported
            # from webappanalyzer-style datasets.
            self._add(acc, matcher.match_text(result.body), "body")
            self._add(acc, matcher.match_text(result.url), "url")

        technologies = [
            Technology(
                name=name,
                categories=tuple(sorted(entry.categories)),
                evidence=tuple(entry.evidence),
            )
            for name, entry in acc.items()
        ]
        technologies.sort(key=lambda tech: tech.name.lower())
        return technologies
