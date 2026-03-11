"""Detection logic."""

from __future__ import annotations

import re

from stackscan.types import DetectedTech, FetchResult, Patterns, RulesByCategory


def _match_any(patterns: Patterns, text: str) -> bool:
    if not patterns:
        return False

    flags = re.IGNORECASE | re.MULTILINE
    for pattern in patterns:
        try:
            if re.search(pattern, text, flags=flags):
                return True
        except re.error:
            continue
    return False


def detect_tech(result: FetchResult, rules: RulesByCategory) -> DetectedTech:
    headers_text = result.headers.get("_raw", "")
    cookies_text = "\n".join(result.cookies)
    html_text = result.body

    detected: dict[str, set[str]] = {}
    for category, techs in rules.items():
        for name, rule in techs.items():
            if (
                _match_any(rule.headers, headers_text)
                or _match_any(rule.cookies, cookies_text)
                or _match_any(rule.html, html_text)
            ):
                detected.setdefault(category, set()).add(name)

    return {category: sorted(names) for category, names in detected.items()}
