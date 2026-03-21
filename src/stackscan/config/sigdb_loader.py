"""Optimized SigDB loader and matcher adapter for stackscan."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from stackscan.types import DetectedTech, FetchResult

if TYPE_CHECKING:
    from sigdb.core.reader import SigDBMatcher

DEFAULT_SIGDB_PATH = Path.home() / "reekeer" / "sigdb" / "sigdb.sigdb"

_COOKIE_RE = re.compile(r"^([^=]+)=(.+)$")


def _default_sigdb_path() -> Path | None:
    path = DEFAULT_SIGDB_PATH
    if path.is_file():
        return path
    return None


class SigDBDetector:
    __slots__ = ("_matcher", "_headers_cache", "_html_cache")

    def __init__(self, matcher: SigDBMatcher) -> None:
        self._matcher = matcher
        self._headers_cache: dict[str, str | None] = {}
        self._html_cache: dict[str, str | None] = {}

    def detect(self, result: FetchResult) -> DetectedTech:
        from sigdb.core.reader import match_group, match_html

        detected_headers: set[str] = set()
        detected_cookies: set[str] = set()
        detected_html: set[str] | None = None

        headers = result.headers
        for name, value in headers.items():
            if name == "_raw":
                continue
            name_lower = name.lower()
            cache_key = f"{name_lower}:{value[:64]}"
            cached = self._headers_cache.get(cache_key)
            if cached is not None:
                if cached:
                    detected_headers.add(cached)
                continue
            m = match_group("headers", value.lower(), self._matcher, name=name_lower)
            if m.result and m.item:
                key = m.item.key
                detected_headers.add(key)
                self._headers_cache[cache_key] = key
            else:
                self._headers_cache[cache_key] = ""

        cookies = result.cookies
        if cookies:
            for cookie in cookies:
                cookie = cookie.strip()
                match = _COOKIE_RE.match(cookie)
                if match:
                    cookie_name, cookie_value = match.groups()
                    m = match_group(
                        "headers",
                        cookie_value.lower(),
                        self._matcher,
                        name=cookie_name.strip().lower(),
                    )
                    if m.result and m.item:
                        detected_cookies.add(m.item.key)

        body = result.body
        if body:
            body_hash = hash(body[:4096])
            cached = self._html_cache.get(body_hash)
            if cached is not None:
                if cached:
                    detected_html = {cached}
            else:
                m = match_html(body, self._matcher)
                if m.result and m.item:
                    key = m.item.key
                    detected_html = {key}
                    self._html_cache[body_hash] = key
                else:
                    self._html_cache[body_hash] = ""

        if not detected_headers and not detected_cookies and not detected_html:
            return {}

        result_detected: DetectedTech = {}
        if detected_headers:
            result_detected["headers"] = sorted(detected_headers)
        if detected_cookies:
            result_detected["cookies"] = sorted(detected_cookies)
        if detected_html:
            result_detected["html"] = sorted(detected_html)
        return result_detected


def load_sigdb_detector(source: str | Path | None = None) -> SigDBDetector:
    from sigdb.core import SigDBMatcher, load_sigdb

    if source is None:
        default_path = _default_sigdb_path()
        if default_path is None:
            raise FileNotFoundError(
                f"SigDB file not found at default path: {DEFAULT_SIGDB_PATH}. "
                "Please provide a --sigdb argument or install sigdb at the default location."
            )
        source = default_path

    path = Path(source)
    if not path.is_file():
        raise FileNotFoundError(f"SigDB file not found: {source}")

    db = load_sigdb(path)
    matcher = SigDBMatcher(db)
    return SigDBDetector(matcher)


async def load_sigdb_rules(source: str | Path | None = None) -> SigDBDetector:
    return load_sigdb_detector(source)
