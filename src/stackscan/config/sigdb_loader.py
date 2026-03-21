"""SigDB loader and matcher adapter for stackscan."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from stackscan.types import DetectedTech, FetchResult

if TYPE_CHECKING:
    from sigdb import SigDBMatcher, SigDBReader

DEFAULT_SIGDB_PATH = Path.home() / "reekeer" / "sigdb" / "sigdb.sigdb"


def _default_sigdb_path() -> Path | None:
    path = DEFAULT_SIGDB_PATH
    if path.is_file():
        return path
    return None


class SigDBDetector:
    def __init__(self, matcher: SigDBMatcher) -> None:
        self._matcher = matcher

    def detect(self, result: FetchResult) -> DetectedTech:
        from sigdb.core.reader import match_group, match_html

        detected: dict[str, set[str]] = {}

        for name, value in result.headers.items():
            if name.lower() == "_raw":
                continue
            m = match_group("headers", value.lower(), self._matcher, name=name.lower())
            if m.result and m.item:
                detected.setdefault("headers", set()).add(m.item.key)

        if result.cookies:
            cookies_text = "\n".join(result.cookies)
            for cookie in cookies_text.split(";"):
                cookie = cookie.strip()
                if "=" in cookie:
                    name, _, value = cookie.partition("=")
                    m = match_group("headers", value.lower(), self._matcher, name=name.strip().lower())
                    if m.result and m.item:
                        detected.setdefault("cookies", set()).add(m.item.key)

        m = match_html(result.body, self._matcher)
        if m.result and m.item:
            detected.setdefault("html", set()).add(m.item.key)

        return {category: sorted(names) for category, names in detected.items()}


def load_sigdb_detector(source: str | Path | None = None) -> SigDBDetector:
    from sigdb import SigDBReader, load_sigdb

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
