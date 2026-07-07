"""Assemble sigdb matchers from the default database and configured sources."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from stackscan.config.sources import SourceStore

if TYPE_CHECKING:
    from sigdb.core import SigDBMatcher

DEFAULT_SIGDB_PATH = Path.home() / "reekeer" / "sigdb" / "sigdb.sigdb"


class NoSignaturesError(RuntimeError):
    """Raised when no signature database can be located."""


def _default_sigdb_path() -> Path | None:
    return DEFAULT_SIGDB_PATH if DEFAULT_SIGDB_PATH.is_file() else None


def _load_matcher(path: Path) -> SigDBMatcher:
    from sigdb.core import SigDBMatcher, load_sigdb

    return SigDBMatcher(load_sigdb(path))


def resolve_sigdb_paths(explicit: str | Path | None, *, use_sources: bool = True) -> list[Path]:
    """Return the ordered, de-duplicated list of ``.sigdb`` files to load."""

    paths: list[Path] = []

    if explicit is not None:
        path = Path(explicit)
        if not path.is_file():
            raise FileNotFoundError(f"SigDB file not found: {explicit}")
        paths.append(path)
    else:
        default = _default_sigdb_path()
        if default is not None:
            paths.append(default)

    if use_sources:
        paths.extend(SourceStore().resolve_paths())

    seen: set[Path] = set()
    ordered: list[Path] = []
    for path in paths:
        resolved = path.resolve()
        if resolved not in seen:
            seen.add(resolved)
            ordered.append(path)
    return ordered


def build_matchers(explicit: str | Path | None, *, use_sources: bool = True) -> list[SigDBMatcher]:
    paths = resolve_sigdb_paths(explicit, use_sources=use_sources)
    if not paths:
        raise NoSignaturesError(
            "No signature database found. Provide --sigdb PATH, install one at "
            f"{DEFAULT_SIGDB_PATH}, or add a source with 'stackscan sigdb add <url>'."
        )
    return [_load_matcher(path) for path in paths]
