from __future__ import annotations

from stackscan.config import build_matchers, builtin_sigdb_path


def test_builtin_sigdb_is_bundled() -> None:
    path = builtin_sigdb_path()
    assert path is not None
    assert path.is_file()
    assert path.read_bytes()[:4] == b"SIGT"


def test_build_matchers_uses_builtin_without_explicit_path() -> None:
    matchers = build_matchers(None, use_sources=False)
    assert len(matchers) >= 1
