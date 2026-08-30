from __future__ import annotations

import json
from pathlib import Path

import pytest

from stackscan.config.sources import SourceError, SourceStore, _normalize_git_url


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STACKSCAN_HOME", str(tmp_path))


def _rules_file(tmp_path: Path) -> str:
    rules = {"nginx": {"headers": {"Server": "nginx"}, "categories": ["web-server"]}}
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    return path.as_uri()


def test_add_web_rules_source_compiles_sigdb(tmp_path: Path) -> None:
    store = SourceStore()
    source = store.add(_rules_file(tmp_path))
    assert source.kind == "web"
    assert Path(source.path).is_file()
    assert Path(source.path).read_bytes()[:4] == b"SIGT"


def test_add_path_source_uses_local_sigdb(tmp_path: Path) -> None:
    from sigdb.core import build_sigdb

    sig = tmp_path / "local.sigdb"
    build_sigdb(rules={"x": {"headers": {"server": "nginx", "_name": "X"}}}, output_path=sig)
    store = SourceStore()
    source = store.add(str(sig))
    assert source.kind == "path"
    assert Path(source.path) == sig.resolve()
    assert store.resolve_paths() == [sig.resolve()]


def test_list_and_resolve_paths(tmp_path: Path) -> None:
    store = SourceStore()
    store.add(_rules_file(tmp_path))
    assert len(store.list()) == 1
    assert len(store.resolve_paths()) == 1


def test_disable_and_enable_source(tmp_path: Path) -> None:
    store = SourceStore()
    source = store.add(_rules_file(tmp_path))
    assert store.set_enabled(source.id, False) is True
    assert store.list()[0].enabled is False
    assert store.resolve_paths() == []
    assert store.set_enabled(source.id, True) is True
    assert len(store.resolve_paths()) == 1
    assert store.set_enabled("nonexistent", False) is False


def test_remove_source(tmp_path: Path) -> None:
    store = SourceStore()
    source = store.add(_rules_file(tmp_path))
    assert store.remove(source.id) is True
    assert store.list() == []
    assert store.remove("nonexistent") is False


def test_normalize_git_url_keeps_supported_transports() -> None:
    assert _normalize_git_url("https://host/repo.git") == "https://host/repo.git"
    assert _normalize_git_url("git+ssh://host/repo.git") == "ssh://host/repo.git"
    assert _normalize_git_url("git@host:owner/repo.git") == "git@host:owner/repo.git"


def test_normalize_git_url_rejects_transport_helpers() -> None:
    with pytest.raises(SourceError):
        _normalize_git_url("ext::sh -c touch% /tmp/pwned.git")
    with pytest.raises(SourceError):
        _normalize_git_url("--upload-pack=touch /tmp/pwned.git")


def test_normalize_git_url_allows_existing_local_repo(tmp_path: Path) -> None:
    local = tmp_path / "repo.git"
    local.mkdir()
    assert _normalize_git_url(str(local)) == str(local)
