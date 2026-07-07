"""Tests for signature source management."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stackscan.config.sources import SourceStore


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STACKSCAN_HOME", str(tmp_path))


def _rules_file(tmp_path: Path) -> str:
    rules = {"nginx": {"headers": {"Server": "nginx"}, "categories": ["web-server"]}}
    path = tmp_path / "rules.json"
    path.write_text(json.dumps(rules), encoding="utf-8")
    return path.as_uri()


def test_add_http_rules_source_compiles_sigdb(tmp_path: Path) -> None:
    store = SourceStore()
    source = store.add(_rules_file(tmp_path))
    assert source.kind == "http"
    assert Path(source.path).is_file()
    assert Path(source.path).read_bytes()[:4] == b"SIGT"


def test_list_and_resolve_paths(tmp_path: Path) -> None:
    store = SourceStore()
    store.add(_rules_file(tmp_path))
    assert len(store.list()) == 1
    assert len(store.resolve_paths()) == 1


def test_remove_source(tmp_path: Path) -> None:
    store = SourceStore()
    source = store.add(_rules_file(tmp_path))
    assert store.remove(source.id) is True
    assert store.list() == []
    assert store.remove("nonexistent") is False
