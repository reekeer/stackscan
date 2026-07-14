from __future__ import annotations

from pathlib import Path

import pytest

from stackscan.net.subdomains import (
    _parse_labels,
    apex_domain,
    load_bundled_wordlist,
    load_wordlist,
)


def test_apex_strips_leading_www() -> None:
    assert apex_domain("www.example.com") == "example.com"


def test_apex_keeps_bare_domain() -> None:
    assert apex_domain("example.com") == "example.com"
    assert apex_domain("EXAMPLE.COM.") == "example.com"


def test_bundled_wordlist_has_common_labels() -> None:
    labels = load_bundled_wordlist()
    assert "mail" in labels
    assert "dev" in labels
    assert "staging" in labels
    assert all(label and (not label.startswith("#")) for label in labels)


def test_parse_labels_dedupes_and_skips_comments() -> None:
    assert _parse_labels("# c\nmail\n\nmail\ndev\n") == ("mail", "dev")


def test_load_wordlist_uses_cache_without_network(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("STACKSCAN_HOME", str(tmp_path))
    cache = tmp_path / "db" / "seclists-dns-top110k.txt"
    cache.parent.mkdir(parents=True)
    cache.write_text("api\nvpn\napi\n", encoding="utf-8")
    load_wordlist.cache_clear()
    try:
        assert load_wordlist() == ("api", "vpn")
    finally:
        load_wordlist.cache_clear()
