from __future__ import annotations

from pathlib import Path

import pytest

from stackscan.cli import _dedupe, _format_detected, _read_targets
from stackscan.utils import normalize_url


def test_normalize_url_adds_https_to_bare_host() -> None:
    assert normalize_url("example.com") == "https://example.com"


def test_normalize_url_preserves_existing_scheme() -> None:
    assert normalize_url("http://example.com") == "http://example.com"
    assert normalize_url("https://example.com") == "https://example.com"


def test_dedupe_preserves_first_seen_order() -> None:
    assert _dedupe(["a", "b", "a", "c", "b"]) == ["a", "b", "c"]


def test_format_detected_empty_returns_dash() -> None:
    assert _format_detected({}) == "-"


def test_format_detected_orders_by_category() -> None:
    detected = {"html": ["React"], "headers": ["nginx", "PHP"]}
    assert _format_detected(detected) == "headers: nginx, PHP | html: React"


def test_read_targets_skips_blank_lines_and_comments(tmp_path: Path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("example.com\n\n# comment\nfoo.test\n", encoding="utf-8")
    assert _read_targets(target_file, []) == ["example.com", "foo.test"]


def test_read_targets_prepends_positional_targets(tmp_path: Path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("from-file.test\n", encoding="utf-8")
    assert _read_targets(target_file, ["cli.test"]) == ["cli.test", "from-file.test"]


def test_read_targets_missing_file_raises() -> None:
    with pytest.raises(FileNotFoundError):
        _read_targets(Path("does-not-exist-xyz.txt"), [])



