"""Tests for CLI argument parsing."""

from __future__ import annotations

import pytest

from stackscan.cli import _parse_args, _dedupe, _read_targets


class TestParseArgs:
    def test_parse_empty_args(self) -> None:
        args = _parse_args([])
        assert args.targets == []
        assert args.file is None
        assert not hasattr(args, "sigdb") or args.sigdb is None

    def test_parse_targets(self) -> None:
        args = _parse_args(["http://example.com", "https://test.com"])
        assert args.targets == ["http://example.com", "https://test.com"]

    def test_parse_sigdb_option(self) -> None:
        args = _parse_args(["--sigdb", "/path/to/sigdb.sigdb", "http://example.com"])
        assert args.sigdb == "/path/to/sigdb.sigdb"
        assert args.targets == ["http://example.com"]

    def test_parse_file_option(self) -> None:
        args = _parse_args(["-f", "/path/to/targets.txt"])
        assert args.file.name == "targets.txt"

    def test_parse_timeout_option(self) -> None:
        args = _parse_args(["--timeout", "30.5", "http://example.com"])
        assert args.timeout == 30.5

    def test_parse_concurrency_option(self) -> None:
        args = _parse_args(["--concurrency", "20", "http://example.com"])
        assert args.concurrency == 20

    def test_parse_insecure_option(self) -> None:
        args = _parse_args(["--insecure", "http://example.com"])
        assert args.insecure is True

    def test_parse_json_output(self) -> None:
        args = _parse_args(["--json", "http://example.com"])
        assert args.json_output is True

    def test_parse_show_empty(self) -> None:
        args = _parse_args(["--show-empty", "http://example.com"])
        assert args.show_empty is True

    def test_parse_version(self) -> None:
        with pytest.raises(SystemExit):
            _parse_args(["--version"])


class TestDedupe:
    def test_dedupe_empty(self) -> None:
        assert _dedupe([]) == []

    def test_dedupe_no_duplicates(self) -> None:
        result = _dedupe(["a", "b", "c"])
        assert result == ["a", "b", "c"]

    def test_dedupe_with_duplicates(self) -> None:
        result = _dedupe(["a", "b", "a", "c", "b"])
        assert result == ["a", "b", "c"]

    def test_dedupe_preserves_order(self) -> None:
        result = _dedupe(["c", "a", "b", "a", "c"])
        assert result == ["c", "a", "b"]


class TestReadTargets:
    def test_read_targets_from_positional(self) -> None:
        result = _read_targets(None, ["http://a.com", "http://b.com"])
        assert result == ["http://a.com", "http://b.com"]

    def test_read_targets_strips_whitespace(self) -> None:
        result = _read_targets(None, ["  http://a.com  ", " http://b.com"])
        assert result == ["http://a.com", "http://b.com"]

    def test_read_targets_ignores_empty(self) -> None:
        result = _read_targets(None, ["", "  ", "http://a.com"])
        assert result == ["http://a.com"]

    def test_read_targets_ignores_comments(self, tmp_path: pytest.TempPathFactory) -> None:
        targets_file = tmp_path / "targets.txt"
        targets_file.write_text("# comment\nhttp://a.com\n# another")
        result = _read_targets(targets_file, [])
        assert result == ["http://a.com"]
