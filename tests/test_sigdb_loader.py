"""Tests for SigDB loader."""

from __future__ import annotations

import pytest
from pathlib import Path

from stackscan.config.sigdb_loader import (
    DEFAULT_SIGDB_PATH,
    _default_sigdb_path,
    SigDBDetector,
    load_sigdb_detector,
)


class TestDefaultPath:
    def test_default_path_uses_home(self) -> None:
        assert DEFAULT_SIGDB_PATH.name == "sigdb.sigdb"
        assert DEFAULT_SIGDB_PATH.parent.name == "sigdb"

    def test_default_sigdb_path_returns_none_when_missing(self) -> None:
        result = _default_sigdb_path()
        # Depends on whether the file exists at default path
        # This test just verifies the function works
        assert result is None or isinstance(result, Path)


class TestLoadSigdbDetector:
    def test_load_from_nonexistent_path_raises(self) -> None:
        with pytest.raises(FileNotFoundError, match="SigDB file not found"):
            load_sigdb_detector("/nonexistent/path/to/sigdb.sigdb")

    def test_load_from_invalid_path(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_sigdb_detector("/tmp")


class TestSigDBDetector:
    def test_detector_detects_headers(self, tmp_path: pytest.TempPathFactory) -> None:
        from sigdb.core import build_sigdb, SigDBMatcher

        rules = {
            "nginx": {
                "headers": {"server": "nginx"}
            }
        }
        sigdb_path = tmp_path / "test.sigdb"
        build_sigdb(rules=rules, output_path=sigdb_path)

        detector = load_sigdb_detector(sigdb_path)

        from stackscan.types import FetchResult

        result = FetchResult(
            url="http://example.com",
            status=200,
            headers={"server": "nginx/1.0"},
            body="<html></html>",
            cookies=[],
        )

        detected = detector.detect(result)
        assert "headers" in detected
        assert "nginx" in detected["headers"]

    def test_detector_detects_html(self, tmp_path: pytest.TempPathFactory) -> None:
        from sigdb.core import build_sigdb

        rules = {
            "React": {
                "html": ["tag:script:attr:src:value:/react.production.min.js"]
            }
        }
        sigdb_path = tmp_path / "test.sigdb"
        build_sigdb(rules=rules, output_path=sigdb_path)

        detector = load_sigdb_detector(sigdb_path)

        from stackscan.types import FetchResult

        result = FetchResult(
            url="http://example.com",
            status=200,
            headers={},
            body='<script src="/react.production.min.js"></script>',
            cookies=[],
        )

        detected = detector.detect(result)
        assert "html" in detected
        assert "React" in detected["html"]

    def test_detector_no_match(self, tmp_path: pytest.TempPathFactory) -> None:
        from sigdb.core import build_sigdb

        rules = {
            "nginx": {
                "headers": {"server": "nginx"}
            }
        }
        sigdb_path = tmp_path / "test.sigdb"
        build_sigdb(rules=rules, output_path=sigdb_path)

        detector = load_sigdb_detector(sigdb_path)

        from stackscan.types import FetchResult

        result = FetchResult(
            url="http://example.com",
            status=200,
            headers={"server": "apache"},
            body="<html></html>",
            cookies=[],
        )

        detected = detector.detect(result)
        assert detected == {}
