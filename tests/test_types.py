"""Tests for types."""

from __future__ import annotations

import pytest

from stackscan.types import (
    DetectedTech,
    FetchResult,
    ScanTargetResult,
)


class TestFetchResult:
    def test_fetch_result_creation(self) -> None:
        result = FetchResult(
            url="http://example.com",
            status=200,
            headers={"server": "nginx"},
            body="<html></html>",
            cookies=["session=abc123"],
        )
        assert result.url == "http://example.com"
        assert result.status == 200
        assert result.headers["server"] == "nginx"
        assert result.body == "<html></html>"
        assert list(result.cookies) == ["session=abc123"]

    def test_fetch_result_is_frozen(self) -> None:
        result = FetchResult(
            url="http://example.com",
            status=200,
            headers={},
            body="",
            cookies=[],
        )
        with pytest.raises(AttributeError):
            result.status = 500  # type: ignore


class TestScanTargetResult:
    def test_scan_target_result_creation(self) -> None:
        result = ScanTargetResult(
            url="http://example.com",
            status=200,
            detected={"headers": ["nginx"]},
            error=None,
        )
        assert result.url == "http://example.com"
        assert result.status == 200
        assert result.detected == {"headers": ["nginx"]}
        assert result.error is None

    def test_scan_target_result_default_detected(self) -> None:
        result = ScanTargetResult(
            url="http://example.com",
            status=404,
        )
        assert result.detected == {}

    def test_scan_target_result_with_error(self) -> None:
        result = ScanTargetResult(
            url="http://example.com",
            status=None,
            error="Connection timeout",
        )
        assert result.error == "Connection timeout"
        assert result.status is None

    def test_scan_target_result_is_frozen(self) -> None:
        result = ScanTargetResult(
            url="http://example.com",
            status=200,
        )
        with pytest.raises(AttributeError):
            result.status = 500  # type: ignore


class TestDetectedTech:
    def test_detected_tech_empty(self) -> None:
        detected: DetectedTech = {}
        assert detected == {}

    def test_detected_tech_single_category(self) -> None:
        detected: DetectedTech = {"headers": ["nginx", "php"]}
        assert "headers" in detected
        assert detected["headers"] == ["nginx", "php"]

    def test_detected_tech_multiple_categories(self) -> None:
        detected: DetectedTech = {
            "headers": ["nginx"],
            "html": ["React", "Bootstrap"],
        }
        assert len(detected) == 2
