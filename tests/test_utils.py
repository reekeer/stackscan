"""Tests for utils."""

from __future__ import annotations

import pytest

from stackscan.utils import normalize_url


class TestNormalizeUrl:
    def test_normalize_https_url(self) -> None:
        result = normalize_url("https://example.com")
        assert result == "https://example.com"

    def test_normalize_http_url(self) -> None:
        result = normalize_url("http://example.com")
        assert result == "http://example.com"

    def test_normalize_url_without_scheme(self) -> None:
        result = normalize_url("example.com")
        assert result == "https://example.com"

    def test_normalize_url_with_path(self) -> None:
        result = normalize_url("example.com/path/to/page")
        assert result == "https://example.com/path/to/page"

    def test_normalize_url_with_port(self) -> None:
        result = normalize_url("example.com:8080")
        assert result == "https://example.com:8080"

    def test_normalize_url_preserves_trailing_slash(self) -> None:
        result = normalize_url("example.com/")
        assert result == "https://example.com/"

    def test_normalize_url_preserves_query_params(self) -> None:
        result = normalize_url("example.com/?foo=bar")
        assert result == "https://example.com/?foo=bar"

    def test_normalize_url_preserves_fragment(self) -> None:
        result = normalize_url("example.com/#section")
        assert result == "https://example.com/#section"

    def test_normalize_url_preserves_http(self) -> None:
        result = normalize_url("http://example.com")
        assert result == "http://example.com"

    def test_normalize_url_preserves_www(self) -> None:
        result = normalize_url("www.example.com")
        assert result == "https://www.example.com"

    def test_normalize_empty_string(self) -> None:
        result = normalize_url("")
        assert result == "https://"

    def test_normalize_url_with_subdomain(self) -> None:
        result = normalize_url("api.example.com")
        assert result == "https://api.example.com"
