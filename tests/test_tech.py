"""Tests for sigdb-backed technology detection."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from sigdb.core import SigDBMatcher, load_sigdb
from sigdb.format.trie import build_sigdb

from stackscan.analyzers import TechAnalyzer
from stackscan.types import FetchResult


def _matcher(tmp_path: Path) -> SigDBMatcher:
    rules: dict[str, Any] = {
        "nginx": {"headers": {"Server": "nginx"}},
        "PHP": {"headers": {"X-Powered-By": "PHP"}},
        "WordPress": {
            "html": [{"tag": "meta", "attr": "name", "value": "generator"}],
            "meta": {"generator": "wordpress"},
        },
    }
    out = tmp_path / "tech.sigdb"
    build_sigdb(rules=rules, output_path=out)
    return SigDBMatcher(load_sigdb(out))


def test_detects_multiple_technologies(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com",
        status=200,
        headers={"server": "nginx", "x-powered-by": "PHP/8.2"},
        body='<meta name="generator" content="WordPress 6.4">',
        cookies=(),
    )
    techs = {tech.name for tech in analyzer.detect(result)}
    assert {"nginx", "PHP", "WordPress"} <= techs


def test_evidence_recorded(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com",
        status=200,
        headers={"server": "nginx"},
        body="",
        cookies=(),
    )
    techs = analyzer.detect(result)
    nginx = next(tech for tech in techs if tech.name == "nginx")
    assert "header:server" in nginx.evidence
