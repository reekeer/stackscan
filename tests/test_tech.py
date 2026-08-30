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
        "MyFramework": {"framework": ["my-fw-button"]},
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
        url="https://example.com", status=200, headers={"server": "nginx"}, body="", cookies=()
    )
    techs = analyzer.detect(result)
    nginx = next(tech for tech in techs if tech.name == "nginx")
    assert "header:server" in nginx.evidence


def test_confidence_reflects_evidence_strength(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com", status=200, headers={"server": "nginx"}, body="", cookies=()
    )
    nginx = next(tech for tech in analyzer.detect(result) if tech.name == "nginx")
    assert nginx.confidence == 100
    assert 1 <= nginx.confidence <= 100


def test_detects_framework_from_class_tokens(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com",
        status=200,
        headers={},
        body='<button class="my-fw-button primary">x</button>',
        cookies=(),
    )
    names = {tech.name for tech in analyzer.detect(result)}
    assert "MyFramework" in names


def test_tailwind_utilities_do_not_emulate_frameworks(tmp_path: Path) -> None:
    rules: dict[str, Any] = {
        "Backdrop": {"headers": {"X-Generator": "Backdrop"}},
        "MyFramework": {"framework": ["my-fw-button"]},
    }
    sigdb = tmp_path / "tech.sigdb"
    build_sigdb(rules=rules, output_path=sigdb)
    analyzer = TechAnalyzer([SigDBMatcher(load_sigdb(sigdb))])
    result = FetchResult(
        url="https://example.com",
        status=200,
        headers={},
        body='<div class="my-fw-button px-4 backdrop-blur flex grid">x</div>',
        cookies=(),
    )
    names = {tech.name for tech in analyzer.detect(result)}
    assert "MyFramework" in names
    assert "Backdrop" not in names


def test_detects_generic_core_commit_service(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com",
        status=200,
        headers={},
        body="CurseForge Core (a26fded)",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(result)}
    assert "CurseForge" in techs
    assert techs["CurseForge"].version == "a26fded"
    assert "service" in techs["CurseForge"].categories


def test_detects_apache_and_does_not_confuse_with_nginx(tmp_path: Path) -> None:
    rules: dict[str, Any] = {
        "nginx": {"headers": {"Server": "nginx"}},
        "Apache": {"headers": {"Server": "Apache"}},
    }
    sigdb = tmp_path / "tech.sigdb"
    build_sigdb(rules=rules, output_path=sigdb)
    analyzer = TechAnalyzer([SigDBMatcher(load_sigdb(sigdb))])

    apache_result = FetchResult(
        url="https://example.com",
        status=200,
        headers={"server": "Apache/2.4.57 (Ubuntu)"},
        body="",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(apache_result)}
    assert "Apache" in techs
    assert "nginx" not in techs

    nginx_result = FetchResult(
        url="https://example.com",
        status=200,
        headers={"server": "nginx/1.24.0"},
        body="",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(nginx_result)}
    assert "nginx" in techs
    assert "Apache" not in techs


def test_detects_nginx_from_404_body_when_header_is_plain(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com/unknown",
        status=404,
        headers={"server": "cloudflare"},
        body="<html><body><hr><center>nginx/1.24.0</center></body></html>",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(result)}
    assert "nginx" in techs
    assert techs["nginx"].version == "1.24.0"
    assert "infrastructure" in techs["nginx"].categories


def test_detects_apache_from_404_body(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com/unknown",
        status=404,
        headers={},
        body="<html><body>Apache/2.4.57 Server at example.com Port 443</body></html>",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(result)}
    assert "Apache" in techs
    assert techs["Apache"].version == "2.4.57"


def test_detects_generic_service_from_powered_by_footer(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com",
        status=200,
        headers={},
        body="<footer>Powered by CurseForge v2.11.4</footer>",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(result)}
    assert "CurseForge" in techs
    assert techs["CurseForge"].version == "2.11.4"
    assert "service" in techs["CurseForge"].categories


def test_detects_caddy_from_404_body(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com/unknown",
        status=404,
        headers={},
        body="<html><body>Caddy/v2.7.6</body></html>",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(result)}
    assert "Caddy" in techs
    assert techs["Caddy"].version == "2.7.6"


def test_detects_openresty_from_404_body(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com/unknown",
        status=404,
        headers={},
        body="<html><body><center>openresty/1.21.4.3</center></body></html>",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(result)}
    assert "openresty" in techs
    assert techs["openresty"].version == "1.21.4.3"


def test_detects_generic_commit_without_core_keyword(tmp_path: Path) -> None:
    analyzer = TechAnalyzer([_matcher(tmp_path)])
    result = FetchResult(
        url="https://example.com",
        status=200,
        headers={},
        body="<footer>CurseForge (a26fded)</footer>",
        cookies=(),
    )
    techs = {tech.name: tech for tech in analyzer.detect(result)}
    assert "CurseForge" in techs
    assert techs["CurseForge"].version == "a26fded"


def test_generic_ignores_crypto_token_as_commit() -> None:
    from stackscan.analyzers.generic import extract_generic_software, extract_generic_tech

    body = "signed by channel with SHA-256 validation and ed25519 signatures"
    assert extract_generic_tech(body) == []
    assert extract_generic_software(body) == []


def test_generic_truncates_prose_at_stopword() -> None:
    from stackscan.analyzers.generic import extract_generic_tech

    names = {tech.name for tech in extract_generic_tech("Built with Nuxt and the LeavePulse UI")}
    assert names == {"Nuxt"}


def test_generic_powered_by_keeps_single_versioned_hit() -> None:
    from stackscan.analyzers.generic import extract_generic_tech

    techs = extract_generic_tech("Powered by CurseForge v2.11.4")
    assert [(t.name, t.version) for t in techs] == [("CurseForge", "2.11.4")]


def test_generic_powered_by_drops_version_across_stopword() -> None:
    from stackscan.analyzers.generic import extract_generic_software

    hits = {s.name: s.version for s in extract_generic_software("powered by coffee and jQuery 1.12.4")}
    assert hits.get("coffee") is None
