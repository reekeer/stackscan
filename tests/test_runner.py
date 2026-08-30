from __future__ import annotations

import argparse
import asyncio
from typing import Any

import pytest

from stackscan.runner import (
    RunnerConfig,
    _parse_asn,
    _scan_options,
    _slugify,
    report_to_result,
)
from stackscan.types import InfraInfo, IpInfo, NetworkInfo, ScanReport, Technology


def _args(**overrides: object) -> argparse.Namespace:
    base: dict[str, object] = {
        "backend": None,
        "worker_token": None,
        "runner_id": "runner-test",
        "batch": 3,
        "sigdb": None,
        "user_agent": None,
        "once": True,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _report() -> ScanReport:
    report = ScanReport(url="https://example.com")
    report.final_url = "https://example.com/"
    report.status = 200
    report.network = NetworkInfo(host="example.com", ipv4=("93.184.216.34",), ipv6=())
    report.infra = InfraInfo(cdn=("Cloudflare",))
    report.ip_info = [
        IpInfo(
            ip="93.184.216.34",
            country="US",
            city="Norwalk",
            asn="AS13335 Cloudflare, Inc.",
            org="Cloudflare",
            isp="Cloudflare",
        )
    ]
    report.technologies = [Technology(name="Nginx Proxy", categories=("web-server",))]
    return report


def test_slugify_lowercases_and_dashes() -> None:
    assert _slugify("Nginx Proxy 1.2") == "nginx-proxy-1-2"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("AS13335 Cloudflare, Inc.", (13335, "Cloudflare, Inc.")),
        ("13335 Cloudflare", (13335, "Cloudflare")),
        ("Cloudflare", (None, None)),
        (None, (None, None)),
        ("", (None, None)),
    ],
)
def test_parse_asn(raw: str | None, expected: tuple[int | None, str | None]) -> None:
    assert _parse_asn(raw) == expected


def test_report_to_result_maps_panel_payload() -> None:
    result = report_to_result(_report(), "job-1", "runner-test")
    assert result["job_id"] == "job-1"
    assert result["worker_id"] == "runner-test"
    assert result["ips"] == ["93.184.216.34"]
    assert result["asn"] == 13335
    assert result["asn_org"] == "Cloudflare, Inc."
    assert result["network_name"] == "Cloudflare"
    assert result["technologies"][0]["slug"] == "nginx-proxy"
    assert result["error"] is None


def test_report_to_result_keeps_error_report() -> None:
    result = report_to_result(ScanReport(url="https://x.test", error="boom"), "job-2", "w")
    assert result["error"] == "boom"
    assert result["ips"] == []
    assert result["asn"] is None


def test_config_reads_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("STACKSCAN_BACKEND_URL", "http://panel:8787/")
    monkeypatch.setenv("STACKSCAN_WORKER_TOKEN", "tok")
    cfg = RunnerConfig(_args())
    assert cfg.backend_url == "http://panel:8787"
    assert cfg.worker_token == "tok"
    assert cfg.batch == 3


def test_scan_options_profile_is_lean() -> None:
    options = _scan_options(RunnerConfig(_args()))
    assert options.ports is False
    assert options.cve is False
    assert options.subdomains is False
    assert options.concurrency == 3


def test_run_skips_malformed_jobs(monkeypatch: pytest.MonkeyPatch) -> None:
    from stackscan import runner

    claimed: list[dict[str, str]] = [{"id": "1"}, {"url": "https://ok.test", "id": "2"}]
    scanned: list[str] = []
    reported: list[list[dict[str, Any]]] = []

    async def fake_claim(self: Any) -> list[dict[str, str]]:
        return claimed

    async def fake_report(self: Any, results: list[dict[str, Any]]) -> int:
        reported.append(results)
        return len(results)

    async def fake_scan_target(url: str, **_: Any) -> ScanReport:
        scanned.append(url)
        return ScanReport(url=url)

    monkeypatch.setattr(runner.PanelClient, "claim", fake_claim)
    monkeypatch.setattr(runner.PanelClient, "report", fake_report)
    monkeypatch.setattr(runner, "scan_target", fake_scan_target)
    monkeypatch.setattr(runner, "build_matchers", lambda *a, **k: [])
    monkeypatch.setattr(runner, "TechAnalyzer", lambda matchers: object())

    asyncio.run(runner._run(RunnerConfig(_args())))

    assert scanned == ["https://ok.test"]
    assert [r["job_id"] for r in reported[0]] == ["2"]
