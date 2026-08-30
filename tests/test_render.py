from __future__ import annotations

from rich.console import Console

from stackscan.render import _network_section, _tech_section
from stackscan.types import NetworkInfo, ScanReport, Technology


def _render(section: object) -> str:
    console = Console(width=100, no_color=True)
    with console.capture() as cap:
        console.print(section)
    return cap.get()


def test_tech_section_collapses_one_stack_across_subdomains() -> None:
    report = ScanReport(url="https://leavepulse.com")
    report.technologies = [
        Technology(name="leavepulse-ui", categories=("frontend",), location=host, confidence=conf)
        for host, conf in (
            ("leavepulse.com", 100),
            ("api.leavepulse.com", 75),
            ("dev.leavepulse.com", 100),
        )
    ]
    out = _render(_tech_section(report))
    # The stack name is written once, not once per subdomain.
    assert out.count("leavepulse-ui") == 1
    # Every host still appears, listed under the single row.
    for host in ("leavepulse.com", "api.leavepulse.com", "dev.leavepulse.com"):
        assert host in out
    # Differing confidences collapse to a range.
    assert "75-100%" in out


def test_tech_section_keeps_distinct_stacks_separate() -> None:
    report = ScanReport(url="https://leavepulse.com")
    report.technologies = [
        Technology(name="nginx", categories=("infrastructure",), location="a.test", confidence=90),
        Technology(name="nginx", categories=("infrastructure",), location="b.test", confidence=90),
        Technology(name="redis", categories=("database",), location="a.test", confidence=80),
    ]
    out = _render(_tech_section(report))
    assert out.count("nginx") == 1
    assert out.count("redis") == 1
    assert "90%" in out and "80%" in out


def test_tech_section_survives_markup_in_remote_names() -> None:
    report = ScanReport(url="https://evil.test")
    report.technologies = [
        Technology(name="nginx [/]", categories=("web-server",), location="evil.test"),
        Technology(name="[bold]boom", categories=("web-server",), location="evil.test"),
    ]
    out = _render(_tech_section(report))
    assert "nginx [/]" in out
    assert "[bold]boom" in out


def test_network_section_survives_markup_in_txt_records() -> None:
    report = ScanReport(url="https://evil.test")
    report.network = NetworkInfo(
        host="evil.test",
        ipv4=("1.2.3.4",),
        ipv6=(),
        txt=("v=spf1 [/] all",),
    )
    out = _render(_network_section(report))
    assert "v=spf1 [/] all" in out
