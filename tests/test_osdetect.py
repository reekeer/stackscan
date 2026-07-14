from __future__ import annotations

from stackscan.analyzers.osdetect import detect_os
from stackscan.types import NetworkInfo, Port, PortScan, ScanReport, Software


def test_majority_os_wins_for_conflicting_votes() -> None:
    report = ScanReport(url="https://a.test")
    report.network = NetworkInfo(host="a.test", ipv4=("1.2.3.4",))
    report.software = [
        Software(name="nginx", version="1.24.0", source="header:server", os="Ubuntu"),
    ]
    report.ports = PortScan(
        scanner="connect",
        ports=(
            Port(port=22, host="1.2.3.4", service="ssh", os="Debian"),
            Port(port=3306, host="1.2.3.4", service="mysql", os="Debian"),
        ),
    )
    findings = detect_os(report)
    host_findings = {f.host: f for f in findings}
    assert "1.2.3.4" in host_findings
    assert host_findings["1.2.3.4"].os == "Debian"
    assert host_findings["1.2.3.4"].confidence == 1.0


def test_windows_ports_yield_windows() -> None:
    report = ScanReport(url="https://b.test")
    report.network = NetworkInfo(host="b.test", ipv4=("5.6.7.8",))
    report.ports = PortScan(
        scanner="connect",
        ports=(Port(port=3389, host="5.6.7.8", service="ms-wbt-server"),),
    )
    findings = detect_os(report)
    assert any(f.os == "Windows" and f.host == "5.6.7.8" for f in findings)


def test_confidence_reflects_vote_share() -> None:
    report = ScanReport(url="https://9.9.9.9")
    report.network = NetworkInfo(host="9.9.9.9", ipv4=("9.9.9.9",))
    report.software = [
        Software(name="nginx", version="1.0", source="header:server", os="Ubuntu"),
    ]
    report.ports = PortScan(
        scanner="connect",
        ports=(
            Port(port=22, host="9.9.9.9", service="ssh", os="Ubuntu"),
            Port(port=3306, host="9.9.9.9", service="mysql", os="Debian"),
        ),
    )
    findings = detect_os(report)
    finding = next(f for f in findings if f.host == "9.9.9.9")
    assert finding.os == "Ubuntu"
    assert finding.confidence == 2 / 3
