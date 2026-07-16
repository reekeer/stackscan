from __future__ import annotations

from stackscan.analyzers import classify_services, detect_web_services
from stackscan.types import ScanReport, Technology


def test_detect_matrix_from_body() -> None:
    techs = detect_web_services({}, '{"versions":["r0.6.1"]} /_matrix/client/versions', "hs.test")
    names = {t.name for t in techs}
    assert "Matrix Synapse" in names


def test_detect_matrix_from_server_header() -> None:
    techs = detect_web_services({"server": "Synapse/1.98.0"}, "welcome", "hs.test")
    assert any(t.name == "Matrix Synapse" for t in techs)


def test_detect_mikrotik_and_admin_category() -> None:
    techs = detect_web_services({"server": "MikroTik RouterOS"}, "webfig login", "router.test")
    tech = next(t for t in techs if t.name == "MikroTik RouterOS")
    assert tech.categories == ("admin-panel",)


def test_no_false_positive_on_plain_page() -> None:
    assert detect_web_services({"server": "nginx"}, "<h1>hello world</h1>", "x.test") == []


def test_admin_panel_category_becomes_service_finding() -> None:
    report = ScanReport(url="https://router.test")
    report.technologies = [
        Technology(name="MikroTik RouterOS", categories=("admin-panel",), evidence=("content",))
    ]
    findings = classify_services(report)
    assert any(f.kind == "admin-panel" and f.name == "MikroTik RouterOS" for f in findings)
    assert all(f.severity == "HIGH" for f in findings if f.kind == "admin-panel")
