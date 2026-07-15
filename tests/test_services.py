from stackscan.analyzers.services import classify_services
from stackscan.types import Port, PortScan, ScanReport, Technology


def test_database_port_emits_medium_service_by_default() -> None:
    report = ScanReport(url="https://a.test")
    report.ports = PortScan(
        scanner="connect",
        ports=(Port(port=3306, service="mysql"), Port(port=5432, service="postgresql")),
    )
    services = classify_services(report)
    kinds = {s.name: s for s in services}
    assert "MySQL" in kinds
    assert kinds["MySQL"].severity == "MEDIUM"
    assert kinds["MySQL"].kind == "database"


def test_database_auth_refused_emits_low_service() -> None:
    report = ScanReport(url="https://a.test")
    report.ports = PortScan(
        scanner="connect",
        ports=(Port(port=3306, service="mysql", state="auth-refused"),),
    )
    services = classify_services(report)
    mysql = next(s for s in services if s.name == "MySQL")
    assert mysql.severity == "LOW"


def test_admin_tech_emits_high_service() -> None:
    report = ScanReport(url="https://a.test")
    report.technologies = [Technology(name="phpMyAdmin", categories=("service",))]
    services = classify_services(report)
    assert any(s.name == "phpMyAdmin" and s.kind == "admin-panel" for s in services)


def test_remote_access_port_emits_high_service() -> None:
    report = ScanReport(url="https://a.test")
    report.ports = PortScan(scanner="connect", ports=(Port(port=3389),))
    services = classify_services(report)
    assert any(s.name == "RDP" and s.kind == "remote-access" for s in services)


def test_camera_port_emits_high_service() -> None:
    report = ScanReport(url="https://a.test")
    report.ports = PortScan(scanner="connect", ports=(Port(port=554),))
    services = classify_services(report)
    assert any(s.name == "RTSP" and s.kind == "camera" for s in services)


def test_no_duplicates_for_same_service() -> None:
    report = ScanReport(url="https://a.test")
    report.technologies = [Technology(name="MySQL", categories=("database",))]
    report.ports = PortScan(scanner="connect", ports=(Port(port=3306, service="mysql"),))
    services = classify_services(report)
    assert len([s for s in services if s.name == "MySQL"]) == 1


def test_generic_web_server_tech_does_not_emit_service_finding() -> None:
    report = ScanReport(url="https://a.test")
    report.technologies = [Technology(name="nginx", categories=("infrastructure",), evidence=("body:nginx/1.24.0",))]
    services = classify_services(report)
    assert not any(s.name == "nginx" for s in services)


def test_generic_application_tech_does_not_emit_service_finding() -> None:
    report = ScanReport(url="https://a.test")
    report.technologies = [Technology(name="CurseForge", categories=("service",), evidence=("body:powered-by",))]
    services = classify_services(report)
    assert not any(s.name == "CurseForge" for s in services)
