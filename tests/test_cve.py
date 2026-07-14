from __future__ import annotations

from stackscan.analyzers.cve import (
    _cmp,
    _in_range,
    extract_software,
    match_cves,
    software_from_ports,
)
from stackscan.types import Port, PortScan


def test_version_compare_numeric() -> None:
    assert _cmp("1.18.0", "1.20.1") < 0
    assert _cmp("1.20.1", "1.18.0") > 0
    assert _cmp("2.4.49", "2.4.49") == 0


def test_version_compare_letter_suffix() -> None:
    assert _cmp("1.0.1f", "1.0.1g") < 0
    assert _cmp("1.0.1", "1.0.1g") < 0
    assert _cmp("1.3.5b", "1.3.5") > 0


def test_in_range_bounds() -> None:
    rng = {"start_incl": "0.6.18", "end_excl": "1.20.1"}
    assert _in_range("1.18.0", rng) is True
    assert _in_range("1.20.1", rng) is False
    assert _in_range("0.6.17", rng) is False
    assert _in_range("", {}) is False


def test_extract_software_from_headers() -> None:
    headers = {"server": "nginx/1.18.0", "x-powered-by": "PHP/7.2.10"}
    software = extract_software(headers, "")
    names = {(s.name, s.version) for s in software}
    assert ("nginx", "1.18.0") in names
    assert ("php", "7.2.10") in names


def test_extract_jquery_from_body() -> None:
    body = '<script src="/assets/jquery-3.3.1.min.js"></script>'
    software = extract_software({}, body)
    assert any(s.name == "jquery" and s.version == "3.3.1" for s in software)


def test_match_cves_hits_vulnerable_nginx() -> None:
    software = extract_software({"server": "nginx/1.18.0"}, "")
    cves = match_cves(software)
    ids = {c.id for c in cves}
    assert "CVE-2021-23017" in ids
    hit = next(c for c in cves if c.id == "CVE-2021-23017")
    assert hit.severity == "HIGH"
    assert hit.confidence in (85, 91, 98)


def test_confidence_resolves_to_fixed_tiers() -> None:
    software = extract_software({"server": "nginx/1.18.0"}, "")
    cves = match_cves(software)
    assert cves
    assert all(c.confidence in (85, 91, 98) for c in cves)


def test_match_cves_excludes_patched_version_for_a_cve() -> None:
    software = extract_software({"server": "nginx/1.25.0"}, "")
    ids = {c.id for c in match_cves(software)}
    assert "CVE-2021-23017" not in ids


def test_match_cves_requires_version() -> None:
    software = extract_software({"server": "nginx"}, "")
    assert match_cves(software) == []


def test_software_from_ports_ssh_banner() -> None:
    scan = PortScan(
        scanner="connect", ports=(Port(port=22, service="ssh", version="SSH-2.0-OpenSSH_8.7"),)
    )
    software = software_from_ports(scan)
    assert any(s.name == "openssh" and s.version == "8.7" for s in software)
