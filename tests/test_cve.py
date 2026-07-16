from __future__ import annotations

from stackscan.analyzers.cve import (
    _cmp,
    _distro_tag,
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


def test_software_from_ports_ssh_space_version() -> None:
    scan = PortScan(
        scanner="nmap",
        ports=(
            Port(
                port=22,
                service="ssh",
                product="OpenSSH",
                version="9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)",
            ),
        ),
    )
    software = software_from_ports(scan)
    ssh = next(s for s in software if s.name == "openssh")
    assert ssh.version == "9.6p1"
    assert "Ubuntu" in ssh.os


def test_match_cves_marks_nmap_ssh_banner_unconfirmed() -> None:
    scan = PortScan(
        scanner="nmap",
        ports=(
            Port(
                port=22,
                service="ssh",
                product="OpenSSH",
                version="9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)",
            ),
        ),
    )
    software = software_from_ports(scan)
    cves = match_cves(software)
    assert cves
    assert all(c.unconfirmed for c in cves)
    assert all(c.confidence <= 60 for c in cves)


def test_distro_tag_detects_backport_suffixes() -> None:
    assert _distro_tag("nginx/1.24.0 (Ubuntu)") == "Ubuntu"
    assert _distro_tag("OpenSSH_9.6p1 Ubuntu-3ubuntu13.18") == "Ubuntu"
    assert _distro_tag("10.11.14-MariaDB-0ubuntu0.24.04.1") == "0ubuntu0.24.04.1"
    assert _distro_tag("nginx/1.20.0") == ""


def test_extract_software_sets_os_from_server_header() -> None:
    headers = {"server": "nginx/1.24.0 (Ubuntu)"}
    software = extract_software(headers, "")
    nginx = next(s for s in software if s.name == "nginx")
    assert "Ubuntu" in nginx.os


def test_match_cves_marks_ubuntu_banner_unconfirmed() -> None:
    software = extract_software({"server": "nginx/1.24.0 (Ubuntu)"}, "")
    cves = match_cves(software)
    assert cves
    assert all(c.unconfirmed for c in cves)
    assert all(c.confidence <= 60 for c in cves)
    assert not any(c.severity == "CRITICAL" and not c.unconfirmed for c in cves)


def test_backport_cves_hidden_at_default_threshold() -> None:
    # Distro-backported / SSH banner matches are phantom CVEs by default: they
    # must fall below the CLI default of --cve-min-confidence 40 so they never
    # surface unless the user explicitly asks for a lower threshold.
    software = extract_software({"server": "nginx/1.24.0 (Ubuntu)"}, "")
    assert match_cves(software)
    assert match_cves(software, min_confidence=40) == []


def test_backport_ssh_cves_hidden_at_default_threshold() -> None:
    scan = PortScan(
        scanner="nmap",
        ports=(
            Port(
                port=22,
                service="ssh",
                product="OpenSSH",
                version="9.6p1 Ubuntu 3ubuntu13.18 (Ubuntu Linux; protocol 2.0)",
            ),
        ),
    )
    software = software_from_ports(scan)
    assert match_cves(software)
    assert match_cves(software, min_confidence=40) == []


def test_match_cves_clean_upstream_keeps_normal_confidence() -> None:
    software = extract_software({"server": "nginx/1.18.0"}, "")
    cves = match_cves(software)
    assert cves
    assert not any(c.unconfirmed for c in cves)
    assert all(c.confidence in (85, 91, 98) for c in cves)


def test_match_cves_marks_centos_banner_unconfirmed() -> None:
    software = extract_software({"server": "nginx/1.24.0 (CentOS)"}, "")
    cves = match_cves(software)
    assert cves
    assert all(c.unconfirmed for c in cves)
    assert all(c.confidence <= 60 for c in cves)


def test_match_cves_respects_min_confidence() -> None:
    software = extract_software({"server": "nginx/1.18.0"}, "")
    all_cves = match_cves(software)
    assert all_cves
    high_confidence = match_cves(software, min_confidence=95)
    assert len(high_confidence) < len(all_cves)
    assert all(c.confidence >= 95 for c in high_confidence)


def test_extract_software_from_core_commit_body() -> None:
    software = extract_software({}, "CurseForge Core (a26fded)")
    curse = next(s for s in software if s.name == "curseforge")
    assert curse.version == "a26fded"
    assert curse.source == "body:core-commit"


def test_extract_generic_software_from_404_body() -> None:
    body = "<html><body><hr><center>nginx/1.18.0</center></body></html>"
    software = extract_software({"server": "cloudflare"}, body)
    nginx = next(s for s in software if s.name == "nginx")
    assert nginx.version == "1.18.0"
    assert nginx.source.startswith("body:")


def test_commit_hash_does_not_match_cve_ranges() -> None:
    software = extract_software({}, "CurseForge Core (a26fded)")
    assert not match_cves(software)


def test_distro_tag_detects_various_backport_distros() -> None:
    assert _distro_tag("nginx/1.24.0 (Ubuntu)") == "Ubuntu"
    assert _distro_tag("Apache/2.4.57 (Debian)") == "Debian"
    assert _distro_tag("OpenSSH_9.6p1 Fedora-38") == "Fedora"
    assert _distro_tag("OpenSSH_9.6p1 el9_3.2") == "el9"
    assert _distro_tag("nginx/1.24.0 (Rocky Linux)") == "Rocky"
    assert _distro_tag("nginx/1.24.0 (AlmaLinux 9)") == "AlmaLinux"
    assert _distro_tag("nginx/1.24.0 (Amazon Linux 2)") == "Amazon"
    assert _distro_tag("OpenSSH_9.6p1 ~bpo11+1") == "~bpo11+1"
    assert _distro_tag("nginx/1.24.0 +deb11u1") == "+deb11u1"
    assert _distro_tag("nginx/1.24.0 (Oracle Linux 8)") == "Oracle"
    assert _distro_tag("nginx/1.24.0 (SLES 15)") == "SLES"
    assert _distro_tag("nginx/1.24.0") == ""


def test_software_from_ports_flags_distro_backports_for_any_service() -> None:
    cases = [
        ("nginx", "1.24.0 (Ubuntu)", "Ubuntu"),
        ("apache", "2.4.57 (Debian)", "Debian"),
        ("openssh", "9.6p1 Fedora-38", "Fedora"),
        ("mysql", "8.0.36-0ubuntu0.22.04.1", "Ubuntu"),
        ("nginx", "1.24.0 (Rocky Linux)", "Rocky"),
        ("nginx", "1.24.0 (AlmaLinux 9)", "AlmaLinux"),
        ("nginx", "1.24.0 (Amazon Linux 2)", "Amazon"),
    ]
    for product, version, expected in cases:
        scan = PortScan(
            scanner="nmap",
            ports=(Port(port=80, service="http", product=product, version=version),),
        )
        software = software_from_ports(scan)
        assert software, f"no software extracted for {product}"
        assert any(
            expected.lower() in (s.os or "").lower() for s in software
        ), f"expected {expected} in os for {product} {version}, got {[s.os for s in software]}"
        cves = match_cves(software)
        if cves:
            assert all(
                c.unconfirmed for c in cves
            ), f"CVEs for {product} {version} should be unconfirmed"
            assert all(
                c.confidence <= 60 for c in cves
            ), f"CVE confidence for {product} {version} should be capped at 60"
