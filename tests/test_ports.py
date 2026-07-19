from __future__ import annotations

from stackscan.net.fingerprint import (
    fingerprint_banner,
    fingerprint_http,
    fingerprint_mysql,
    sanitize_banner,
)
from stackscan.net.ports import COMMON_PORTS, default_ports


def test_default_ports_are_sorted_and_include_common_services() -> None:
    ports = default_ports()
    assert ports == tuple(sorted(ports))
    for expected in (22, 80, 443, 25, 3306, 554):
        assert expected in ports


def test_common_ports_have_probe_kind() -> None:
    for _service, probe in COMMON_PORTS.values():
        assert probe in {"banner", "http", "rtsp", "mysql", "none"}


def test_fingerprint_ssh_banner() -> None:
    service, product, version = fingerprint_banner("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1")
    assert service == "ssh"
    assert product == "OpenSSH"
    assert version == "8.9p1"


def test_fingerprint_ftp_banner() -> None:
    service, product, version = fingerprint_banner("220 ProFTPD 1.3.5 Server ready")
    assert service == "ftp"
    assert product == "ProFTPD"
    assert version == "1.3.5"


def test_fingerprint_http_server_header() -> None:
    response = "HTTP/1.1 200 OK\r\nServer: nginx/1.25.1\r\nContent-Type: text/html\r\n\r\n"
    product, version = fingerprint_http(response)
    assert product == "nginx"
    assert version == "1.25.1"


def test_fingerprint_unknown_banner() -> None:
    assert fingerprint_banner("random noise") == (None, None, None)


def test_sanitize_banner_strips_control_chars() -> None:
    raw = "\x00\x01k\n5.5.5-10.11.14-MariaDB\x07\x00"
    assert sanitize_banner(raw) == "k5.5.5-10.11.14-MariaDB"


def _mysql_handshake(version: str) -> bytes:
    payload = bytearray([0x0A])
    payload.extend(version.encode("utf-8"))
    payload.append(0x00)
    payload.extend(b"\x00" * 20)
    length = len(payload)
    return bytes([length & 0xFF, (length >> 8) & 0xFF, (length >> 16) & 0xFF, 0x00]) + bytes(
        payload
    )


def test_fingerprint_mysql_mariadb_with_ubuntu_suffix() -> None:
    data = _mysql_handshake("5.5.5-10.11.14-MariaDB-0ubuntu0.24.04.1")
    product, version, os, refused = fingerprint_mysql(data)
    assert product == "MariaDB"
    assert version == "10.11.14"
    assert "Ubuntu" in os
    assert refused is False


def test_fingerprint_mysql_plain_mysql() -> None:
    data = _mysql_handshake("8.0.35")
    product, version, os, refused = fingerprint_mysql(data)
    assert product == "MySQL"
    assert version == "8.0.35"
    assert refused is False


def test_fingerprint_mysql_err_packet_is_auth_refused() -> None:
    data = bytes([0x15, 0x00, 0x00, 0x00, 0xFF]) + b"\x00" * 21
    product, version, os, refused = fingerprint_mysql(data)
    assert refused is True


def test_fingerprint_mysql_detects_el_centos() -> None:
    data = _mysql_handshake("5.5.5-10.6.16-MariaDB-1.el8")
    product, version, os, refused = fingerprint_mysql(data)
    assert product == "MariaDB"
    assert os == "RHEL/CentOS 8"


def test_fingerprint_mysql_detects_fedora() -> None:
    data = _mysql_handshake("5.5.5-10.6.16-MariaDB-1.fc38")
    product, version, os, refused = fingerprint_mysql(data)
    assert product == "MariaDB"
    assert os == "Fedora 38"
