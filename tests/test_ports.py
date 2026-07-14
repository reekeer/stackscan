from __future__ import annotations

from stackscan.net.fingerprint import fingerprint_banner, fingerprint_http
from stackscan.net.ports import COMMON_PORTS, default_ports


def test_default_ports_are_sorted_and_include_common_services() -> None:
    ports = default_ports()
    assert ports == tuple(sorted(ports))
    for expected in (22, 80, 443, 25, 3306, 554):
        assert expected in ports


def test_common_ports_have_probe_kind() -> None:
    for _service, probe in COMMON_PORTS.values():
        assert probe in {"banner", "http", "rtsp", "none"}


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
