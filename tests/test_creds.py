from __future__ import annotations

from stackscan.analyzers.creds import _http_ports, _looks_like_device, _parse_creds_csv
from stackscan.types import Port, PortScan

_SAMPLE_CSV = 'Vendor,Username,Password,Comments\n"2Wire, Inc.",http,<BLANK>,\n3COM,admin,admin,\nAcme,admin,admin,\nNoise,some long descriptive username that is clearly not a login,x,\n'


def test_parse_creds_csv_handles_blank_and_dedupe() -> None:
    pairs = _parse_creds_csv(_SAMPLE_CSV)
    assert ("http", "") in pairs
    assert ("admin", "admin") in pairs
    assert pairs.count(("admin", "admin")) == 1
    assert all((" " not in user for user, _ in pairs))


def test_looks_like_device_matches_camera_realm() -> None:
    assert _looks_like_device('Basic realm="IPCamera"', "") is True
    assert _looks_like_device("", "Hikvision-Webs") is True
    assert _looks_like_device('Basic realm="Corporate Intranet"', "nginx") is False


def test_http_ports_split_tls() -> None:
    scan = PortScan(
        scanner="connect",
        ports=(
            Port(port=80, service="http"),
            Port(port=443, service="https"),
            Port(port=8080, service="http-proxy"),
            Port(port=22, service="ssh"),
        ),
    )
    ports = dict(_http_ports(scan))
    assert ports[80] is False
    assert ports[443] is True
    assert ports[8080] is False
    assert 22 not in ports


def test_http_ports_empty_scan() -> None:
    assert _http_ports(None) == []
