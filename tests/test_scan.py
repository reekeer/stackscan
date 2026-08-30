from __future__ import annotations

import asyncio

import pytest

from stackscan.net.dns import DnsResult
from stackscan.scan import ScanOptions, _fetch_with_fallback, exc_text, stage_total
from stackscan.types import FetchResult, ScanReport


def _opts(**overrides: object) -> ScanOptions:
    base: dict[str, object] = {
        "timeout": 5.0,
        "user_agent": "t",
        "insecure": False,
        "max_bytes": 1000,
    }
    base.update(overrides)
    return ScanOptions(**base)  # type: ignore[arg-type]


def test_stage_total_default_passes() -> None:
    assert stage_total(_opts()) == 17


def test_stage_total_minimal_passes() -> None:
    minimal = _opts(
        subdomains=False,
        probe=False,
        ports=False,
        cve=False,
        cve_online=False,
        ip_info=False,
        whois=False,
    )
    assert stage_total(minimal) == 7


def test_stage_total_full_passes() -> None:
    full = _opts(
        subdomains=True,
        probe=True,
        ports=True,
        cve=True,
        cve_online=True,
        ip_info=True,
        whois=True,
        default_creds=True,
        parse_social=True,
        smart_scan=True,
        discover_sites=True,
    )
    assert stage_total(full) == 20


class _FakeSession:
    def __init__(self, calls: list[tuple[str, bool]]) -> None:
        self.calls = calls
        self.index = 0

    async def fetch(
        self,
        url: str,
        *,
        timeout: float,
        user_agent: str,
        insecure: bool,
        max_bytes: int,
    ) -> FetchResult:
        self.calls.append((url, insecure))
        self.index += 1
        if self.index == 1:
            raise Exception("SSLCertVerificationError: self-signed certificate")
        return FetchResult(
            url=url,
            status=200,
            headers={},
            body="",
            cookies=(),
        )


class _Options:
    timeout = 5.0
    user_agent = "test"
    insecure = False
    max_bytes = 1000


def test_fetch_with_fallback_retries_insecure_https() -> None:
    session = _FakeSession([])
    report = ScanReport(url="https://1.2.3.4")
    result, effective = asyncio.run(
        _fetch_with_fallback("https://1.2.3.4", session, _Options(), report)
    )
    assert result is not None
    assert result.status == 200
    assert effective == "https://1.2.3.4"
    assert session.calls[0] == ("https://1.2.3.4", False)
    assert session.calls[1] == ("https://1.2.3.4", True)
    assert report.error is None


class _TimeoutSession:
    async def fetch(self, url: str, **_: object) -> FetchResult:
        raise TimeoutError


def test_exc_text_names_empty_exceptions() -> None:
    assert exc_text(TimeoutError()) == "timed out"
    assert exc_text(ConnectionResetError()) == "ConnectionResetError"
    assert exc_text(ValueError("boom")) == "boom"


def test_fetch_with_fallback_reports_timeout_message() -> None:
    report = ScanReport(url="http://slow.test")
    result, _ = asyncio.run(
        _fetch_with_fallback("http://slow.test", _TimeoutSession(), _Options(), report)
    )
    assert result is None
    assert report.error == "timed out"


def _empty_dns(host: str, **_: object) -> DnsResult:
    return DnsResult(host=host, ipv4=(), ipv6=(), cname=(), reverse_dns={})


def test_resolve_network_seeds_bare_ipv4_target(monkeypatch: pytest.MonkeyPatch) -> None:
    from stackscan import scan
    from stackscan.net import GeoProvider
    from stackscan.scan import _collect_ips, _resolve_network

    monkeypatch.setattr(scan, "resolve_host", _empty_dns)
    net = asyncio.run(_resolve_network("192.0.2.1", _opts(geo=False), GeoProvider(None)))
    assert net is not None
    assert "192.0.2.1" in net.ipv4
    report = ScanReport(url="https://192.0.2.1")
    report.network = net
    # Without the seed the address set is empty and every IP-keyed pass (ports, ip-info) is skipped.
    assert _collect_ips(report) == {"192.0.2.1"}


def test_resolve_network_seeds_bare_ipv6_target(monkeypatch: pytest.MonkeyPatch) -> None:
    from stackscan import scan
    from stackscan.net import GeoProvider
    from stackscan.scan import _resolve_network

    monkeypatch.setattr(scan, "resolve_host", _empty_dns)
    net = asyncio.run(_resolve_network("2001:db8::1", _opts(geo=False), GeoProvider(None)))
    assert net is not None
    assert "2001:db8::1" in net.ipv6


def test_resolve_network_does_not_seed_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    from stackscan import scan
    from stackscan.net import GeoProvider
    from stackscan.scan import _resolve_network

    monkeypatch.setattr(
        scan,
        "resolve_host",
        lambda host, **_: DnsResult(
            host=host, ipv4=("93.184.216.34",), ipv6=(), cname=(), reverse_dns={}
        ),
    )
    net = asyncio.run(_resolve_network("example.com", _opts(geo=False), GeoProvider(None)))
    assert net is not None
    assert "example.com" not in net.ipv4
