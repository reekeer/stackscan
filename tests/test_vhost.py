from __future__ import annotations

import asyncio
from dataclasses import dataclass

from stackscan.scan import ScanOptions, discover_vhosts
from stackscan.types import FetchResult, NetworkInfo, Port, PortScan, ScanReport, Subdomain


@dataclass
class _MockResponse:
    status: int
    headers: dict[str, str]
    body: str
    url: str = "http://1.2.3.4/"
    http_version: str | None = "1.1"


class _MockSession:
    def __init__(self, responses: dict[tuple[str, str | None], _MockResponse]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    async def fetch(
        self,
        url: str,
        *,
        timeout: float,
        user_agent: str,
        insecure: bool,
        max_bytes: int,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> FetchResult:
        self.calls.append((url, headers))
        key = (url, headers.get("Host") if headers else None)
        resp = self._responses.get(key, _MockResponse(status=403, headers={}, body=""))
        return FetchResult(
            url=resp.url,
            status=resp.status,
            headers={"_raw": "", **{k.lower(): v for k, v in resp.headers.items()}},
            body=resp.body,
            cookies=(),
            http_version=resp.http_version,
        )


def _make_report() -> ScanReport:
    report = ScanReport(url="https://example.com")
    report.network = NetworkInfo(
        host="example.com",
        ipv4=("1.2.3.4",),
    )
    report.ports = PortScan(
        scanner="connect",
        ports=(Port(port=80, protocol="tcp", state="open", host="1.2.3.4"),),
    )
    report.subdomains = [Subdomain(name="www.example.com", addresses=("1.2.3.4",), source="dns")]
    return report


def _options() -> ScanOptions:
    return ScanOptions(
        timeout=5.0,
        user_agent="stackscan/test",
        insecure=True,
        max_bytes=10000,
        full=True,
        discover_sites=True,
        concurrency=10,
    )


def test_discover_vhosts_finds_new_subdomain() -> None:
    report = _make_report()
    options = _options()
    responses: dict[tuple[str, str | None], _MockResponse] = {
        ("http://1.2.3.4", None): _MockResponse(status=403, headers={}, body="baseline"),
        ("http://1.2.3.4", "www.example.com"): _MockResponse(status=403, headers={}, body=""),
        (
            "http://1.2.3.4",
            "mail.example.com",
        ): _MockResponse(
            status=301,
            headers={"Location": "https://mail.example.com/"},
            body="",
        ),
    }
    session = _MockSession(responses)
    found = asyncio.run(discover_vhosts(report, session, options))  # type: ignore[arg-type]
    names = {sub.name for sub in found}
    assert "mail.example.com" in names
    assert "www.example.com" not in names


def test_discover_vhosts_extracts_hosts_from_content() -> None:
    report = _make_report()
    options = _options()
    body = '<a href="https://api.example.com/v1">api</a><script src="https://cdn.example.com/app.js"></script>'
    responses: dict[tuple[str, str | None], _MockResponse] = {
        ("http://1.2.3.4", None): _MockResponse(status=403, headers={}, body="baseline"),
        (
            "http://1.2.3.4",
            "cdn.example.com",
        ): _MockResponse(
            status=200,
            headers={},
            body="cdn",
        ),
    }
    session = _MockSession(responses)
    found = asyncio.run(discover_vhosts(report, session, options, body=body))  # type: ignore[arg-type]
    names = {sub.name for sub in found}
    assert "cdn.example.com" in names
    # api resolves to same baseline, so it is not flagged as a separate vhost
    assert "api.example.com" not in names


class _CatchAllSession:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, str] | None]] = []

    async def fetch(
        self,
        url: str,
        *,
        timeout: float,
        user_agent: str,
        insecure: bool,
        max_bytes: int,
        headers: dict[str, str] | None = None,
        allow_redirects: bool = True,
    ) -> FetchResult:
        self.calls.append((url, headers))
        host = headers.get("Host") if headers else None
        status = 403 if host is None else 200
        return FetchResult(
            url=url, status=status, headers={"_raw": ""}, body="ok", cookies=(), http_version="1.1"
        )


def test_discover_vhosts_skips_catch_all_ip() -> None:
    report = _make_report()
    options = _options()
    session = _CatchAllSession()
    found = asyncio.run(discover_vhosts(report, session, options))  # type: ignore[arg-type]
    assert found == []


def test_discover_vhosts_respects_full_flag() -> None:
    report = _make_report()
    options = ScanOptions(
        timeout=5.0,
        user_agent="stackscan/test",
        insecure=True,
        max_bytes=10000,
        full=False,
        discover_sites=True,
        concurrency=10,
    )
    session = _MockSession({})
    found = asyncio.run(discover_vhosts(report, session, options))  # type: ignore[arg-type]
    assert found == []
    assert session.calls == []
