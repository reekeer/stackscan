from __future__ import annotations

import asyncio

from stackscan.scan import ScanOptions, _fetch_with_fallback, stage_total
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
    assert stage_total(_opts()) == 9


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
    assert stage_total(minimal) == 5


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
