"""Full-stack scan orchestration for a single target."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import TYPE_CHECKING

from stackscan.analyzers import (
    ExposureProbe,
    TechAnalyzer,
    analyze_exposure,
    analyze_infra,
    analyze_security_headers,
)
from stackscan.net import GeoProvider, fetch_tls_info, lookup_geo, resolve_host
from stackscan.types import FetchResult, NetworkInfo, ScanReport
from stackscan.utils import host_of, is_https

if TYPE_CHECKING:
    from stackscan.core import StackscanSession


@dataclass(frozen=True)
class ScanOptions:
    timeout: float
    user_agent: str
    insecure: bool
    max_bytes: int
    dns: bool = True
    tls: bool = True
    geo: bool = True
    probe: bool = True


async def _resolve_network(host: str, options: ScanOptions, geo: GeoProvider) -> NetworkInfo | None:
    if not host or not options.dns:
        return None
    dns = await asyncio.to_thread(resolve_host, host)
    geo_map: dict[str, dict[str, str]] = {}
    if options.geo and geo.enabled:
        geo_map = await asyncio.to_thread(lookup_geo, (*dns.ipv4, *dns.ipv6), geo)
    return NetworkInfo(
        host=host,
        ipv4=dns.ipv4,
        ipv6=dns.ipv6,
        cname=dns.cname,
        reverse_dns=dns.reverse_dns,
        geo=geo_map,
    )


async def scan_target(
    url: str,
    *,
    matchers_analyzer: TechAnalyzer,
    session: StackscanSession,
    options: ScanOptions,
    geo: GeoProvider,
    semaphore: asyncio.Semaphore,
) -> ScanReport:
    host = host_of(url)
    report = ScanReport(url=url)

    async with semaphore:
        fetched: FetchResult | None = None
        try:
            fetched = await session.fetch(
                url,
                timeout=options.timeout,
                user_agent=options.user_agent,
                insecure=options.insecure,
                max_bytes=options.max_bytes,
            )
        except Exception as exc:  # noqa: BLE001 - a scanner must survive bad targets
            report.error = str(exc)

        report.network = await _resolve_network(host, options, geo)

        if options.tls and host and is_https(url):
            report.tls = await asyncio.to_thread(fetch_tls_info, host, insecure=options.insecure)

        if fetched is None:
            return report

        report.final_url = fetched.url
        report.status = fetched.status
        report.technologies = matchers_analyzer.detect(fetched)
        report.infra = analyze_infra(fetched.headers, tuple(fetched.cookies), host)
        report.security = analyze_security_headers(fetched.headers)

        if options.probe:
            probe = ExposureProbe(
                timeout=options.timeout,
                user_agent=options.user_agent,
                insecure=options.insecure,
            )
            report.exposure = await analyze_exposure(session, fetched.url, probe)

    return report
