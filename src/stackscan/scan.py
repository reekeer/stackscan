from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING, Any

from stackscan.analyzers import (
    ExposureProbe,
    TechAnalyzer,
    analyze_exposure,
    analyze_infra,
    analyze_security_headers,
    classify_services,
    detect_devices,
    detect_os,
    extract_software,
    match_cves,
    match_cves_online,
    merge_cve_matches,
    parse_social,
    software_from_ports,
)
from stackscan.net import (
    GeoProvider,
    enrich_ips,
    enumerate_subdomains,
    fetch_tls_info,
    lookup_geo,
    resolve_host,
    scan_ports,
)
from stackscan.types import (
    BruteTarget,
    CredFinding,
    FetchResult,
    IpInfo,
    NetworkInfo,
    Port,
    PortScan,
    ScanReport,
    SiteFinding,
    Software,
    TlsInfo,
)
from stackscan.utils import host_of, is_https, port_of

if TYPE_CHECKING:
    from stackscan.core import StackscanSession

_HTTP_PORTS: frozenset[int] = frozenset(
    {80, 443, 631, 2082, 2083, 3000, 7547, 8000, 8080, 8081, 8443, 8888, 9000}
)


def _http_url(host: str, port: int, tls: bool) -> str:
    scheme = "https" if tls else "http"
    if (tls and port == 443) or (not tls and port == 80):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


async def _fetch_with_fallback(
    url: str, session: StackscanSession, options: ScanOptions, report: ScanReport
) -> tuple[FetchResult | None, str]:
    attempts: list[tuple[str, bool]] = [(url, options.insecure)]
    if is_https(url) and not options.insecure:
        attempts.append((url, True))
    if is_https(url):
        attempts.append(("http://" + url.split("://", 1)[1], False))
    first_error: str | None = None
    for attempt, insecure in attempts:
        try:
            fetched = await session.fetch(
                attempt,
                timeout=options.timeout,
                user_agent=options.user_agent,
                insecure=insecure,
                max_bytes=options.max_bytes,
            )
        except Exception as exc:
            if first_error is None:
                first_error = str(exc)
            continue
        return (fetched, attempt)
    report.error = first_error
    return (None, url)


def _dns_record_hosts(net: NetworkInfo | None) -> tuple[str, ...]:
    if net is None:
        return ()
    return (*net.mx, *net.ns, *net.cname, *net.txt, *net.soa)


def _http_protocols(fetched: FetchResult, tls: TlsInfo | None) -> list[str]:
    protocols: list[str] = []
    if fetched.http_version:
        protocols.append(f"HTTP/{fetched.http_version}")
    if tls and tls.alpn == "h2":
        protocols.append("HTTP/2 (ALPN)")
    alt_svc = fetched.headers.get("alt-svc", "")
    if "h3" in alt_svc:
        protocols.append("HTTP/3 (Alt-Svc)")
    return protocols


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
    cve: bool = True
    cve_online: bool = False
    parse_social: bool = False
    ports: bool = False
    subdomains: bool = False
    ip_info: bool = True
    default_creds: bool = False
    port_timeout: float = 2.0
    prefer_nmap: bool = True
    workers: int = 100
    subdomain_limit: int = 5000
    cred_limit: int = 100
    ct_logs: bool = True
    concurrency: int = 10
    full: bool = False
    smart_scan: bool = False
    discover_sites: bool = False
    site_limit: int = 20


def _collect_dns_domains(host: str, dns: Any) -> tuple[str, ...]:
    domains: set[str] = {host}
    for vals in (dns.cname, dns.mx, dns.ns, dns.soa, dns.txt):
        for value in vals:
            for part in value.split():
                part = part.strip(". ")
                if "." in part and not part.replace(".", "").isdigit():
                    domains.add(part.lower())
    for name in dns.reverse_dns.values():
        domains.add(name.lower().rstrip("."))
    return tuple(sorted(domains))


async def _resolve_network(host: str, options: ScanOptions, geo: GeoProvider) -> NetworkInfo | None:
    if not host or not options.dns:
        return None
    dns = await asyncio.to_thread(resolve_host, host)
    geo_map: dict[str, dict[str, str]] = {}
    if options.geo and geo.enabled:
        geo_map = await asyncio.to_thread(lookup_geo, (*dns.ipv4, *dns.ipv6), geo)
    domains = _collect_dns_domains(host, dns)
    return NetworkInfo(
        host=host,
        ipv4=dns.ipv4,
        ipv6=dns.ipv6,
        cname=dns.cname,
        mx=dns.mx,
        ns=dns.ns,
        txt=dns.txt,
        soa=dns.soa,
        caa=dns.caa,
        reverse_dns=dns.reverse_dns,
        geo=geo_map,
        domains=domains,
    )


async def _scan_site(
    url: str,
    session: StackscanSession,
    options: ScanOptions,
    analyzer: TechAnalyzer,
    probe: ExposureProbe,
) -> SiteFinding:
    tls: TlsInfo | None = None
    try:
        fetched = await session.fetch(
            url,
            timeout=min(options.timeout, 6.0),
            user_agent=options.user_agent,
            insecure=options.insecure,
            max_bytes=options.max_bytes,
        )
    except Exception as exc:
        return SiteFinding(url=url, error=str(exc))
    host = host_of(url)
    if host and is_https(url):
        try:
            tls = await asyncio.to_thread(
                fetch_tls_info, host, port_of(url), insecure=options.insecure
            )
        except Exception:
            tls = None
    return SiteFinding(
        url=url,
        final_url=fetched.url,
        status=fetched.status,
        technologies=analyzer.detect(fetched),
        software=extract_software(fetched.headers, fetched.body, location=host_of(fetched.url)),
        infra=analyze_infra(fetched.headers, tuple(fetched.cookies), host),
        security=analyze_security_headers(fetched.headers),
        exposure=await analyze_exposure(session, fetched.url, probe) if options.probe else None,
        protocols=_http_protocols(fetched, tls),
    )


def _collect_ips(report: ScanReport) -> set[str]:
    ips: set[str] = set()
    if report.network is not None:
        ips.update(report.network.ipv4)
        ips.update(report.network.ipv6)
    for sub in report.subdomains:
        ips.update(sub.addresses)
    return ips


def _collect_site_candidates(report: ScanReport, limit: int) -> list[str]:
    candidates: list[str] = []
    seen: set[str] = set()
    primary = report.final_url or report.url

    def add(url: str) -> None:
        if url not in seen:
            seen.add(url)
            candidates.append(url)

    if primary:
        add(primary)

    port_scan = report.ports
    if port_scan is not None:
        for port in port_scan.ports:
            if port.port not in _HTTP_PORTS:
                continue
            host = port.host or report.network.host if report.network else None
            if not host:
                continue
            tls = port.port in (443, 8443, 2083) or "https" in (port.service or "").lower()
            add(_http_url(host, port.port, tls))

    for sub in report.subdomains:
        if sub.name in seen or f"https://{sub.name}" in seen:
            continue
        add(f"https://{sub.name}")
        add(f"http://{sub.name}")

    return candidates[:limit]


async def _scan_derived_sites(
    candidates: list[str],
    session: StackscanSession,
    options: ScanOptions,
    analyzer: TechAnalyzer,
) -> list[SiteFinding]:
    if not candidates:
        return []
    probe = ExposureProbe(
        timeout=min(options.timeout, 6.0),
        user_agent=options.user_agent,
        insecure=options.insecure,
    )
    semaphore = asyncio.Semaphore(max(options.concurrency, 5))

    async def one(url: str) -> SiteFinding:
        async with semaphore:
            return await _scan_site(url, session, options, analyzer, probe)

    results = await asyncio.gather(*(one(url) for url in candidates))
    seen_urls: set[str] = set()
    unique: list[SiteFinding] = []
    for r in results:
        if r.status is None:
            continue
        key = (r.final_url or r.url).rstrip("/")
        if key in seen_urls:
            continue
        seen_urls.add(key)
        unique.append(r)
    return unique


def _all_software(report: ScanReport) -> list[Software]:
    software: list[Software] = []
    seen: set[tuple[str, str | None]] = set()

    def add(items: list[Software]) -> None:
        for item in items:
            key = (item.name.lower(), item.version)
            if key in seen:
                continue
            seen.add(key)
            software.append(item)

    add(report.software)
    add(software_from_ports(report.ports))
    for site in report.site_findings:
        add(site.software)
    return software


async def _scan_ports_on_ips(
    ips: set[str],
    options: ScanOptions,
) -> tuple[PortScan | None, dict[str, PortScan]]:
    if not ips or not options.ports:
        return (None, {})
    semaphore = asyncio.Semaphore(max(options.workers // 10, 4))

    async def one(ip: str) -> tuple[str, PortScan]:
        async with semaphore:
            scan = await scan_ports(
                ip,
                timeout=options.port_timeout,
                prefer_nmap=options.prefer_nmap,
                workers=max(options.workers // len(ips), 20),
            )
        return (ip, scan)

    results = await asyncio.gather(*(one(ip) for ip in ips))
    per_ip: dict[str, PortScan] = {ip: scan for ip, scan in results}
    seen_ports: set[tuple[str | None, int]] = set()
    all_ports: list[Port] = []
    for scan in per_ip.values():
        for port in scan.ports:
            key = (port.host, port.port)
            if key in seen_ports:
                continue
            seen_ports.add(key)
            all_ports.append(port)
    all_ports.sort(key=lambda p: (p.host or "", p.port))
    merged = PortScan(
        scanner="nmap" if options.prefer_nmap else "connect",
        ports=tuple(all_ports),
        note=f"scanned {len(per_ip)} host(s)",
    )
    return (merged, per_ip)


async def _enrich_unique_ips(
    report: ScanReport,
    options: ScanOptions,
) -> list[IpInfo]:
    if not options.ip_info:
        return []
    unique: set[str] = set()
    sources: dict[str, str] = {}
    if report.network is not None:
        host = report.network.host
        for ip in (*report.network.ipv4, *report.network.ipv6):
            unique.add(ip)
            sources.setdefault(ip, host)
    for sub in report.subdomains:
        for ip in sub.addresses:
            unique.add(ip)
            sources.setdefault(ip, sub.name)
    for port in report.ports.ports if report.ports else ():
        if port.host:
            sources.setdefault(port.host, f"port {port.port}/{port.protocol}")
    if not unique:
        return []
    return await enrich_ips(tuple(unique), workers=options.workers, sources=sources)


async def _detect_creds_smart(
    report: ScanReport,
    options: ScanOptions,
) -> tuple[list[CredFinding], list[BruteTarget]]:
    if not options.default_creds or report.ports is None:
        return ([], [])
    semaphore = asyncio.Semaphore(max(options.concurrency, 5))

    async def one(host: str, scan: PortScan) -> tuple[list[CredFinding], list[BruteTarget]]:
        async with semaphore:
            return await detect_devices(
                host,
                scan,
                timeout=min(options.timeout, 8.0),
                workers=max(options.workers // 10, 4),
            )

    hosts: set[str] = set()
    if report.network is not None:
        hosts.add(report.network.host)
    for port in report.ports.ports:
        if port.host:
            hosts.add(port.host)
    for sub in report.subdomains:
        hosts.add(sub.name)

    results = await asyncio.gather(*(one(host, report.ports) for host in hosts))
    findings: list[CredFinding] = []
    candidates: list[BruteTarget] = []
    for result_findings, result_candidates in results:
        findings.extend(result_findings)
        candidates.extend(result_candidates)
    return (findings, candidates)


async def scan_target(
    url: str,
    *,
    matchers_analyzer: TechAnalyzer,
    session: StackscanSession,
    options: ScanOptions,
    geo: GeoProvider,
    semaphore: asyncio.Semaphore,
    log: Callable[[str], None] | None = None,
) -> ScanReport:
    host = host_of(url)
    report = ScanReport(url=url)
    started = perf_counter()

    def stage(message: str) -> None:
        if log is not None:
            log(message)

    async with semaphore:
        stage("resolving DNS · fetching page · TLS handshake")
        tls_coro = (
            asyncio.to_thread(fetch_tls_info, host, port_of(url), insecure=options.insecure)
            if options.tls and host and is_https(url)
            else _aval(None)
        )
        (fetched, _effective_url), report.network, report.tls = await asyncio.gather(
            _fetch_with_fallback(url, session, options, report),
            _resolve_network(host, options, geo),
            tls_coro,
        )

        if fetched is not None:
            stage("parsing page · detecting technologies")
            report.final_url = fetched.url
            report.status = fetched.status
            report.technologies = matchers_analyzer.detect(fetched)
            report.infra = analyze_infra(fetched.headers, tuple(fetched.cookies), host)
            report.security = analyze_security_headers(fetched.headers)
            report.protocols = _http_protocols(fetched, report.tls)
            if options.parse_social:
                report.social = parse_social(fetched.body, fetched.url)

        if (options.subdomains and host) or (options.probe and fetched is not None):
            bits: list[str] = []
            if options.subdomains and host:
                bits.append("enumerating subdomains")
            if options.probe and fetched is not None:
                bits.append("probing exposure")
            stage(" · ".join(bits))
        san = report.tls.subject_alt_names if report.tls else ()
        sub_coro = (
            enumerate_subdomains(
                host,
                san_names=san,
                dns_hosts=_dns_record_hosts(report.network),
                timeout=options.port_timeout,
                workers=options.workers,
                limit=options.subdomain_limit,
                passive=options.ct_logs,
            )
            if options.subdomains and host
            else _aval([])
        )
        exp_coro = (
            analyze_exposure(
                session,
                fetched.url,
                ExposureProbe(
                    timeout=options.timeout,
                    user_agent=options.user_agent,
                    insecure=options.insecure,
                ),
            )
            if options.probe and fetched is not None
            else _aval(None)
        )
        report.subdomains, report.exposure = await asyncio.gather(sub_coro, exp_coro)

        if options.smart_scan:
            ips = _collect_ips(report)
            stage(f"scanning ports on {len(ips)} host(s)")
            report.ports, _ = await _scan_ports_on_ips(ips, options)
        elif options.ports and host:
            stage("scanning ports")
            report.ports = await scan_ports(
                host,
                timeout=options.port_timeout,
                prefer_nmap=options.prefer_nmap,
                workers=options.workers,
            )

        if options.discover_sites:
            stage("probing derived sites")
            report.site_findings = await _scan_derived_sites(
                _collect_site_candidates(report, options.site_limit),
                session,
                options,
                matchers_analyzer,
            )

        if options.cve:
            stage("correlating CVEs")
            report.software = extract_software(
                fetched.headers if fetched else {},
                fetched.body if fetched else "",
                location=host_of(fetched.url) if fetched else host,
            )
            report.software.extend(software_from_ports(report.ports))
            report.cves = match_cves(_all_software(report))

        if options.ip_info or options.default_creds or (options.cve and options.cve_online):
            stage("IP intelligence · default-cred checks")
        online_coro = (
            match_cves_online(_all_software(report))
            if options.cve and options.cve_online
            else _aval([])
        )
        ipinfo_coro = _enrich_unique_ips(report, options) if options.ip_info else _aval([])
        empty_creds: tuple[list[CredFinding], list[BruteTarget]] = ([], [])
        creds_coro = (
            _detect_creds(report, host, options) if options.default_creds else _aval(empty_creds)
        )
        online_cves, report.ip_info, creds_result = await asyncio.gather(
            online_coro, ipinfo_coro, creds_coro
        )
        report.creds, report.brute_targets = creds_result
        if online_cves:
            report.cves = merge_cve_matches(report.cves, online_cves)

        report.services = classify_services(report)
        report.os_findings = detect_os(report)
    report.elapsed = perf_counter() - started
    return report


async def _aval(value: object) -> Any:

    return value


async def _detect_creds(
    report: ScanReport, host: str, options: ScanOptions
) -> tuple[list[CredFinding], list[BruteTarget]]:
    if options.smart_scan:
        return await _detect_creds_smart(report, options)
    if host and report.ports is not None:
        return await detect_devices(
            host,
            report.ports,
            timeout=options.timeout,
            workers=max(options.workers // 10, 4),
        )
    return ([], [])
