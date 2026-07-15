from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urljoin

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
from stackscan.net.ipinfo import is_cdn_host, is_public_ip
from stackscan.net.subdomains import RECURSIVE_PREFIXES, hostnames_in_records, load_bundled_wordlist
from stackscan.scanners.isp_blocked import detect_isp_block
from stackscan.scanners.secrets import scan_secrets
from stackscan.scanners.takeover import detect_takeovers
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
    Subdomain,
    Technology,
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


async def _cdn_ips(
    ips: set[str], *, timeout: float = 8.0, workers: int = 5
) -> set[str]:
    import aiohttp

    public = [ip for ip in ips if is_public_ip(ip)]
    if not public:
        return set()
    semaphore = asyncio.Semaphore(max(workers, 1))
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    cdn: set[str] = set()

    async with aiohttp.ClientSession(timeout=client_timeout) as session:

        async def check(ip: str) -> None:
            async with semaphore:
                try:
                    async with session.get(
                        f"https://ipwho.is/{ip}",
                        headers={"User-Agent": "stackscan"},
                    ) as resp:
                        if resp.status != 200:
                            return
                        data = cast("dict[str, Any]", await resp.json())
                except Exception:
                    return
            if not data.get("success"):
                return
            connection = cast("dict[str, Any]", data.get("connection") or {})
            org = str(connection.get("org") or "")
            isp = str(connection.get("isp") or "")
            if is_cdn_host(org, isp):
                cdn.add(ip)

        await asyncio.gather(*(check(ip) for ip in public))
    return cdn


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
    probe_404: bool = True
    cve: bool = True
    cve_online: bool = False
    cve_min_confidence: int = 0
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


_FALLBACK_404_PATHS = [
    lambda: f"stackscan-{secrets.token_urlsafe(8).lower()}",
    lambda: f"stackscan-{secrets.token_urlsafe(6).lower()}.php",
    lambda: f"stackscan-{secrets.token_urlsafe(6).lower()}/",
]


async def _probe_404(
    session: StackscanSession, base_url: str, options: ScanOptions
) -> FetchResult | None:
    timeout = min(options.timeout, 4.0)
    for path_factory in _FALLBACK_404_PATHS:
        probe_url = urljoin(base_url.rstrip("/") + "/", path_factory())
        try:
            result = await session.fetch(
                probe_url,
                timeout=timeout,
                user_agent=options.user_agent,
                insecure=options.insecure,
                max_bytes=options.max_bytes,
            )
        except Exception:
            continue
        if result.status in {404, 400, 401, 403, 500, 502, 503}:
            return result
    return None


def _merge_technologies(primary: list[Technology], extra: list[Technology]) -> list[Technology]:
    by_name: dict[str, Technology] = {tech.name.lower(): tech for tech in primary}
    for tech in extra:
        key = tech.name.lower()
        existing = by_name.get(key)
        if existing is None:
            by_name[key] = tech
        else:
            combined_evidence = tuple(dict.fromkeys((*existing.evidence, *tech.evidence)))
            by_name[key] = Technology(
                name=existing.name,
                categories=existing.categories or tech.categories,
                evidence=combined_evidence,
                location=existing.location or tech.location,
                confidence=max(existing.confidence, tech.confidence),
                version=existing.version or tech.version,
            )
    return sorted(by_name.values(), key=lambda t: t.name.lower())


def _merge_software(primary: list[Software], extra: list[Software]) -> list[Software]:
    seen: set[tuple[str, str | None]] = {(s.name.lower(), s.version) for s in primary}
    merged = list(primary)
    for item in extra:
        key = (item.name.lower(), item.version)
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


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
    block_msg = detect_isp_block(url, fetched)
    if block_msg:
        return SiteFinding(url=url, final_url=fetched.url, status=fetched.status, error=block_msg)
    host = host_of(url)
    if host and is_https(url):
        try:
            tls = await asyncio.to_thread(
                fetch_tls_info, host, port_of(url), insecure=options.insecure
            )
        except Exception:
            tls = None

    technologies = analyzer.detect(fetched)
    software = extract_software(fetched.headers, fetched.body, location=host_of(fetched.url))
    if options.probe_404:
        not_found = await _probe_404(session, fetched.url, options)
        if not_found is not None:
            technologies = _merge_technologies(technologies, analyzer.detect(not_found))
            software = _merge_software(
                software,
                extract_software(not_found.headers, not_found.body, location=host_of(not_found.url)),
            )

    return SiteFinding(
        url=url,
        final_url=fetched.url,
        status=fetched.status,
        technologies=technologies,
        software=software,
        infra=analyze_infra(fetched.headers, tuple(fetched.cookies), host),
        security=analyze_security_headers(fetched.headers),
        exposure=await analyze_exposure(session, fetched.url, probe) if options.probe else None,
        protocols=_http_protocols(fetched, tls),
    )


def _collect_ips(report: ScanReport, *, include_vhost: bool = False) -> set[str]:
    ips: set[str] = set()
    if report.network is not None:
        ips.update(report.network.ipv4)
        ips.update(report.network.ipv6)
    for sub in report.subdomains:
        if not include_vhost and sub.source == "vhost":
            continue
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


_VHOST_BASELINE_TIMEOUT = 4.0
_VHOST_PROBE_TIMEOUT = 3.0
_VHOST_MAX_CANDIDATES = 700


def _vhost_candidate_names(report: ScanReport, limit: int, body: str = "") -> list[str]:
    apex = report.network.host if report.network else host_of(report.url)
    if not apex:
        return []
    seen: set[str] = set()
    names: list[str] = []

    def add(name: str) -> None:
        if name and name not in seen and name.endswith("." + apex):
            seen.add(name)
            names.append(name)

    for sub in report.subdomains:
        add(sub.name)
        for zone in _parent_zhosts(sub.name, apex):
            add(zone)
    for host in _subdomains_from_content(report, body):
        add(host)
    for label in load_bundled_wordlist():
        add(f"{label}.{apex}")
    for prefix in RECURSIVE_PREFIXES:
        for base in (apex, *(sub.name for sub in report.subdomains)):
            if base == apex:
                add(f"{prefix}.{apex}")
            else:
                add(f"{prefix}.{base}")
    return names[:limit]


def _parent_zhosts(name: str, apex: str) -> list[str]:
    labels = name.split(".")
    apex_len = len(apex.split("."))
    out: list[str] = []
    while len(labels) > apex_len + 1:
        labels = labels[1:]
        out.append(".".join(labels))
    return out


async def _probe_vhost(
    session: StackscanSession,
    ip: str,
    port: int,
    tls: bool,
    name: str,
    user_agent: str,
    timeout: float,
    max_bytes: int,
    baseline_status: int | None,
) -> tuple[str, int | None, str]:
    try:
        result = await session.fetch(
            _http_url(ip, port, tls),
            timeout=timeout,
            user_agent=user_agent,
            insecure=True,
            max_bytes=max_bytes,
            headers={"Host": name},
        )
    except Exception:
        return (name, None, "")
    body = result.body.lower()
    location = result.headers.get("location", "")
    return (name, result.status, location + body[:512])


async def _vhost_baselines(
    session: StackscanSession,
    targets: list[tuple[str, int, bool]],
    user_agent: str,
    timeout: float,
    max_bytes: int,
) -> dict[tuple[str, int, bool], tuple[int | None, str]]:
    semaphore = asyncio.Semaphore(10)

    async def one(target: tuple[str, int, bool]) -> tuple[tuple[str, int, bool], tuple[int | None, str]]:
        ip, port, tls = target
        async with semaphore:
            try:
                result = await session.fetch(
                    _http_url(ip, port, tls),
                    timeout=timeout,
                    user_agent=user_agent,
                    insecure=True,
                    max_bytes=max_bytes,
                )
            except Exception:
                return (target, (None, ""))
            return (target, (result.status, result.body.lower()[:512]))

    results = await asyncio.gather(*(one(t) for t in targets))
    return dict(results)


def _subdomains_from_content(report: ScanReport, body: str) -> set[str]:
    apex = report.network.host if report.network else host_of(report.url)
    if not apex:
        return set()
    return hostnames_in_records((body,), apex)


async def discover_vhosts(
    report: ScanReport,
    session: StackscanSession,
    options: ScanOptions,
    body: str = "",
    cdn_ips: set[str] | None = None,
) -> list[Subdomain]:
    if not options.full or not options.discover_sites:
        return []
    cdn_ips = cdn_ips or set()
    ips = {ip for ip in _collect_ips(report) if ip not in cdn_ips}
    if not ips:
        return []
    port_scan = report.ports
    targets: list[tuple[str, int, bool]] = []
    if port_scan is not None:
        for port in port_scan.ports:
            if port.port not in (80, 443):
                continue
            for ip in ips:
                targets.append((ip, port.port, port.port == 443))
    if not targets:
        return []
    targets = list(dict.fromkeys(targets))
    names = _vhost_candidate_names(report, min(options.subdomain_limit, _VHOST_MAX_CANDIDATES), body)
    if not names:
        return []
    baselines = await _vhost_baselines(
        session,
        targets,
        options.user_agent,
        _VHOST_BASELINE_TIMEOUT,
        options.max_bytes,
    )
    semaphore = asyncio.Semaphore(max(options.workers, 50))

    async def one(
        target: tuple[str, int, bool], name: str
    ) -> tuple[str, tuple[str, ...]] | None:
        ip, port, tls = target
        baseline = baselines.get(target)
        if baseline is None or baseline[0] is None:
            return None
        async with semaphore:
            vname, status, indicator = await _probe_vhost(
                session,
                ip,
                port,
                tls,
                name,
                options.user_agent,
                _VHOST_PROBE_TIMEOUT,
                options.max_bytes,
                baseline[0],
            )
        if status is None:
            return None
        if status != baseline[0] or vname.lower() in indicator or vname.replace(".", "-") in indicator:
            return (vname, (ip,))
        return None

    tasks = [one(t, name) for t in targets for name in names]
    found = await asyncio.gather(*tasks)
    discovered: dict[str, Subdomain] = {}
    existing_names = {sub.name for sub in report.subdomains}
    for item in found:
        if item is None:
            continue
        name, addrs = item
        if name in existing_names or name in discovered:
            continue
        discovered[name] = Subdomain(name=name, addresses=addrs, source="vhost")
    return sorted(discovered.values(), key=lambda sub: sub.name)


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
    cdn_ips: set[str] | None = None,
) -> tuple[PortScan | None, dict[str, PortScan]]:
    cdn_ips = cdn_ips or set()
    ips = {ip for ip in ips if ip not in cdn_ips}
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
    skipped = f", skipped {len(cdn_ips)} CDN/proxy IP(s)" if cdn_ips else ""
    merged = PortScan(
        scanner="nmap" if options.prefer_nmap else "connect",
        ports=tuple(all_ports),
        note=f"scanned {len(per_ip)} host(s){skipped}",
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
            block_msg = detect_isp_block(url, fetched)
            if block_msg:
                stage(block_msg)
                report.error = block_msg
                report.final_url = fetched.url
                report.status = fetched.status
                report.elapsed = perf_counter() - started
                return report
            stage("parsing page · detecting technologies")
            report.final_url = fetched.url
            report.status = fetched.status
            report.technologies = matchers_analyzer.detect(fetched)
            report.infra = analyze_infra(fetched.headers, tuple(fetched.cookies), host)
            report.security = analyze_security_headers(fetched.headers)
            report.protocols = _http_protocols(fetched, report.tls)
            report.secrets = scan_secrets(
                fetched.body, location=host_of(fetched.url) if fetched else host or ""
            )
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
        content_hosts: set[str] = (
            hostnames_in_records((fetched.body,), host) if fetched and host else set()
        )
        sub_coro = (
            enumerate_subdomains(
                host,
                san_names=san,
                dns_hosts=(*_dns_record_hosts(report.network), *content_hosts),
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

        if options.subdomains and report.subdomains:
            stage("checking for subdomain takeovers")
            report.takeovers = await detect_takeovers(
                report.subdomains,
                session,
                timeout=min(options.timeout, 8.0),
                user_agent=options.user_agent,
                workers=max(options.workers // 10, 5),
            )

        ips = _collect_ips(report)
        cdn_ips: set[str] = set()
        if (options.smart_scan or options.ports) and ips:
            stage("identifying CDN/proxy IPs")
            cdn_ips = await _cdn_ips(
                ips,
                timeout=min(options.timeout, 8.0),
                workers=max(options.workers // 10, 4),
            )
            if cdn_ips:
                stage(f"skipping {len(cdn_ips)} CDN/proxy IP(s)")

        if options.smart_scan:
            stage(f"scanning ports on {len(ips - cdn_ips)} host(s)")
            report.ports, _ = await _scan_ports_on_ips(ips, options, cdn_ips=cdn_ips)
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
            vhosts = await discover_vhosts(
                report, session, options, body=fetched.body if fetched else "", cdn_ips=cdn_ips
            )
            if vhosts:
                report.subdomains.extend(vhosts)
                report.subdomains.sort(key=lambda sub: sub.name)
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
            report.cves = match_cves(
                _all_software(report), min_confidence=max(0, options.cve_min_confidence)
            )

        if options.ip_info or options.default_creds or (options.cve and options.cve_online):
            stage("IP intelligence · default-cred checks")
        online_coro = (
            match_cves_online(
                _all_software(report), min_confidence=max(0, options.cve_min_confidence)
            )
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
