from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections.abc import Iterable
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.progress import Progress
from rich.table import Table

from stackscan import __version__, theme
from stackscan.analyzers import TechAnalyzer, brute_devices, summarize_edge
from stackscan.config import NoSignaturesError, SourceError, SourceStore, build_matchers
from stackscan.net import GeoProvider, nmap_available
from stackscan.render import render_banner, render_reports
from stackscan.scan import ScanOptions, StageLog, scan_target, stage_total
from stackscan.types import BruteTarget, CredFinding, DetectedTech, ScanReport
from stackscan.utils import expand_cidr, is_cidr, normalize_url

DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_BYTES = 1000000
DEFAULT_CONCURRENCY = 10
DEFAULT_WORKERS = 350
DEFAULT_USER_AGENT = "stackscan/2.0 (+https://github.com/reekeer/stackscan)"


@lru_cache(maxsize=1)
def _glyphs() -> theme.Glyphs:
    return theme.glyphs(Console(stderr=True))


class _HelpAction(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        render_banner(Console())
        parser.print_help()
        parser.exit()


def _build_scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stackscan",
        description="Full web stack analyzer (technologies, edge infra, network, exposure).",
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", action=_HelpAction, nargs=0, help="Show this help message and exit."
    )

    parser.add_argument("targets", nargs="*", help="Target URLs or hostnames.")
    parser.add_argument("-f", "--file", dest="file", type=Path, help="File with targets, one/line.")
    parser.add_argument("--sigdb", dest="sigdb", help="Explicit .sigdb path (overrides default).")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout.")
    parser.add_argument("--user-agent", dest="user_agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification.")
    parser.add_argument("--max-bytes", dest="max_bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument(
        "--concurrency", type=int, default=DEFAULT_CONCURRENCY, help="Concurrent targets."
    )
    parser.add_argument("--geoip-db", dest="geoip_db", help="MaxMind .mmdb for IP geolocation.")
    parser.add_argument(
        "--disable",
        dest="disable",
        default="",
        metavar="LIST",
        help='Skip passes by name, e.g. --disable "dns,tls,geo,probe,cve,ip-info,nmap".',
    )
    parser.add_argument(
        "--parse-social",
        dest="parse_social",
        action="store_true",
        help="Extract social media and contact links from the page.",
    )
    parser.add_argument(
        "--cve-online",
        action="store_true",
        help="Also query NVD live for detected products (default is offline).",
    )
    parser.add_argument(
        "--cve-min-confidence",
        dest="cve_min_confidence",
        type=int,
        default=40,
        metavar="N",
        help="Hide CVE matches with confidence below N (0-100, default 40).",
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Deep scan: enable ports, subdomains, offline CVEs, IP info, and default-cred checks.",
    )
    parser.add_argument(
        "--full-auto",
        dest="full_auto",
        action="store_true",
        help="Auto-accept every brute prompt on discovered devices (enables default-cred checks).",
    )
    parser.add_argument(
        "--ports",
        action="store_true",
        help="Active port/service scan (nmap if installed, else a Python connect scan).",
    )

    parser.add_argument(
        "--port-timeout", dest="port_timeout", type=float, default=1.5, help="Per-port timeout."
    )
    parser.add_argument(
        "--subdomains",
        action="store_true",
        help="Enumerate subdomains via AXFR + DNS wordlist + TLS SANs.",
    )
    parser.add_argument(
        "--subdomain-limit",
        dest="subdomain_limit",
        type=int,
        default=5000,
        help="Max wordlist labels to resolve (0 = the full ~870k list, slow).",
    )
    parser.add_argument(
        "--hide-unresolved",
        dest="hide_unresolved",
        action="store_true",
        help="Hide subdomain entries that have no A record.",
    )
    parser.add_argument(
        "--site-limit",
        dest="site_limit",
        type=int,
        default=50,
        help="Max derived sites to analyze from discovered open ports (0 = unlimited).",
    )
    parser.add_argument(
        "--default-creds",
        dest="default_creds",
        action="store_true",
        help="Bounded default-credential / open-device check (authorized targets only).",
    )
    parser.add_argument(
        "--cred-limit",
        dest="cred_limit",
        type=int,
        default=50,
        help="Max default-credential pairs to try per device (0 = full SecLists list).",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=DEFAULT_WORKERS,
        help="Parallel workers for ports/subdomains/creds.",
    )
    parser.add_argument(
        "--export",
        dest="export",
        default="",
        metavar="FMTS",
        help="Export report: html, xml, json-f (file), json-t (terminal). Comma-separated.",
    )
    parser.add_argument(
        "--output",
        dest="output",
        default="stackscan-report",
        help="Base name/path for file exports (default: stackscan-report).",
    )
    parser.add_argument(
        "--graph", dest="graph", action="store_true", help="Include graph in JSON output."
    )
    parser.add_argument("--show-empty", action="store_true", help="Show targets with no findings.")
    parser.add_argument("--compact", action="store_true", help="Compact one-row-per-target table.")
    parser.add_argument(
        "--no-bell",
        dest="no_bell",
        action="store_true",
        help="Do not ring the terminal bell when the scan finishes.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        type=int,
        default=0,
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _extract_verbose(argv: list[str]) -> tuple[int, list[str]]:

    level = 0
    rest: list[str] = []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg in ("-v", "--verbose"):
            level = max(level, 1)
            if i + 1 < len(argv) and argv[i + 1].isdigit():
                level = int(argv[i + 1])
                i += 1
        elif arg.startswith("--verbose="):
            value = arg.split("=", 1)[1]
            level = int(value) if value.isdigit() else 1
        elif len(arg) >= 2 and arg[0] == "-" and set(arg[1:]) == {"v"}:
            level = max(level, len(arg) - 1)
        else:
            rest.append(arg)
        i += 1
    return level, rest


_DISABLE_MAP: dict[str, str] = {
    "dns": "no_dns",
    "tls": "no_tls",
    "geo": "no_geo",
    "probe": "no_probe",
    "404-probe": "no_404_probe",
    "endpoints": "no_404_probe",
    "endpoint": "no_404_probe",
    "cve": "no_cve",
    "ip-info": "no_ip_info",
    "ipinfo": "no_ip_info",
    "ip": "no_ip_info",
    "builtin": "no_builtin",
    "sources": "no_sources",
    "nmap": "no_nmap",
    "banner": "no_banner",
    "subdomains": "no_subdomains",
    "ports": "no_ports",
    "creds": "no_creds",
    "default-creds": "no_creds",
    "cve-online": "no_cve_online",
    "social": "no_parse_social",
    "socials": "no_parse_social",
    "ct": "no_ct",
    "crt": "no_ct",
    "passive": "no_ct",
    "whois": "no_whois",
    "rdap": "no_whois",
    "registration": "no_whois",
}


def _apply_disable(args: argparse.Namespace, console: Console) -> None:
    for attr in set(_DISABLE_MAP.values()):
        if not hasattr(args, attr):
            setattr(args, attr, False)
    for token in args.disable.replace(" ", ",").split(","):
        token = token.strip().lower().lstrip("-")
        if not token:
            continue
        attr = _DISABLE_MAP.get(token)
        if attr is None:
            _warn(
                console,
                f"unknown --disable feature: {token} (known: {', '.join(sorted(_DISABLE_MAP))})",
            )
            continue
        setattr(args, attr, True)


def _read_targets(path: Path | None, positional: Iterable[str]) -> list[str]:
    targets = [item.strip() for item in positional if item.strip()]
    if path is None:
        return targets
    if not path.is_file():
        raise FileNotFoundError(f"Targets file not found: {path}")
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        targets.append(line)
    return targets


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        ordered.append(item)
    return ordered


def _format_detected(detected: DetectedTech) -> str:
    if not detected:
        return "-"
    chunks: list[str] = []
    for category in sorted(detected):
        techs = ", ".join(detected[category])
        chunks.append(f"{category}: {techs}")
    return " | ".join(chunks)


async def _expand_wildcards(raw_targets: list[str], workers: int) -> list[str]:
    from stackscan.net import expand_wildcard_target, has_wildcard, resolve_existing

    console = Console(stderr=True)
    out: list[str] = []
    for target in raw_targets:
        if not has_wildcard(target):
            out.append(target)
            continue
        candidates = expand_wildcard_target(target)
        console.print(
            f"[{theme.MUTED}]expanding[/] {target} → {len(candidates)} candidates, resolving…",
            highlight=False,
        )
        resolving = await resolve_existing(candidates, workers=max(workers * 10, 1000))
        console.print(f"[{theme.SUCCESS}][+][/] {target}: {len(resolving)} live domain(s)")
        out.extend(resolving)
    return out


class _StageTracker:
    def __init__(self, progress_obj: Progress, task_id: Any, target: str, total: int) -> None:
        self._progress = progress_obj
        self._task_id = task_id
        self._target = target
        self._index = 0
        self._total = total
        self._host = target.split("://", 1)[-1]

    def _title(self, message: str) -> None:
        _set_title(f"stackscan {self._index}/{self._total} · {self._host} · {message}")

    def stage(self, message: str) -> None:
        self._index += 1
        self._progress.update(
            self._task_id,
            advance=1,
            description=f"{_glyphs().run} {self._target} {_glyphs().bullet} {message}",
        )
        self._title(message)

    def info(self, message: str) -> None:
        self._progress.update(
            self._task_id,
            description=f"{_glyphs().run} {self._target} {_glyphs().bullet} {message}",
        )
        self._title(message)

    def reserve(self, extra: int) -> None:
        if extra <= 0:
            return
        self._total += extra
        self._progress.update(self._task_id, total=self._total)

    def advance(self, message: str, *, steps: int = 1) -> None:
        self._index += steps
        self._progress.update(
            self._task_id,
            advance=steps,
            description=f"{_glyphs().run} {self._target} {_glyphs().bullet} {message}",
        )
        self._title(message)


async def _run_scans(args: argparse.Namespace) -> list[ScanReport]:
    from stackscan.core import StackscanSession

    raw_targets = _read_targets(args.file, args.targets)
    if not raw_targets:
        return []
    expanded: list[str] = []
    for target in raw_targets:
        if is_cidr(target):
            expanded.extend(expand_cidr(target))
        else:
            expanded.append(target)
    raw_targets = expanded
    raw_targets = await _expand_wildcards(raw_targets, max(args.workers, 1))
    if not raw_targets:
        return []
    targets = _dedupe([normalize_url(target) for target in raw_targets])
    matchers = build_matchers(
        args.sigdb, use_sources=not args.no_sources, use_builtin=not args.no_builtin
    )
    analyzer = TechAnalyzer(matchers)
    geo = GeoProvider(args.geoip_db)
    full = args.full
    options = ScanOptions(
        timeout=args.timeout,
        user_agent=args.user_agent,
        insecure=args.insecure,
        max_bytes=args.max_bytes,
        dns=not args.no_dns,
        tls=not args.no_tls,
        geo=not args.no_geo,
        probe=not args.no_probe,
        probe_404=not args.no_404_probe,
        cve=not args.no_cve,
        cve_online=args.cve_online and not args.no_cve_online,
        cve_min_confidence=max(0, min(100, args.cve_min_confidence)),
        parse_social=not args.no_parse_social,
        whois=not getattr(args, "no_whois", False),
        ports=not args.no_ports,
        subdomains=not args.no_subdomains,
        hide_unresolved=args.hide_unresolved,
        ip_info=not args.no_ip_info,
        default_creds=(args.default_creds or full or args.full_auto)
        and (not getattr(args, "no_creds", False)),
        port_timeout=args.port_timeout,
        prefer_nmap=not args.no_nmap,
        workers=max(args.workers, 1),
        subdomain_limit=max(args.subdomain_limit, 0),
        cred_limit=max(args.cred_limit, 0),
        ct_logs=not getattr(args, "no_ct", False),
        concurrency=max(args.concurrency, 1),
        full=full,
        smart_scan=full,
        discover_sites=full,
        site_limit=max(args.site_limit, 0),
    )
    from rich.progress import (
        BarColumn,
        MofNCompleteColumn,
        TextColumn,
        TimeElapsedColumn,
    )

    err_console = Console(stderr=True)
    total_targets = len(targets)
    completed = 0
    staged = args.verbose >= 2 or (args.verbose == 0 and total_targets == 1)
    per_target_total = stage_total(options)

    async def scan_one(
        target: str,
        progress_obj: Progress | None = None,
        task_id: Any | None = None,
        target_total: int = 1,
    ) -> ScanReport:
        nonlocal completed
        if args.verbose == 1:
            err_console.print(f"[{theme.MUTED}][*] Starting scan of {target}...[/]")

        stage_log: StageLog | None = None
        if staged and progress_obj is not None and task_id is not None:
            stage_log = _StageTracker(progress_obj, task_id, target, target_total)
            stage_log.info("starting...")

        report = await scan_target(
            target,
            matchers_analyzer=analyzer,
            session=session,
            options=options,
            geo=geo,
            semaphore=semaphore,
            log=stage_log,
        )

        completed += 1

        findings: list[str] = []
        if report.error:
            findings.append(f"error: {report.error}")
        else:
            if report.status is not None:
                findings.append(f"status {report.status}")
            tech_count = len(report.technologies)
            if tech_count:
                findings.append(f"{tech_count} tech")
            if report.ports:
                open_ports = len(report.ports.ports)
                if open_ports:
                    findings.append(f"{open_ports} port(s)")
            if report.subdomains:
                findings.append(f"{len(report.subdomains)} subdomain(s)")
            if report.site_findings:
                findings.append(f"{len(report.site_findings)} site(s)")

        summary_str = ", ".join(findings)
        if args.verbose == 1:
            err_console.print(
                f"[{theme.SUCCESS}][+][/] [{completed}/{total_targets}] Finished {target} in {_fmt_elapsed(report.elapsed or 0)} ({summary_str})",
                highlight=False,
            )

        _set_title(f"stackscan {completed}/{total_targets} · {target.split('://', 1)[-1]}")
        if progress_obj is not None and task_id is not None:
            if staged:
                progress_obj.update(
                    task_id, completed=target_total, description=f"{_glyphs().ok} {target}"
                )
            else:
                progress_obj.update(task_id, advance=1, description=f"Scanning: {target}")

        return report

    def is_json_terminal() -> bool:
        for token in args.export.replace(" ", ",").split(","):
            if token.strip().lower() == "json-t":
                return True
        return False

    semaphore = asyncio.Semaphore(max(args.concurrency, 1))
    _set_title(f"stackscan · scanning {total_targets} target(s)")
    async with StackscanSession() as session:
        if not is_json_terminal():
            transient = args.verbose == 0
            with Progress(
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                console=err_console,
                transient=transient,
            ) as progress:
                if staged:
                    task_ids = {
                        target: progress.add_task(f"[~] {target}", total=per_target_total)
                        for target in targets
                    }
                    tasks = [
                        scan_one(target, progress, task_ids[target], per_target_total)
                        for target in targets
                    ]
                else:
                    task_id = progress.add_task("Scanning targets...", total=total_targets)
                    tasks = [scan_one(target, progress, task_id) for target in targets]
                return list(await asyncio.gather(*tasks))
        else:
            tasks = [scan_one(target) for target in targets]
            return list(await asyncio.gather(*tasks))


def _fmt_elapsed(seconds: float) -> str:
    if seconds < 90:
        return f"{seconds:.2f}s"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s ({seconds:.0f}s)"


def _infra_summary(report: ScanReport) -> str:
    infra = report.infra
    cdn_orgs = [
        info.org or info.isp for info in report.ip_info if info.is_cdn and (info.org or info.isp)
    ]
    parts: list[str] = []
    edge = summarize_edge(infra, [org for org in cdn_orgs if org], sep=f" {_glyphs().arrow} ")
    if edge:
        parts.append("behind " + edge)
    if infra.server:
        parts.append("server: " + ", ".join(infra.server))
    return " | ".join(parts) if parts else "-"


def _exposure_summary(report: ScanReport) -> str:
    if report.exposure is None:
        return "-"
    flags: list[str] = []
    if report.exposure.git_exposed:
        flags.append("[red].git[/red]")
    if report.exposure.robots_txt:
        flags.append("robots")
    if report.exposure.sitemap:
        flags.append("sitemap")
    if report.exposure.security_txt:
        flags.append("security.txt")
    return ", ".join(flags) if flags else "-"


def _render_table(reports: list[ScanReport], show_empty: bool) -> None:
    console = Console()
    table = Table(title="Stackscan Report")
    table.add_column("Target", style="cyan", overflow="fold")
    table.add_column("IPs", overflow="fold")
    table.add_column("Status", justify="right")
    table.add_column("Infrastructure")
    table.add_column("Technologies")
    table.add_column("Exposure")
    table.add_column("Error", style="red")
    for report in reports:
        has_findings = bool(report.technologies) or bool(report.infra.server or report.infra.cdn)
        if not show_empty and (not has_findings) and (not report.error):
            continue
        ips: list[str] = []
        if report.network is not None:
            ips.extend(report.network.ipv4)
            ips.extend(report.network.ipv6)
        table.add_row(
            report.final_url or report.url,
            ", ".join(ips) if ips else "-",
            str(report.status) if report.status is not None else "-",
            _infra_summary(report),
            _format_detected(report.by_category()),
            _exposure_summary(report),
            report.error or "",
        )
    console.print(table)


def _payload(
    reports: list[ScanReport], elapsed: float, include_graph: bool = False
) -> dict[str, object]:
    payload: dict[str, object] = {
        "scanner": "stackscan",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "elapsed_seconds": round(elapsed, 3),
        "results": [report.to_dict() for report in reports],
    }
    if include_graph:
        from typing import cast

        from stackscan.export import build_graph

        payload["graph"] = build_graph(cast("list[dict[str, Any]]", payload["results"]))
    return payload


def _render_json(reports: list[ScanReport], elapsed: float, include_graph: bool = False) -> None:
    json.dump(_payload(reports, elapsed, include_graph), sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


_EXPORTERS: dict[str, tuple[str, str]] = {
    "json-f": ("json", "to_json"),
    "xml": ("xml", "to_xml"),
    "html": ("html", "to_html"),
}


def _write_exports(
    reports: list[ScanReport],
    elapsed: float,
    spec: str,
    output: str,
    console: Console,
    include_graph: bool = False,
) -> None:
    from stackscan import export

    requested: list[str] = []
    for token in spec.replace(" ", ",").split(","):
        fmt = token.strip().lower()
        if not fmt:
            continue
        if fmt not in _EXPORTERS:
            _warn(console, f"unknown --export format: {fmt} (known: json-f, json-t, xml, html)")
            continue
        requested.append(fmt)
    for fmt in dict.fromkeys(requested):
        ext, func = _EXPORTERS[fmt]
        payload = _payload(reports, elapsed, include_graph=(include_graph and fmt == "json-f"))
        text: str = getattr(export, func)(payload)
        out = Path(f"{output}.{ext}")
        out.write_text(text, encoding="utf-8")
        console.print(f"[{theme.SUCCESS}][+][/] wrote {out}", highlight=False)


def _scan_summary(reports: list[ScanReport], elapsed: float) -> str:
    targets = len(reports)
    cves = sum(len(report.cves) for report in reports)
    critical = sum(
        1
        for report in reports
        for cve in report.cves
        if cve.severity.upper() == "CRITICAL" and not cve.unconfirmed
    )
    unconfirmed = sum(1 for report in reports for cve in report.cves if cve.unconfirmed)
    exposed = sum(
        1
        for report in reports
        for finding in report.creds
        if finding.kind in ("default-creds", "open-no-auth")
    )
    ports = sum(len(report.ports.ports) for report in reports if report.ports is not None)
    subdomains = sum(len(report.subdomains) for report in reports)
    sites = sum(len(report.site_findings) for report in reports)
    parts = [f"[bold]{targets}[/bold] target(s)", f"[bold]{cves}[/bold] CVE(s)"]
    if critical:
        parts.append(f"[bold {theme.DANGER}]{critical} critical[/]")
    if unconfirmed:
        parts.append(f"[bold]{unconfirmed}[/bold] unconfirmed")
    if ports:
        parts.append(f"[bold]{ports}[/bold] open port(s)")
    if subdomains:
        parts.append(f"[bold]{subdomains}[/bold] subdomain(s)")
    if sites:
        parts.append(f"[bold]{sites}[/bold] site(s)")
    if exposed:
        parts.append(f"[bold {theme.DANGER}]{exposed} exposed device(s)[/]")
    parts.append(f"{_glyphs().done} done in [{theme.ACCENT}]{_fmt_elapsed(elapsed)}[/]")
    return f"  {_glyphs().bullet}  ".join(parts)


def _warn(console: Console, message: str) -> None:
    console.print(f"[{theme.WARN}]{_glyphs().warn}[/] {message}", highlight=False)


def _error(console: Console, message: str) -> None:
    console.print(f"[{theme.DANGER}]{_glyphs().err}[/] {message}", highlight=False)


def _set_title(title: str) -> None:
    try:
        if sys.stderr.isatty():
            sys.stderr.write(f"\x1b]0;{title}\x07")
            sys.stderr.flush()
    except Exception:
        pass


def _bell() -> None:
    try:
        if sys.stderr.isatty():
            sys.stderr.write("\a")
            sys.stderr.flush()
    except Exception:
        pass


def _increase_nofile_limit() -> None:
    try:
        import resource

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(hard, 8192) if hard != resource.RLIM_INFINITY else 8192
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
    except Exception:
        pass


def _brute_subject(cameras: int, devices: int) -> str:
    parts: list[str] = []
    if cameras:
        parts.append(f"{cameras} open camera" + ("s" if cameras != 1 else ""))
    if devices:
        parts.append(f"{devices} device" + ("s" if devices != 1 else ""))
    return " and ".join(parts) if parts else "device(s)"


def _prompt_brute(cameras: int, devices: int, console: Console) -> bool:
    console.print(
        f"[{theme.WARN}][?][/] Parser found {_brute_subject(cameras, devices)}."
        " Try to brute? Y(Yes)/N(No)",
        highlight=False,
    )
    while True:
        try:
            answer = input("> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return False
        if answer in ("y", "yes"):
            return True
        if answer in ("n", "no", ""):
            return False
        console.print(f"[{theme.MUTED}]please answer y/yes or n/no[/]", highlight=False)


async def _brute_pairs(
    pairs: list[tuple[ScanReport, BruteTarget]], args: argparse.Namespace
) -> list[tuple[ScanReport, list[CredFinding]]]:
    semaphore = asyncio.Semaphore(max(args.concurrency, 1))

    async def one(report: ScanReport, target: BruteTarget) -> tuple[ScanReport, list[CredFinding]]:
        async with semaphore:
            findings = await brute_devices(
                [target],
                timeout=min(args.timeout, 8.0),
                workers=max(args.workers // 10, 4),
                cred_limit=max(args.cred_limit, 0),
            )
        return (report, findings)

    return list(await asyncio.gather(*(one(report, target) for report, target in pairs)))


def _sort_creds(pairs: list[tuple[ScanReport, BruteTarget]]) -> None:
    for report in {id(report): report for report, _ in pairs}.values():
        report.creds.sort(
            key=lambda f: (f.kind != "default-creds", f.kind != "open-no-auth", f.target)
        )


def _run_brute_phase(
    reports: list[ScanReport], args: argparse.Namespace, console: Console, *, json_terminal: bool
) -> None:
    pairs = [(report, target) for report in reports for target in report.brute_targets]
    if not pairs:
        return
    cameras = sum(1 for _, target in pairs if target.is_camera)
    devices = len(pairs) - cameras
    if args.full_auto:
        accept = True
    elif json_terminal:
        accept = False
    else:
        accept = _prompt_brute(cameras, devices, console)
    if not accept:
        for report, target in pairs:
            report.creds.append(
                CredFinding(
                    target=target.target,
                    service=target.service,
                    kind="auth-required",
                    detail="brute-force skipped",
                )
            )
        _sort_creds(pairs)
        return
    for report, findings in asyncio.run(_brute_pairs(pairs, args)):
        report.creds.extend(findings)
    _sort_creds(pairs)


def _scan_command(argv: list[str]) -> int:
    _increase_nofile_limit()
    verbose_level, argv = _extract_verbose(argv)
    parser = _build_scan_parser()
    args = parser.parse_args(argv)
    args.verbose = verbose_level
    err_console = Console(stderr=True)
    _apply_disable(args, err_console)
    if not getattr(args, "no_banner", False):
        render_banner(err_console)
    if (
        (args.ports or args.full)
        and (not getattr(args, "no_nmap", False))
        and (not nmap_available())
    ):
        _warn(err_console, "nmap not found — using the built-in Python connect scan.")
    if args.default_creds or args.full or args.full_auto:
        _warn(
            err_console,
            "default-credential checks enabled — only scan systems you are authorized to test.",
        )
    started = time.perf_counter()
    try:
        reports = asyncio.run(_run_scans(args))
    except FileNotFoundError as exc:
        _error(err_console, str(exc))
        return 2
    except NoSignaturesError as exc:
        _error(err_console, str(exc))
        return 2
    except Exception as exc:
        _error(err_console, f"Failed to scan: {exc}")
        return 1
    if not reports:
        _warn(err_console, "No targets provided.")
        return 2

    def _export_formats() -> list[str]:
        formats: list[str] = []
        for token in args.export.replace(" ", ",").split(","):
            fmt = token.strip().lower()
            if fmt and fmt not in formats:
                formats.append(fmt)
        return formats

    json_terminal = "json-t" in _export_formats()
    _run_brute_phase(reports, args, err_console, json_terminal=json_terminal)
    elapsed = time.perf_counter() - started
    file_formats = [fmt for fmt in _export_formats() if fmt != "json-t"]
    if file_formats:
        _write_exports(
            reports,
            elapsed,
            ",".join(file_formats),
            args.output,
            err_console,
            include_graph=args.graph,
        )
    if json_terminal:
        _render_json(reports, elapsed, include_graph=args.graph)
    elif args.compact:
        _render_table(reports, args.show_empty)
        err_console.print(_scan_summary(reports, elapsed))
    else:
        render_reports(reports, Console(), show_empty=args.show_empty)
        err_console.print(_scan_summary(reports, elapsed))
    _set_title(f"stackscan · done ({len(reports)} target(s) in {_fmt_elapsed(elapsed)})")
    if not args.no_bell:
        _bell()
    return 0


def _sigdb_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="stackscan sigdb",
        description="Manage signature sources.",
        add_help=False,
    )
    parser.add_argument(
        "-h", "--help", action=_HelpAction, nargs=0, help="Show this help message and exit."
    )
    sub = parser.add_subparsers(dest="action", required=True)
    add_p = sub.add_parser("add", help="Add a signature source (http URL or git repo).")
    add_p.add_argument("url", help="Source URL: .sigdb, rules JSON, or a git repository.")
    sub.add_parser("list", help="List configured sources.")
    remove_p = sub.add_parser("remove", help="Remove a source by id or url.")
    remove_p.add_argument("key", help="Source id or url.")
    update_p = sub.add_parser("update", help="Re-fetch and recompile a source (or all).")
    update_p.add_argument("key", nargs="?", help="Source id or url; omit to update all.")
    args = parser.parse_args(argv)
    store = SourceStore()
    console = Console()
    try:
        if args.action == "add":
            source = store.add(args.url)
            console.print(
                f"[green]Added[/green] {args.url} ([cyan]{source.kind}[/cyan], id={source.id}) -> {source.path}"
            )
            return 0
        if args.action == "list":
            sources = store.list()
            if not sources:
                console.print("[yellow]No sources configured.[/yellow]")
                return 0
            table = Table(title="Signature Sources")
            table.add_column("ID", style="cyan")
            table.add_column("Kind")
            table.add_column("URL", overflow="fold")
            table.add_column("Added")
            for source in sources:
                added = datetime.fromtimestamp(source.added, UTC).strftime("%Y-%m-%d")
                table.add_row(source.id, source.kind, source.url, added)
            console.print(table)
            return 0
        if args.action == "remove":
            removed = store.remove(args.key)
            if removed:
                console.print(f"[green]Removed[/green] {args.key}")
                return 0
            console.print(f"[yellow]No source matched[/yellow] {args.key}")
            return 1
        if args.action == "update":
            refreshed = store.update(args.key)
            if not refreshed:
                console.print("[yellow]Nothing to update.[/yellow]")
                return 1
            for source in refreshed:
                console.print(f"[green]Updated[/green] {source.url} (id={source.id})")
            return 0
    except SourceError as exc:
        Console(stderr=True).print(f"[red]{exc}[/red]")
        return 1
    return 2


def main(argv: Iterable[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    try:
        if args and args[0] == "sigdb":
            return _sigdb_command(args[1:])
        if args and args[0] == "scan":
            args = args[1:]
        return _scan_command(args)
    except KeyboardInterrupt:
        Console(stderr=True).print(f"[{theme.WARN}][!][/] interrupted", highlight=False)
        return 130
