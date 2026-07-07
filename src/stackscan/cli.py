"""Stackscan CLI - full web stack analysis backed by sigdb."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table

from stackscan import __version__
from stackscan.analyzers import TechAnalyzer
from stackscan.config import (
    NoSignaturesError,
    SourceError,
    SourceStore,
    build_matchers,
)
from stackscan.net import GeoProvider
from stackscan.scan import ScanOptions, scan_target
from stackscan.types import DetectedTech, ScanReport
from stackscan.utils import normalize_url

DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_CONCURRENCY = 10
DEFAULT_USER_AGENT = "stackscan/2.0 (+https://github.com/reekeer/stackscan)"


# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #
def _build_scan_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stackscan",
        description="Full web stack analyzer (technologies, edge infra, network, exposure).",
    )
    parser.add_argument("targets", nargs="*", help="Target URLs or hostnames.")
    parser.add_argument("-f", "--file", dest="file", type=Path, help="File with targets, one/line.")
    parser.add_argument("--sigdb", dest="sigdb", help="Explicit .sigdb path (overrides default).")
    parser.add_argument("--no-sources", action="store_true", help="Ignore configured sources.")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout.")
    parser.add_argument("--user-agent", dest="user_agent", default=DEFAULT_USER_AGENT)
    parser.add_argument("--insecure", action="store_true", help="Disable TLS verification.")
    parser.add_argument("--max-bytes", dest="max_bytes", type=int, default=DEFAULT_MAX_BYTES)
    parser.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    parser.add_argument("--geoip-db", dest="geoip_db", help="MaxMind .mmdb for IP geolocation.")
    parser.add_argument("--no-dns", action="store_true", help="Skip DNS/IP resolution.")
    parser.add_argument("--no-tls", action="store_true", help="Skip TLS certificate inspection.")
    parser.add_argument("--no-geo", action="store_true", help="Skip IP geolocation.")
    parser.add_argument("--no-probe", action="store_true", help="Skip passive exposure probes.")
    parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output.")
    parser.add_argument("--show-empty", action="store_true", help="Show targets with no findings.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


# --------------------------------------------------------------------------- #
# Target reading helpers (kept stable for reuse and tests)
# --------------------------------------------------------------------------- #
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


# --------------------------------------------------------------------------- #
# Scan command
# --------------------------------------------------------------------------- #
async def _run_scans(args: argparse.Namespace) -> list[ScanReport]:
    from stackscan.core import StackscanSession

    raw_targets = _read_targets(args.file, args.targets)
    if not raw_targets:
        return []

    targets = _dedupe([normalize_url(target) for target in raw_targets])
    matchers = build_matchers(args.sigdb, use_sources=not args.no_sources)
    analyzer = TechAnalyzer(matchers)
    geo = GeoProvider(args.geoip_db)

    options = ScanOptions(
        timeout=args.timeout,
        user_agent=args.user_agent,
        insecure=args.insecure,
        max_bytes=args.max_bytes,
        dns=not args.no_dns,
        tls=not args.no_tls,
        geo=not args.no_geo,
        probe=not args.no_probe,
    )
    semaphore = asyncio.Semaphore(max(args.concurrency, 1))

    async with StackscanSession() as session:
        tasks = [
            scan_target(
                target,
                matchers_analyzer=analyzer,
                session=session,
                options=options,
                geo=geo,
                semaphore=semaphore,
            )
            for target in targets
        ]
        return list(await asyncio.gather(*tasks))


def _infra_summary(report: ScanReport) -> str:
    infra = report.infra
    parts: list[str] = []
    if infra.cdn:
        parts.append("cdn: " + ", ".join(infra.cdn))
    if infra.waf:
        parts.append("waf: " + ", ".join(infra.waf))
    if infra.server:
        parts.append("server: " + ", ".join(infra.server))
    if infra.proxy:
        parts.append("proxy: " + ", ".join(infra.proxy))
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
    table.add_column("Status", justify="right")
    table.add_column("Infrastructure")
    table.add_column("Technologies")
    table.add_column("Exposure")
    table.add_column("Error", style="red")

    for report in reports:
        has_findings = bool(report.technologies) or bool(report.infra.server or report.infra.cdn)
        if not show_empty and not has_findings and not report.error:
            continue
        table.add_row(
            report.final_url or report.url,
            str(report.status) if report.status is not None else "-",
            _infra_summary(report),
            _format_detected(report.by_category()),
            _exposure_summary(report),
            report.error or "",
        )
    console.print(table)


def _render_json(reports: list[ScanReport]) -> None:
    payload = {
        "scanner": "stackscan",
        "version": __version__,
        "generated_at": datetime.now(UTC).isoformat(),
        "results": [report.to_dict() for report in reports],
    }
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def _scan_command(argv: list[str]) -> int:
    parser = _build_scan_parser()
    args = parser.parse_args(argv)

    try:
        reports = asyncio.run(_run_scans(args))
    except FileNotFoundError as exc:
        Console(stderr=True).print(f"[red]{exc}[/red]")
        return 2
    except NoSignaturesError as exc:
        Console(stderr=True).print(f"[red]{exc}[/red]")
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI fallback
        Console(stderr=True).print(f"[red]Failed to scan: {exc}[/red]")
        return 1

    if not reports:
        Console(stderr=True).print("[yellow]No targets provided.[/yellow]")
        return 2

    if args.json_output:
        _render_json(reports)
    else:
        _render_table(reports, args.show_empty)
    return 0


# --------------------------------------------------------------------------- #
# sigdb source-management command
# --------------------------------------------------------------------------- #
def _sigdb_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="stackscan sigdb", description="Manage signature sources."
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
                f"[green]Added[/green] {args.url} "
                f"([cyan]{source.kind}[/cyan], id={source.id}) -> {source.path}"
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


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def main(argv: Iterable[str] | None = None) -> int:
    args = list(argv) if argv is not None else sys.argv[1:]
    if args and args[0] == "sigdb":
        return _sigdb_command(args[1:])
    if args and args[0] == "scan":
        args = args[1:]
    return _scan_command(args)
