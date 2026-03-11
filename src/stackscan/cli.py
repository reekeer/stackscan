"""Stackscan CLI - lightweight Wappalyzer-like tech detection."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import cast

from rich.console import Console
from rich.table import Table

from stackscan import __version__
from stackscan.config import load_framework_rules
from stackscan.core import StackscanSession, detect_tech
from stackscan.types import DetectedTech, RulesByCategory, ScanTargetResult
from stackscan.utils import normalize_url

DEFAULT_TIMEOUT = 12.0
DEFAULT_MAX_BYTES = 1_000_000
DEFAULT_CONCURRENCY = 10
DEFAULT_USER_AGENT = "stackscan/1.0 (+https://example.invalid)"


def _parse_args(argv: Iterable[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="stackscan",
        description="Lightweight Wappalyzer-like stack detector.",
    )
    parser.add_argument("targets", nargs="*", help="Target URLs or hostnames.")
    parser.add_argument(
        "-f",
        "--file",
        dest="file",
        type=Path,
        help="Path to a file with targets (one per line).",
    )
    parser.add_argument(
        "--frameworks",
        dest="frameworks",
        help="Frameworks JSON source (file path or URL). Default: bundled frameworks.json",
    )
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Request timeout.")
    parser.add_argument(
        "--user-agent",
        dest="user_agent",
        default=DEFAULT_USER_AGENT,
        help="Custom User-Agent header.",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification.",
    )
    parser.add_argument(
        "--max-bytes",
        dest="max_bytes",
        type=int,
        default=DEFAULT_MAX_BYTES,
        help="Maximum response body size to read.",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=DEFAULT_CONCURRENCY,
        help="Number of concurrent requests.",
    )
    parser.add_argument("--json", dest="json_output", action="store_true", help="JSON output.")
    parser.add_argument(
        "--show-empty",
        action="store_true",
        help="Include targets with no detections in table output.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    return parser.parse_args(list(argv) if argv is not None else None)


def _read_targets(path: Path | None, positional: Iterable[str]) -> list[str]:
    targets = [item.strip() for item in positional if item.strip()]
    if path is None:
        return targets
    if not path.is_file():
        raise FileNotFoundError(f"Targets file not found: {path}")
    raw = path.read_text(encoding="utf-8")
    for line in raw.splitlines():
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


async def _scan_target(
    url: str,
    *,
    rules: RulesByCategory,
    session: StackscanSession,
    timeout: float,
    user_agent: str,
    insecure: bool,
    max_bytes: int,
    semaphore: asyncio.Semaphore,
) -> ScanTargetResult:
    async with semaphore:
        try:
            result = await session.fetch(
                url,
                timeout=timeout,
                user_agent=user_agent,
                insecure=insecure,
                max_bytes=max_bytes,
            )
        except Exception as exc:  # noqa: BLE001 - CLI should be resilient
            return ScanTargetResult(url=url, status=None, detected={}, error=str(exc))

    detected = detect_tech(result, rules)
    return ScanTargetResult(url=result.url, status=result.status, detected=detected, error=None)


async def _run_scans(args: argparse.Namespace) -> list[ScanTargetResult]:
    raw_targets = _read_targets(args.file, args.targets)
    if not raw_targets:
        return []

    targets = _dedupe([normalize_url(target) for target in raw_targets])
    rules = await load_framework_rules(args.frameworks)

    connector_limit = max(args.concurrency, 1)
    semaphore = asyncio.Semaphore(connector_limit)

    async with StackscanSession() as session:
        session = cast(StackscanSession, session)
        tasks = [
            _scan_target(
                target,
                rules=rules,
                session=session,
                timeout=args.timeout,
                user_agent=args.user_agent,
                insecure=args.insecure,
                max_bytes=args.max_bytes,
                semaphore=semaphore,
            )
            for target in targets
        ]
        return list(await asyncio.gather(*tasks))


def _format_detected(detected: DetectedTech) -> str:
    if not detected:
        return "-"
    chunks: list[str] = []
    for category in sorted(detected):
        techs = ", ".join(detected[category])
        chunks.append(f"{category}: {techs}")
    return " | ".join(chunks)


def _render_table(results: list[ScanTargetResult], show_empty: bool) -> None:
    console = Console()
    table = Table(title="Stackscan Results")
    table.add_column("URL", style="cyan")
    table.add_column("Status", justify="right")
    table.add_column("Detected")
    table.add_column("Error", style="red")

    for item in results:
        has_detections = bool(item.detected)
        if not show_empty and not has_detections and not item.error:
            continue
        table.add_row(
            item.url,
            str(item.status) if item.status is not None else "-",
            _format_detected(item.detected),
            item.error or "",
        )

    console.print(table)


def _render_json(results: list[ScanTargetResult]) -> None:
    payload = [
        {
            "url": item.url,
            "status": item.status,
            "detected": item.detected,
            "error": item.error,
        }
        for item in results
    ]
    json.dump(payload, sys.stdout, ensure_ascii=False, indent=2)
    sys.stdout.write("\n")


def main(argv: Iterable[str] | None = None) -> int:
    args = _parse_args(argv)

    try:
        results = asyncio.run(_run_scans(args))
    except FileNotFoundError as exc:
        Console(stderr=True).print(f"[red]{exc}[/red]")
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI fallback
        Console(stderr=True).print(f"[red]Failed to scan: {exc}[/red]")
        return 1

    if not results:
        Console(stderr=True).print("[yellow]No targets provided.[/yellow]")
        return 2

    if args.json_output:
        _render_json(results)
    else:
        _render_table(results, args.show_empty)

    return 0
