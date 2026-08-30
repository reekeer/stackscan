"""Runner mode: connect to a StackScan panel and scan jobs off its queue.

Enabled with ``stackscan --runner`` or ``STACKSCAN_RUNNER=1``. The runner claims
jobs from the panel over HTTP (``POST /api/jobs/claim``), fingerprints each target
with the normal stackscan engine, and reports results back (``POST /api/results``).
It needs only network access to the panel — no database or Redis.

Configuration (all via environment, overridable by CLI flags):

    STACKSCAN_BACKEND_URL   panel base URL           (default http://localhost:8787)
    STACKSCAN_WORKER_TOKEN  shared worker token      (required for a real panel)
    STACKSCAN_RUNNER_ID     stable id for this runner (default runner-<host>-<pid>)
    STACKSCAN_RUNNER_BATCH  jobs claimed per cycle    (default 5)
    STACKSCAN_RUNNER_IDLE   seconds to wait when idle (default 5)
    STACKSCAN_SIGDB         explicit .sigdb path      (optional)
"""

from __future__ import annotations

import argparse
import asyncio
import os
import socket
import time
from typing import Any

from aiohttp import ClientSession, ClientTimeout

from stackscan import __version__
from stackscan.analyzers import TechAnalyzer
from stackscan.config import build_matchers
from stackscan.core import StackscanSession
from stackscan.net import GeoProvider
from stackscan.scan import ScanOptions, exc_text, scan_target
from stackscan.types import ScanReport, Technology

DEFAULT_BACKEND_URL = "http://localhost:8787"
DEFAULT_BATCH = 5
DEFAULT_IDLE_SECONDS = 5.0
DEFAULT_USER_AGENT = f"stackscanRunner/{__version__} (+https://github.com/reekeer/stackscan)"


def _slugify(name: str) -> str:
    return "".join(ch if ch.isalnum() else "-" for ch in name.lower()).strip("-")


class RunnerConfig:
    def __init__(self, args: argparse.Namespace) -> None:
        self.backend_url = (
            args.backend or os.environ.get("STACKSCAN_BACKEND_URL") or DEFAULT_BACKEND_URL
        ).rstrip("/")
        self.worker_token = args.worker_token or os.environ.get("STACKSCAN_WORKER_TOKEN") or ""
        self.runner_id = (
            args.runner_id
            or os.environ.get("STACKSCAN_RUNNER_ID")
            or f"runner-{socket.gethostname()}-{os.getpid()}"
        )
        self.batch = args.batch or int(os.environ.get("STACKSCAN_RUNNER_BATCH") or DEFAULT_BATCH)
        self.idle_seconds = float(os.environ.get("STACKSCAN_RUNNER_IDLE") or DEFAULT_IDLE_SECONDS)
        self.sigdb = args.sigdb or os.environ.get("STACKSCAN_SIGDB")
        self.user_agent = args.user_agent or DEFAULT_USER_AGENT
        self.once = args.once


def _scan_options(cfg: RunnerConfig) -> ScanOptions:
    """A lean profile suited to unattended, high-volume panel scanning."""
    return ScanOptions(
        timeout=12.0,
        user_agent=cfg.user_agent,
        insecure=False,
        max_bytes=1_000_000,
        dns=True,
        tls=True,
        geo=True,
        probe=False,
        cve=False,
        cve_online=False,
        parse_social=False,
        whois=False,
        ports=False,
        subdomains=False,
        ip_info=True,
        default_creds=False,
        concurrency=max(cfg.batch, 1),
    )


def _first(values: Any) -> str | None:
    for value in values or ():
        if value:
            return str(value)
    return None


def _parse_asn(raw: str | None) -> tuple[int | None, str | None]:
    """Split an "AS13335 Cloudflare" style string into (number, org)."""
    if not raw:
        return None, None
    token, _, rest = raw.strip().partition(" ")
    digits = token[2:] if token[:2].upper() == "AS" else token
    number = int(digits) if digits.isdigit() else None
    return number, (rest.strip() or None)


def _tech_dict(tech: Technology) -> dict[str, Any]:
    category = tech.categories[0] if tech.categories else "unknown"
    slug = _slugify(tech.name)
    return {
        "id": slug,
        "name": tech.name,
        "slug": slug,
        "category": category,
        "version": tech.version,
        "confidence": tech.confidence,
    }


def report_to_result(report: ScanReport, job_id: str, worker_id: str) -> dict[str, Any]:
    """Map a stackscan report to the panel's /api/results payload."""
    net = report.network
    ips: list[str] = []
    if net is not None:
        ips = [*net.ipv4, *net.ipv6]
    if not ips and report.real_ips:
        ips = sorted(report.real_ips)

    ip = report.ip_info[0] if report.ip_info else None
    asn_number, asn_org = _parse_asn(ip.asn if ip else None)
    provider = (ip.org or ip.isp) if ip else None

    return {
        "job_id": str(job_id),
        "url": report.url,
        "final_url": report.final_url,
        "status": report.status,
        "ips": ips,
        "country": (ip.country if ip else None),
        "city": (ip.city if ip else None),
        "asn": asn_number,
        "asn_org": asn_org,
        "provider": provider,
        "hosting": (ip.isp if ip else None),
        "network_name": _first(report.infra.cdn) or provider,
        "technologies": [_tech_dict(tech) for tech in report.all_technologies()],
        "error": report.error,
        "worker_id": worker_id,
        "scanned_at": int(time.time()),
    }


class PanelClient:
    def __init__(self, cfg: RunnerConfig, http: ClientSession) -> None:
        self._cfg = cfg
        self._http = http

    @property
    def _headers(self) -> dict[str, str]:
        headers = {"User-Agent": self._cfg.user_agent}
        if self._cfg.worker_token:
            headers["X-Worker-Token"] = self._cfg.worker_token
        return headers

    async def claim(self) -> list[dict[str, str]]:
        async with self._http.post(
            f"{self._cfg.backend_url}/api/jobs/claim",
            json={"worker_id": self._cfg.runner_id, "max": self._cfg.batch},
            headers=self._headers,
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
        return list(payload.get("jobs", []))

    async def report(self, results: list[dict[str, Any]]) -> int:
        if not results:
            return 0
        async with self._http.post(
            f"{self._cfg.backend_url}/api/results",
            json=results,
            headers=self._headers,
        ) as resp:
            resp.raise_for_status()
            payload = await resp.json()
        return int(payload.get("accepted", 0))


async def _run(cfg: RunnerConfig) -> None:
    matchers = build_matchers(cfg.sigdb, use_sources=True, use_builtin=True)
    analyzer = TechAnalyzer(matchers)
    geo = GeoProvider()
    options = _scan_options(cfg)
    semaphore = asyncio.Semaphore(max(cfg.batch, 1))

    print(
        f"stackscan runner {cfg.runner_id} -> {cfg.backend_url} "
        f"(batch={cfg.batch}, {len(matchers)} matchers)",
        flush=True,
    )

    timeout = ClientTimeout(total=30)
    async with (
        ClientSession(timeout=timeout) as http,
        StackscanSession() as scan_session,
    ):
        client = PanelClient(cfg, http)
        while True:
            try:
                jobs = await client.claim()
            except Exception as exc:  # noqa: BLE001 - keep polling through panel hiccups.
                print(f"[!] claim failed: {exc}", flush=True)
                await asyncio.sleep(cfg.idle_seconds)
                if cfg.once:
                    return
                continue

            if not jobs:
                if cfg.once:
                    return
                await asyncio.sleep(cfg.idle_seconds)
                continue

            async def scan_one(job: dict[str, str]) -> dict[str, Any]:
                url = job["url"]
                job_id = job["id"]
                try:
                    report = await scan_target(
                        url,
                        matchers_analyzer=analyzer,
                        session=scan_session,
                        options=options,
                        geo=geo,
                        semaphore=semaphore,
                        log=None,
                    )
                except Exception as exc:  # noqa: BLE001 - one bad target must not stop the runner.
                    report = ScanReport(url=url, error=exc_text(exc))
                return report_to_result(report, job_id, cfg.runner_id)

            usable = [job for job in jobs if job.get("url") and job.get("id")]
            skipped = len(jobs) - len(usable)
            if skipped:
                print(f"[!] skipped {skipped} malformed job(s)", flush=True)
            if not usable:
                if cfg.once:
                    return
                await asyncio.sleep(cfg.idle_seconds)
                continue

            results = await asyncio.gather(*(scan_one(job) for job in usable))
            try:
                accepted = await client.report(list(results))
            except Exception as exc:  # noqa: BLE001
                print(f"[!] report failed: {exc}", flush=True)
            else:
                ok = sum(1 for r in results if not r["error"])
                print(
                    f"[+] scanned {len(results)} ({ok} ok), panel accepted {accepted}",
                    flush=True,
                )

            if cfg.once:
                return


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="stackscan --runner",
        description="Run stackscan as a panel worker (claim jobs, scan, report back).",
    )
    parser.add_argument("--runner", action="store_true", help="Run in panel worker mode.")
    parser.add_argument("--backend", help="Panel base URL (env STACKSCAN_BACKEND_URL).")
    parser.add_argument(
        "--worker-token", dest="worker_token", help="Worker token (env STACKSCAN_WORKER_TOKEN)."
    )
    parser.add_argument(
        "--runner-id", dest="runner_id", help="Stable runner id (env STACKSCAN_RUNNER_ID)."
    )
    parser.add_argument(
        "--batch", type=int, help="Jobs claimed per cycle (env STACKSCAN_RUNNER_BATCH)."
    )
    parser.add_argument("--sigdb", help="Explicit .sigdb path (env STACKSCAN_SIGDB).")
    parser.add_argument("--user-agent", dest="user_agent", help="Override the runner User-Agent.")
    parser.add_argument(
        "--once", action="store_true", help="Run a single claim/scan/report cycle and exit."
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    cfg = RunnerConfig(args)
    try:
        asyncio.run(_run(cfg))
    except KeyboardInterrupt:
        print("stackscan runner stopped", flush=True)
        return 130
    return 0
