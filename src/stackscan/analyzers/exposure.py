"""Passive exposure probes over publicly reachable well-known paths.

Every request here is a plain GET of a conventional, world-readable location
(``/robots.txt``, ``/sitemap.xml``, ``/.well-known/security.txt``) plus a
read-only check for an accidentally published ``/.git/HEAD``. Nothing attempts
authentication, injection, or protection bypass -- it only observes what the
server already serves to anyone.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING
from urllib.parse import urljoin

from stackscan.types import ExposureInfo

if TYPE_CHECKING:
    from stackscan.core import StackscanSession

_PROBE_MAX_BYTES = 8192


@dataclass(frozen=True)
class ExposureProbe:
    timeout: float
    user_agent: str
    insecure: bool


async def _get(
    session: StackscanSession,
    url: str,
    probe: ExposureProbe,
) -> tuple[int | None, str]:
    try:
        result = await session.fetch(
            url,
            timeout=probe.timeout,
            user_agent=probe.user_agent,
            insecure=probe.insecure,
            max_bytes=_PROBE_MAX_BYTES,
        )
    except Exception:
        return None, ""
    return result.status, result.body


async def analyze_exposure(
    session: StackscanSession,
    base_url: str,
    probe: ExposureProbe,
) -> ExposureInfo:
    findings: list[str] = []

    robots_status, _ = await _get(session, urljoin(base_url, "/robots.txt"), probe)
    robots = robots_status == 200

    sitemap_status, _ = await _get(session, urljoin(base_url, "/sitemap.xml"), probe)
    sitemap = sitemap_status == 200

    sec_status, _ = await _get(session, urljoin(base_url, "/.well-known/security.txt"), probe)
    security_txt = sec_status == 200

    git_status, git_body = await _get(session, urljoin(base_url, "/.git/HEAD"), probe)
    git_exposed = git_status == 200 and git_body.strip().startswith("ref:")
    if git_exposed:
        findings.append("Exposed .git/HEAD (source repository may be publicly readable)")

    return ExposureInfo(
        robots_txt=robots,
        sitemap=sitemap,
        security_txt=security_txt,
        git_exposed=git_exposed,
        findings=tuple(findings),
    )
