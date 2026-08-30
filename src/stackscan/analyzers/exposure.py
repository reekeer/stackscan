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


def _looks_like_robots(body: str) -> bool:
    lowered = body.lower()
    return any(
        directive in lowered
        for directive in ("user-agent:", "disallow:", "allow:", "sitemap:", "crawl-delay:")
    )


def _looks_like_sitemap(body: str) -> bool:
    lowered = body.lstrip().lower()
    return lowered.startswith("<?xml") or "<urlset" in lowered or "<sitemapindex" in lowered


def _looks_like_security_txt(body: str) -> bool:
    lowered = body.lower()
    return any(
        field in lowered for field in ("contact:", "expires:", "encryption:", "acknowledgments:")
    )


async def _get(session: StackscanSession, url: str, probe: ExposureProbe) -> tuple[int | None, str]:
    try:
        result = await session.fetch(
            url,
            timeout=probe.timeout,
            user_agent=probe.user_agent,
            insecure=probe.insecure,
            max_bytes=_PROBE_MAX_BYTES,
        )
    except Exception:
        return (None, "")
    return (result.status, result.body)


async def analyze_exposure(
    session: StackscanSession, base_url: str, probe: ExposureProbe
) -> ExposureInfo:
    findings: list[str] = []
    urls: dict[str, str] = {}

    robots_url = urljoin(base_url, "/robots.txt")
    robots_status, robots_body = await _get(session, robots_url, probe)
    robots = robots_status == 200 and _looks_like_robots(robots_body)
    if robots:
        urls["robots.txt"] = robots_url

    sitemap_url = urljoin(base_url, "/sitemap.xml")
    sitemap_status, sitemap_body = await _get(session, sitemap_url, probe)
    sitemap = sitemap_status == 200 and _looks_like_sitemap(sitemap_body)
    if sitemap:
        urls["sitemap.xml"] = sitemap_url

    sec_url = urljoin(base_url, "/.well-known/security.txt")
    sec_status, sec_body = await _get(session, sec_url, probe)
    security_txt = sec_status == 200 and _looks_like_security_txt(sec_body)
    if security_txt:
        urls["security.txt"] = sec_url

    git_url = urljoin(base_url, "/.git/HEAD")
    git_status, git_body = await _get(session, git_url, probe)
    git_exposed = git_status == 200 and git_body.strip().startswith("ref:")
    if git_exposed:
        urls[".git/HEAD"] = git_url
        findings.append("Exposed .git/HEAD (source repository may be publicly readable)")

    return ExposureInfo(
        robots_txt=robots,
        sitemap=sitemap,
        security_txt=security_txt,
        git_exposed=git_exposed,
        findings=tuple(findings),
        urls=urls,
    )
