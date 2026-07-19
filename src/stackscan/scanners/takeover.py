from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from typing import Any, cast

from stackscan.types import FetchResult, Subdomain, TakeoverFinding
from stackscan.utils import host_of


@dataclass(frozen=True)
class _TakeoverTarget:
    service: str
    suffixes: tuple[str, ...]
    not_found_markers: tuple[str, ...] = ()
    severity: str = "MEDIUM"


_TAKEOVER_TARGETS: tuple[_TakeoverTarget, ...] = (
    _TakeoverTarget(
        service="GitHub Pages",
        suffixes=("github.io", "github.com"),
        not_found_markers=("there isn't a github pages site here",),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="Heroku",
        suffixes=("herokuapp.com", "herokussl.com"),
        not_found_markers=("no such app",),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="AWS S3",
        suffixes=("s3.amazonaws.com", "s3-website", "s3.dualstack"),
        not_found_markers=("no such bucket", "the specified bucket does not exist"),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="AWS Elastic Beanstalk",
        suffixes=("elasticbeanstalk.com",),
        severity="MEDIUM",
    ),
    _TakeoverTarget(
        service="Bitbucket",
        suffixes=("bitbucket.io", "bitbucket.org"),
        not_found_markers=("repository not found",),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="Shopify",
        suffixes=("myshopify.com",),
        not_found_markers=("only one step left", "sorry, this shop is currently unavailable"),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="Tumblr",
        suffixes=("tumblr.com",),
        not_found_markers=("not found",),
        severity="MEDIUM",
    ),
    _TakeoverTarget(
        service="WordPress.com",
        suffixes=("wordpress.com",),
        severity="MEDIUM",
    ),
    _TakeoverTarget(
        service="Fastly",
        suffixes=("fastly.net", "fastly.io"),
        severity="MEDIUM",
    ),
    _TakeoverTarget(
        service="Azure",
        suffixes=("azurewebsites.net", "cloudapp.azure.com", "blob.core.windows.net"),
        not_found_markers=("404 web site not found",),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="Google App Engine",
        suffixes=("appspot.com",),
        not_found_markers=("not found",),
        severity="MEDIUM",
    ),
    _TakeoverTarget(
        service="Surge.sh",
        suffixes=("surge.sh",),
        not_found_markers=("project not found",),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="Netlify",
        suffixes=("netlify.app", "netlify.com"),
        not_found_markers=("not found",),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="Vercel",
        suffixes=("vercel.app", "now.sh"),
        not_found_markers=("the deployment could not be found",),
        severity="HIGH",
    ),
    _TakeoverTarget(
        service="Pantheon",
        suffixes=("pantheonsite.io", "pantheon.io"),
        severity="MEDIUM",
    ),
    _TakeoverTarget(
        service="Fly.io",
        suffixes=("fly.dev",),
        severity="MEDIUM",
    ),
)


_CNAME_RE = re.compile(r"([a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.[a-z0-9.-]+[a-z0-9])", re.IGNORECASE)


def _service_for_cname(cname: str) -> _TakeoverTarget | None:
    lowered = cname.lower().rstrip(".")
    for target in _TAKEOVER_TARGETS:
        for suffix in target.suffixes:
            if suffix in lowered:
                return target
    return None


async def _fetch_url(
    name: str, session: Any, timeout: float, user_agent: str
) -> FetchResult | None:
    from stackscan.core import StackscanSession

    s = cast(StackscanSession, session)
    for scheme in ("https", "http"):
        try:
            return await s.fetch(
                f"{scheme}://{name}/",
                timeout=timeout,
                user_agent=user_agent,
                insecure=True,
                max_bytes=200_000,
            )
        except Exception:
            continue
    return None


async def _resolve_cname(name: str, timeout: float = 3.0) -> str | None:
    try:
        from dns import resolver as _resolver
    except ImportError:
        return None
    resolver = cast(Any, _resolver)
    try:
        answer = await asyncio.wait_for(
            asyncio.to_thread(resolver.resolve, name, "CNAME"),
            timeout=timeout,
        )
        return str(answer[0]).rstrip(".").lower()
    except Exception:
        return None


async def _verify_takeover(
    subdomain: str, target: _TakeoverTarget, session: Any, timeout: float, user_agent: str
) -> tuple[bool, str]:
    result = await _fetch_url(subdomain, session, timeout, user_agent)
    if result is None:
        return (False, "")
    body = result.body.lower()
    for marker in target.not_found_markers:
        if marker in body:
            return (True, f"HTTP {result.status} · {marker}")
    # If the request ended on the target service host and returned 404,
    # the dangling CNAME is likely unclaimed.
    final_host = (host_of(result.url) or "").lower()
    if result.status in (404, 406) and any(
        final_host.endswith("." + suffix) or final_host == suffix for suffix in target.suffixes
    ):
        return (True, f"HTTP {result.status} on {target.service}")
    return (False, "")


async def detect_takeovers(
    subdomains: list[Subdomain],
    session: Any,
    *,
    timeout: float = 6.0,
    user_agent: str = "stackscan",
    workers: int = 20,
) -> list[TakeoverFinding]:
    """Find dangling CNAMEs that point to third-party services."""
    if not subdomains:
        return []
    semaphore = asyncio.Semaphore(max(workers, 1))

    async def check(sub: Subdomain) -> TakeoverFinding | None:
        async with semaphore:
            cname = await _resolve_cname(sub.name, timeout=min(timeout, 3.0))
        if not cname:
            return None
        target = _service_for_cname(cname)
        if target is None:
            return None
        verified, evidence = await _verify_takeover(sub.name, target, session, timeout, user_agent)
        return TakeoverFinding(
            subdomain=sub.name,
            service=target.service,
            cname=cname,
            severity=target.severity if verified else "LOW",
            verified=verified,
            evidence=evidence or f"CNAME → {cname}",
        )

    results = await asyncio.gather(*(check(sub) for sub in subdomains))
    return [r for r in results if r is not None]
