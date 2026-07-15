from __future__ import annotations

import asyncio
import ipaddress
from typing import Any, cast

from stackscan.types import IpInfo

_IPWHO_URL = "https://ipwho.is/"
_CDN_KEYWORDS = (
    "cloudflare",
    "fastly",
    "akamai",
    "cloudfront",
    "amazon",
    "aws",
    "google",
    "microsoft",
    "azure",
    "incapsula",
    "imperva",
    "sucuri",
    "stackpath",
    "cdn77",
    "bunny",
    "keycdn",
    "limelight",
    "edgecast",
    "gcore",
    "edgio",
    "verizon",
)


def _is_public(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(ip.split("%", 1)[0])
    except ValueError:
        return False
    return not (parsed.is_private or parsed.is_loopback or parsed.is_link_local)


def is_public_ip(ip: str) -> bool:
    return _is_public(ip)


def _looks_like_cdn(*values: str | None) -> bool:
    blob = " ".join(v.lower() for v in values if v)
    return any(keyword in blob for keyword in _CDN_KEYWORDS)


def is_cdn_host(*values: str | None) -> bool:
    return _looks_like_cdn(*values)


async def enrich_ips(
    ips: tuple[str, ...],
    *,
    timeout: float = 10.0,
    workers: int = 5,
    sources: dict[str, str] | None = None,
) -> list[IpInfo]:
    import aiohttp

    targets = [ip for ip in dict.fromkeys(ips) if _is_public(ip)]
    if not targets:
        return []
    sources = sources or {}
    semaphore = asyncio.Semaphore(max(workers, 1))
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    async with aiohttp.ClientSession(timeout=client_timeout) as session:

        async def lookup(ip: str) -> IpInfo | None:
            async with semaphore:
                try:
                    async with session.get(
                        f"{_IPWHO_URL}{ip}", headers={"User-Agent": "stackscan"}
                    ) as resp:
                        if resp.status != 200:
                            return None
                        data = cast("dict[str, Any]", await resp.json())
                except (aiohttp.ClientError, TimeoutError, ValueError, OSError):
                    return None
            if not data.get("success"):
                return None
            connection = cast("dict[str, Any]", data.get("connection") or {})
            asn = connection.get("asn")
            org = connection.get("org")
            isp = connection.get("isp")
            return IpInfo(
                ip=ip,
                country=data.get("country"),
                city=data.get("city"),
                org=org,
                isp=isp,
                asn=f"AS{asn}" if asn else None,
                is_cdn=_looks_like_cdn(org, isp),
                source=sources.get(ip, ""),
            )

        results = await asyncio.gather(*(lookup(ip) for ip in targets))
    return [info for info in results if info is not None]
