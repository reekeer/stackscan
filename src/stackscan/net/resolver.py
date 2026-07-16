from __future__ import annotations

import asyncio
import socket

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import ThreadedResolver

from stackscan.net.dns import resolve_ips


class FallbackResolver(AbstractResolver):
    def __init__(self) -> None:
        self._system = ThreadedResolver()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AddressFamily.AF_INET
    ) -> list[ResolveResult]:
        results = await self._public(host, port, family)
        if results:
            return results
        return await self._system.resolve(host, port, family)

    async def _public(
        self, host: str, port: int, family: socket.AddressFamily
    ) -> list[ResolveResult]:
        try:
            families: tuple[socket.AddressFamily, ...]
            if family == socket.AF_UNSPEC:
                families = (socket.AF_INET, socket.AF_INET6)
            else:
                families = (family,)
            results: list[ResolveResult] = []
            for fam in families:
                want_v6 = fam == socket.AF_INET6
                addresses = await asyncio.to_thread(resolve_ips, host, want_v6=want_v6)
                for address in addresses:
                    results.append(
                        ResolveResult(
                            hostname=host,
                            host=address,
                            port=port,
                            family=fam,
                            proto=0,
                            flags=socket.AI_NUMERICHOST,
                        )
                    )
            return results
        except Exception:
            return []

    async def close(self) -> None:
        await self._system.close()


def build_connector() -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(resolver=FallbackResolver())
