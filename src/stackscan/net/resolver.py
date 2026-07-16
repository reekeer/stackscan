from __future__ import annotations

import socket

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import ThreadedResolver

from stackscan.net.dns import resolve_ips


class FallbackResolver(AbstractResolver):
    """Resolve via cached public DNS first, then the system resolver.

    Public resolvers are both fast and give the outside-world view a scanner
    wants; the system resolver is only consulted when the public path returns
    nothing (internal names, split-horizon DNS, or blocked outbound 53).
    """

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
                for address in await self._lookup(host, want_v6):
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

    @staticmethod
    async def _lookup(host: str, want_v6: bool) -> list[str]:
        import asyncio

        return await asyncio.to_thread(resolve_ips, host, want_v6=want_v6)

    async def close(self) -> None:
        await self._system.close()


def build_connector() -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(resolver=FallbackResolver())
