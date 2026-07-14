from __future__ import annotations

import socket

import aiohttp
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.resolver import ThreadedResolver


class FallbackResolver(AbstractResolver):
    def __init__(self) -> None:
        self._system = ThreadedResolver()

    async def resolve(
        self, host: str, port: int = 0, family: socket.AddressFamily = socket.AddressFamily.AF_INET
    ) -> list[ResolveResult]:
        try:
            return await self._system.resolve(host, port, family)
        except OSError:
            results = await self._fallback(host, port, family)
            if results:
                return results
            raise

    async def _fallback(
        self, host: str, port: int, family: socket.AddressFamily
    ) -> list[ResolveResult]:
        if family not in (socket.AddressFamily.AF_INET, socket.AF_UNSPEC):
            return []
        try:
            from stackscan.net.subdomains import resolve_many

            resolved = await resolve_many([host], 3.0, 100)
        except Exception:
            return []
        addresses = resolved.get(host, ())
        return [
            ResolveResult(
                hostname=host,
                host=address,
                port=port,
                family=socket.AF_INET,
                proto=0,
                flags=socket.AI_NUMERICHOST,
            )
            for address in addresses
        ]

    async def close(self) -> None:
        await self._system.close()


def build_connector() -> aiohttp.TCPConnector:
    return aiohttp.TCPConnector(resolver=FallbackResolver())
