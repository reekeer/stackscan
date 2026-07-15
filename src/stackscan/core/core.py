from __future__ import annotations

from collections.abc import Iterable

from aiohttp import ClientSession, ClientTimeout

from stackscan.net.resolver import build_connector
from stackscan.types import FetchResult


def _lower_headers(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {key.lower(): value for key, value in items}


class StackscanSession:
    def __init__(self) -> None:
        self._session: ClientSession | None = None

    async def __aenter__(self) -> StackscanSession:
        self._session = ClientSession(connector=build_connector())
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._session is not None:
            await self._session.close()
            self._session = None

    async def fetch(
        self,
        url: str,
        *,
        timeout: float,
        user_agent: str,
        insecure: bool,
        max_bytes: int,
        headers: dict[str, str] | None = None,
    ) -> FetchResult:
        session = self._session
        if session is None:
            raise RuntimeError("StackscanSession is not entered")
        request_headers: dict[str, str] = {"User-Agent": user_agent}
        if headers:
            request_headers.update(headers)
        async with session.get(
            url,
            headers=request_headers,
            ssl=False if insecure else True,
            timeout=ClientTimeout(total=timeout),
        ) as resp:
            status = resp.status
            header_items = list(resp.headers.items())
            headers = _lower_headers(header_items)
            raw_headers = [f"{key.lower()}: {value}" for key, value in header_items]
            cookies = resp.headers.getall("Set-Cookie", [])
            charset = resp.charset or "utf-8"
            body_bytes = await resp.content.read(max_bytes)
            while await resp.content.read(8192):
                pass
            body = body_bytes.decode(charset, errors="replace")
            url_final = str(resp.url)
            version = resp.version
            http_version = f"{version.major}.{version.minor}" if version else None
        return FetchResult(
            url=url_final,
            status=status,
            headers={"_raw": "\n".join(raw_headers), **headers},
            body=body,
            cookies=tuple(cookies),
            http_version=http_version,
        )
