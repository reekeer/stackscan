"""Core session for stackscan."""

from __future__ import annotations

from collections.abc import Iterable

from aiohttp import ClientSession, ClientTimeout

from stackscan.types import FetchResult


def _lower_headers(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {key.lower(): value for key, value in items}


class StackscanSession:
    """Holds an aiohttp ClientSession with stackscan defaults and helpers."""

    def __init__(self) -> None:
        self._session: ClientSession | None = None

    async def __aenter__(self) -> StackscanSession:
        self._session = ClientSession()
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
    ) -> FetchResult:
        session = self._session
        if session is None:
            raise RuntimeError("StackscanSession is not entered")

        async with session.get(
            url,
            headers={"User-Agent": user_agent},
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
            body = body_bytes.decode(charset, errors="replace")
            url_final = str(resp.url)

        return FetchResult(
            url=url_final,
            status=status,
            headers={"_raw": "\n".join(raw_headers), **headers},
            body=body,
            cookies=tuple(cookies),
        )
