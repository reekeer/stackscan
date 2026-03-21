"""Core session for stackscan with anti-bot evasion."""

from __future__ import annotations

import asyncio
import random
import time
from typing import Any

from aiohttp import ClientSession, ClientTimeout

from stackscan.types import FetchResult


REALISTIC_USER_AGENTS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/122.0.0.0",
)

ACCEPT_HEADERS = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8"
ACCEPT_LANGUAGE = "en-US,en;q=0.9"
ACCEPT_ENCODING = "gzip, deflate, br"


def _get_realistic_headers(user_agent: str | None = None) -> dict[str, str]:
    ua = user_agent or random.choice(REALISTIC_USER_AGENTS)
    return {
        "User-Agent": ua,
        "Accept": ACCEPT_HEADERS,
        "Accept-Language": ACCEPT_LANGUAGE,
        "Accept-Encoding": ACCEPT_ENCODING,
        "DNT": "1",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Cache-Control": "max-age=0",
    }


def _lower_headers_dict(items: list[tuple[str, str]]) -> dict[str, str]:
    return dict((k.lower(), v) for k, v in items)


class StackscanSession(ClientSession):
    """Optimized ClientSession with anti-bot evasion and connection pooling."""

    def __init__(
        self,
        *,
        delay_ms: int = 0,
        connector_kwargs: dict[str, Any] | None = None,
    ) -> None:
        self._delay_ms = delay_ms
        self._last_request_time = 0.0
        self._connector_kwargs = connector_kwargs or {}

        super().__init__(
            timeout=ClientTimeout(total=30, connect=10, sock_read=20),
            connector_owner=False,
        )

    async def fetch(
        self,
        url: str,
        *,
        timeout: float,
        user_agent: str,
        insecure: bool,
        max_bytes: int,
    ) -> FetchResult:
        if self._delay_ms > 0:
            elapsed = time.monotonic() - self._last_request_time
            min_interval = self._delay_ms / 1000.0
            if elapsed < min_interval:
                await asyncio.sleep(min_interval - elapsed)
            self._last_request_time = time.monotonic()

        headers = _get_realistic_headers(user_agent)

        async with self.get(
            url,
            headers=headers,
            ssl=not insecure,
            timeout=ClientTimeout(total=timeout),
            allow_redirects=True,
            max_redirects=5,
        ) as resp:
            status = resp.status
            header_items = list(resp.headers.items())
            headers_lower = _lower_headers_dict(header_items)
            raw_headers_str = "\n".join(f"{k.lower()}: {v}" for k, v in header_items)
            cookies = resp.headers.getall("Set-Cookie", [])
            charset = resp.charset or "utf-8"
            body_bytes = await resp.content.read(max_bytes)
            body = body_bytes.decode(charset, errors="replace")
            url_final = str(resp.url)

        return FetchResult(
            url=url_final,
            status=status,
            headers={"_raw": raw_headers_str, **headers_lower},
            body=body,
            cookies=tuple(cookies),
        )
