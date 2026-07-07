"""URL helpers."""

from __future__ import annotations

from urllib.parse import urlparse


def normalize_url(raw: str) -> str:
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw


def host_of(url: str) -> str:
    """Return the bare hostname of a URL (no port, no scheme)."""

    parsed = urlparse(url if "://" in url else "https://" + url)
    return (parsed.hostname or "").lower()


def port_of(url: str) -> int:
    """Return the explicit or default HTTPS port for a URL."""

    parsed = urlparse(url)
    if parsed.port is not None:
        return parsed.port
    return 443 if is_https(url) else 80


def is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"
