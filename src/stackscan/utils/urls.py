from __future__ import annotations

import ipaddress
from urllib.parse import urlparse


def is_cidr(raw: str) -> bool:
    try:
        ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return False
    return "/" in raw


def expand_cidr(raw: str) -> list[str]:
    network = ipaddress.ip_network(raw, strict=False)
    return [str(host) for host in network]


def normalize_url(raw: str) -> str:
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw


def host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else "https://" + url)
    return (parsed.hostname or "").lower()


def port_of(url: str) -> int:
    parsed = urlparse(url)
    if parsed.port is not None:
        return parsed.port
    return 443 if is_https(url) else 80


def is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"
