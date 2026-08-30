from __future__ import annotations

import ipaddress
from urllib.parse import urlparse

MAX_CIDR_HOSTS = 65536


def is_cidr(raw: str) -> bool:
    try:
        ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return False
    return "/" in raw


def expand_cidr(raw: str) -> list[str]:
    network = ipaddress.ip_network(raw, strict=False)
    if network.num_addresses > MAX_CIDR_HOSTS:
        raise ValueError(
            f"{raw} expands to {network.num_addresses} addresses"
            f" (limit {MAX_CIDR_HOSTS}); use a smaller prefix"
        )
    return [str(host) for host in network]


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def normalize_url(raw: str) -> str:
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw


def host_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else "https://" + url)
    return (parsed.hostname or "").lower()


def netloc_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else "https://" + url)
    host = (parsed.hostname or "").lower()
    if parsed.port is not None:
        return f"{host}:{parsed.port}"
    return host


def port_of(url: str) -> int:
    parsed = urlparse(url)
    if parsed.port is not None:
        return parsed.port
    return 443 if is_https(url) else 80


def is_https(url: str) -> bool:
    return urlparse(url).scheme == "https"
