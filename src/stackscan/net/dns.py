"""DNS resolution using the standard library only.

CNAME chains need a real resolver; if ``dnspython`` is installed we use it,
otherwise we fall back to A/AAAA/PTR records available through ``socket``.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any, cast


@dataclass(frozen=True)
class DnsResult:
    host: str
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    cname: tuple[str, ...]
    reverse_dns: dict[str, str]


def _addrinfo(host: str, family: int) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
    except OSError:
        return []
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return seen


def _reverse(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except OSError:
        return None
    return name


def _cname_chain(host: str) -> tuple[str, ...]:
    try:
        from dns import resolver as _dns_resolver  # type: ignore[import-untyped]
    except ImportError:
        return ()
    resolver = cast("Any", _dns_resolver)
    try:
        answers: Any = resolver.resolve(host, "CNAME", raise_on_no_answer=False)
    except Exception:
        return ()
    chain: list[str] = []
    for rdata in cast("list[Any]", answers):
        target = str(getattr(rdata, "target", "")).rstrip(".")
        if target and target not in chain:
            chain.append(target)
    return tuple(chain)


def resolve_host(host: str, *, reverse: bool = True) -> DnsResult:
    ipv4 = tuple(_addrinfo(host, socket.AF_INET))
    ipv6 = tuple(_addrinfo(host, socket.AF_INET6))
    cname = _cname_chain(host)

    reverse_map: dict[str, str] = {}
    if reverse:
        for ip in (*ipv4, *ipv6):
            name = _reverse(ip)
            if name:
                reverse_map[ip] = name

    return DnsResult(
        host=host,
        ipv4=ipv4,
        ipv6=ipv6,
        cname=cname,
        reverse_dns=reverse_map,
    )
