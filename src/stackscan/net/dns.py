from __future__ import annotations

import ipaddress
import socket
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, cast

_QUERY_TIMEOUT = 2.0
_QUERY_LIFETIME = 3.0
_EXTENDED_TYPES = ("CNAME", "MX", "NS", "TXT", "SOA", "CAA")
_DNS_ATTEMPTS = 3


@dataclass(frozen=True)
class DnsResult:
    host: str
    ipv4: tuple[str, ...]
    ipv6: tuple[str, ...]
    cname: tuple[str, ...]
    reverse_dns: dict[str, str]
    mx: tuple[str, ...] = ()
    ns: tuple[str, ...] = ()
    txt: tuple[str, ...] = ()
    soa: tuple[str, ...] = ()
    caa: tuple[str, ...] = ()
    resolver_available: bool = False
    extras: dict[str, tuple[str, ...]] = field(default_factory=dict[str, tuple[str, ...]])


def _addrinfo(host: str, family: int) -> list[str]:
    for attempt in range(_DNS_ATTEMPTS):
        try:
            infos = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            if attempt + 1 < _DNS_ATTEMPTS and exc.errno in (socket.EAI_AGAIN, socket.EAI_FAIL):
                continue
            return []
        except OSError:
            return []
        seen: list[str] = []
        for info in infos:
            addr = str(info[4][0])
            if family == socket.AF_INET6 and _is_v4_mapped(addr):
                continue
            if addr not in seen:
                seen.append(addr)
        return seen
    return []


def _is_v4_mapped(addr: str) -> bool:
    try:
        parsed = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    return isinstance(parsed, ipaddress.IPv6Address) and parsed.ipv4_mapped is not None


def _reverse(ip: str) -> str | None:
    try:
        name, _, _ = socket.gethostbyaddr(ip)
    except OSError:
        return None
    return name


def _load_resolver() -> Any | None:
    try:
        from dns import resolver as _dns_resolver
    except ImportError:
        return None
    return cast("Any", _dns_resolver)


def _query(resolver: Any, host: str, rdtype: str) -> list[str]:
    from dns import exception as _dns_exc  # type: ignore[import-untyped]

    answers: Any = None
    for attempt in range(_DNS_ATTEMPTS):
        try:
            answers = resolver.resolve(host, rdtype, raise_on_no_answer=False)
            break
        except (_dns_exc.Timeout, _dns_exc.DNSException) as exc:
            if attempt + 1 < _DNS_ATTEMPTS and isinstance(exc, _dns_exc.Timeout):
                continue
            return []
        except Exception:
            return []
    if answers is None:
        return []
    values: list[str] = []
    for rdata in cast("list[Any]", answers):
        text = _format_rdata(rdtype, rdata)
        if text and text not in values:
            values.append(text)
    return values


def _format_rdata(rdtype: str, rdata: Any) -> str:
    if rdtype == "MX":
        pref = getattr(rdata, "preference", "")
        exchange = str(getattr(rdata, "exchange", "")).rstrip(".") or "."
        return f"{pref} {exchange}".strip()
    if rdtype in {"NS", "CNAME"}:
        return str(getattr(rdata, "target", rdata)).rstrip(".")
    if rdtype == "TXT":
        strings = getattr(rdata, "strings", None)
        if strings:
            return "".join(
                part.decode("utf-8", "replace") if isinstance(part, bytes) else str(part)
                for part in cast("list[Any]", strings)
            )
        return str(rdata).strip('"')
    if rdtype == "SOA":
        mname = str(getattr(rdata, "mname", "")).rstrip(".")
        rname = str(getattr(rdata, "rname", "")).rstrip(".")
        serial = getattr(rdata, "serial", "")
        return f"{mname} {rname} {serial}".strip()
    if rdtype == "CAA":
        flags = getattr(rdata, "flags", "")
        tag = getattr(rdata, "tag", "")
        value = getattr(rdata, "value", "")
        if isinstance(tag, bytes):
            tag = tag.decode("utf-8", "replace")
        if isinstance(value, bytes):
            value = value.decode("utf-8", "replace")
        return f"{flags} {tag} {value}".strip()
    return str(rdata).rstrip(".")


def _extended_records(host: str) -> dict[str, tuple[str, ...]]:
    resolver_mod = _load_resolver()
    if resolver_mod is None:
        return {}
    resolver = resolver_mod.Resolver()
    resolver.timeout = _QUERY_TIMEOUT
    resolver.lifetime = _QUERY_LIFETIME
    with ThreadPoolExecutor(max_workers=len(_EXTENDED_TYPES)) as pool:
        futures = {
            rdtype: pool.submit(_query, resolver, host, rdtype) for rdtype in _EXTENDED_TYPES
        }
        return {rdtype: tuple(future.result()) for rdtype, future in futures.items()}


def resolve_host(host: str, *, reverse: bool = True) -> DnsResult:
    ipv4 = tuple(_addrinfo(host, socket.AF_INET))
    ipv6 = tuple(_addrinfo(host, socket.AF_INET6))
    records = _extended_records(host)
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
        cname=records.get("CNAME", ()),
        reverse_dns=reverse_map,
        mx=records.get("MX", ()),
        ns=records.get("NS", ()),
        txt=records.get("TXT", ()),
        soa=records.get("SOA", ()),
        caa=records.get("CAA", ()),
        resolver_available=bool(records),
    )
