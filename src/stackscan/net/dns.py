from __future__ import annotations

import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, cast

_QUERY_TIMEOUT = 2.5
_QUERY_LIFETIME = 5.0
_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")

# Public resolvers. Cloudflare + Google answer correctly almost everywhere and
# DNS records barely change between them, so there is no need to poll a domain's
# own registrar on every run. The rest are censorship-resistant fallbacks for
# regions where the first two are blocked or throttled (Yandex in particular
# stays reachable across most of the CIS). They are tried in order and a query
# only moves on when one times out, so healthy networks pay for the first entry.
_PUBLIC_NAMESERVERS: tuple[str, ...] = (
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "208.67.222.222",
    "77.88.8.8",
)


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
    ttl: dict[str, int] = field(default_factory=dict[str, int])


def _load_dns() -> Any | None:
    import importlib

    try:
        importlib.import_module("dns.resolver")
        importlib.import_module("dns.reversename")
    except ImportError:
        return None
    return cast("Any", importlib.import_module("dns"))


_cache_lock = threading.Lock()
_shared_cache: Any = None


def _resolver(dns_mod: Any, *, public: bool) -> Any:
    """Build a resolver backed by a process-wide, TTL-respecting cache.

    A fresh Resolver is cheap; sharing only the (thread-safe) cache keeps
    repeated lookups within a run instant while avoiding any per-instance
    threading concerns when the record types are queried in parallel.
    """
    global _shared_cache
    if public:
        resolver = dns_mod.resolver.Resolver(configure=False)
        resolver.nameservers = list(_PUBLIC_NAMESERVERS)
    else:
        resolver = dns_mod.resolver.Resolver()
    resolver.timeout = _QUERY_TIMEOUT
    resolver.lifetime = _QUERY_LIFETIME
    with _cache_lock:
        if _shared_cache is None:
            _shared_cache = dns_mod.resolver.LRUCache(max_size=10000)
    resolver.cache = _shared_cache
    return resolver


def _query(resolver: Any, host: str, rdtype: str) -> tuple[list[str], int]:
    from dns import exception as _dns_exc  # type: ignore[import-untyped]

    try:
        answers = resolver.resolve(host, rdtype, raise_on_no_answer=False)
    except _dns_exc.DNSException:
        return [], 0
    except Exception:
        return [], 0
    if answers is None:
        return [], 0
    ttl: int = int(getattr(answers, "ttl", 0) or 0)
    values: list[str] = []
    for rdata in cast("list[Any]", answers):
        text = _format_rdata(rdtype, rdata)
        if text and text not in values:
            values.append(text)
    return values, ttl


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


def _gather(
    dns_mod: Any, host: str, *, public: bool
) -> tuple[dict[str, tuple[str, ...]], dict[str, int]]:
    resolver = _resolver(dns_mod, public=public)
    with ThreadPoolExecutor(max_workers=len(_RECORD_TYPES)) as pool:
        futures = {rdtype: pool.submit(_query, resolver, host, rdtype) for rdtype in _RECORD_TYPES}
        results = {rdtype: future.result() for rdtype, future in futures.items()}
    records = {rdtype: tuple(values) for rdtype, (values, _) in results.items() if values}
    ttls = {rdtype: ttl for rdtype, (_, ttl) in results.items() if ttl}
    return records, ttls


def _reverse_lookup(dns_mod: Any, ips: tuple[str, ...]) -> dict[str, str]:
    if not ips:
        return {}
    resolver = _resolver(dns_mod, public=True)

    def one(ip: str) -> str | None:
        try:
            rev = dns_mod.reversename.from_address(ip)
            answers = resolver.resolve(rev, "PTR", raise_on_no_answer=False)
        except Exception:
            return None
        if answers is None:
            return None
        for rdata in cast("list[Any]", answers):
            name = str(getattr(rdata, "target", rdata)).rstrip(".")
            if name:
                return name
        return None

    out: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=len(ips)) as pool:
        for ip, name in zip(ips, pool.map(one, ips), strict=True):
            if name:
                out[ip] = name
    return out


def resolve_host(host: str, *, reverse: bool = True) -> DnsResult:
    dns_mod = _load_dns()
    if dns_mod is None:
        return _resolve_host_stdlib(host, reverse=reverse)
    records, ttls = _gather(dns_mod, host, public=True)
    # Only fall back to the system resolver when the public path returned no
    # addresses at all (e.g. a network that blocks outbound 53 or split-horizon
    # DNS), and only if the system resolver actually knows the name.
    if not records.get("A") and not records.get("AAAA"):
        sys_records, sys_ttls = _gather(dns_mod, host, public=False)
        if sys_records.get("A") or sys_records.get("AAAA"):
            records, ttls = sys_records, sys_ttls
    ipv4 = records.get("A", ())
    ipv6 = records.get("AAAA", ())
    reverse_map = _reverse_lookup(dns_mod, (*ipv4, *ipv6)) if reverse else {}
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
        ttl=ttls,
    )


def resolve_ips(host: str, *, want_v6: bool = False) -> list[str]:
    """Fast, cached A/AAAA lookup for connecting to a host (used by the HTTP
    connector). Returns literals unchanged and never raises."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    dns_mod = _load_dns()
    if dns_mod is None:
        family = socket.AF_INET6 if want_v6 else socket.AF_INET
        return _addrinfo(host, family)
    resolver = _resolver(dns_mod, public=True)
    values, _ = _query(resolver, host, "AAAA" if want_v6 else "A")
    if values:
        return values
    family = socket.AF_INET6 if want_v6 else socket.AF_INET
    return _addrinfo(host, family)


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


def _resolve_host_stdlib(host: str, *, reverse: bool = True) -> DnsResult:
    ipv4 = tuple(_addrinfo(host, socket.AF_INET))
    ipv6 = tuple(_addrinfo(host, socket.AF_INET6))
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
        cname=(),
        reverse_dns=reverse_map,
        resolver_available=False,
    )
