from __future__ import annotations

import asyncio
import re
import secrets
import socket
import urllib.request
from functools import lru_cache
from importlib import resources
from typing import Any, cast

from stackscan.types import Subdomain
from stackscan.utils import db_dir

_WORDLIST_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-110000.txt"
_WORDLIST_TIMEOUT = 20
_WORDLIST_MAX_BYTES = 8 * 1024 * 1024


def _parse_labels(text: str) -> tuple[str, ...]:
    labels: list[str] = []
    seen: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line in seen:
            continue
        seen.add(line)
        labels.append(line)
    return tuple(labels)


@lru_cache(maxsize=1)
def load_bundled_wordlist() -> tuple[str, ...]:
    text = resources.files("stackscan.data").joinpath("subdomains.txt").read_text("utf-8")
    return _parse_labels(text)


def _download_wordlist() -> str:
    request = urllib.request.Request(_WORDLIST_URL, headers={"User-Agent": "stackscan"})
    with urllib.request.urlopen(request, timeout=_WORDLIST_TIMEOUT) as response:
        return response.read(_WORDLIST_MAX_BYTES).decode("utf-8", "replace")


@lru_cache(maxsize=1)
def load_wordlist() -> tuple[str, ...]:
    cache = db_dir() / "seclists-dns-top110k.txt"
    if cache.is_file():
        try:
            return _parse_labels(cache.read_text("utf-8"))
        except OSError:
            pass
    try:
        text = _download_wordlist()
    except (OSError, ValueError):
        return load_bundled_wordlist()
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(text, encoding="utf-8")
    except OSError:
        pass
    labels = _parse_labels(text)
    return labels or load_bundled_wordlist()


def apex_domain(host: str) -> str:
    host = host.lower().strip(".")
    if host.startswith("www."):
        return host[4:]
    return host


def _resolve(name: str) -> tuple[str, ...]:
    try:
        infos = socket.getaddrinfo(name, None, type=socket.SOCK_STREAM)
    except OSError:
        return ()
    seen: list[str] = []
    for info in infos:
        addr = str(info[4][0])
        if addr not in seen:
            seen.append(addr)
    return tuple(seen)


def _zone_transfer(apex: str) -> dict[str, tuple[str, ...]]:
    try:
        from dns import query as _dns_query, resolver as _dns_resolver, zone as _dns_zone
    except ImportError:
        return {}
    resolver = cast("Any", _dns_resolver)
    query = cast("Any", _dns_query)
    zone_mod = cast("Any", _dns_zone)
    try:
        ns_answers: Any = resolver.resolve(apex, "NS", raise_on_no_answer=False)
    except Exception:
        return {}
    found: dict[str, tuple[str, ...]] = {}
    for ns in cast("list[Any]", ns_answers):
        ns_name = str(getattr(ns, "target", ns)).rstrip(".")
        if not ns_name:
            continue
        try:
            xfr = query.xfr(ns_name, apex, timeout=5.0, lifetime=8.0)
            zone = zone_mod.from_xfr(xfr)
        except Exception:
            continue
        for name, _ttl, rdata in zone.iterate_rdatas("A"):
            fqdn = str(name)
            fqdn = apex if fqdn in ("@", "") else f"{fqdn}.{apex}".rstrip(".")
            addr = str(getattr(rdata, "address", "")).strip()
            if addr:
                found.setdefault(fqdn, ())
                if addr not in found[fqdn]:
                    found[fqdn] = (*found[fqdn], addr)
    return found


def _ordered_labels(limit: int) -> tuple[str, ...]:
    seen: set[str] = set()
    ordered: list[str] = []
    for label in (*load_bundled_wordlist(), *load_wordlist()):
        if label not in seen:
            seen.add(label)
            ordered.append(label)
    return tuple(ordered[:limit]) if limit > 0 else tuple(ordered)


_PUBLIC_RESOLVERS: tuple[str, ...] = (
    "1.1.1.1",
    "1.0.0.1",
    "8.8.8.8",
    "8.8.4.4",
    "9.9.9.9",
    "149.112.112.112",
    "208.67.222.222",
    "208.67.220.220",
    "94.140.14.14",
    "94.140.15.15",
    "185.228.168.9",
    "185.228.169.9",
    "76.76.2.0",
    "76.76.10.0",
    "8.26.56.26",
    "8.20.247.20",
    "64.6.64.6",
    "64.6.65.6",
    "156.154.70.1",
    "156.154.71.1",
    "77.88.8.8",
    "77.88.8.1",
    "84.200.69.80",
    "84.200.70.40",
    "4.2.2.1",
    "4.2.2.2",
)


async def _resolve_many(
    names: list[str], timeout: float, workers: int
) -> dict[str, tuple[str, ...]]:
    try:
        from dns import asyncquery as _asyncquery, message as _message, rdatatype as _rdatatype
    except ImportError:
        return await _resolve_many_thread(names, timeout, workers)
    asyncquery = cast("Any", _asyncquery)
    message = cast("Any", _message)
    a_type = cast("Any", _rdatatype).A
    query_timeout = min(timeout, 2.0)
    semaphore = asyncio.Semaphore(max(workers, 1))
    out: dict[str, tuple[str, ...]] = {}

    async def query_once(name: str, server: str) -> Any | None:
        async with semaphore:
            try:
                query = message.make_query(name, a_type)
                return await asyncquery.udp(query, server, timeout=query_timeout)
            except Exception:
                return None

    async def one(name: str, index: int) -> None:
        response: Any | None = None
        for attempt in range(3):
            server = _PUBLIC_RESOLVERS[(index + attempt) % len(_PUBLIC_RESOLVERS)]
            response = await query_once(name, server)
            if response is not None:
                break
        if response is None:
            return
        addrs: list[str] = []
        for rrset in cast("list[Any]", response.answer):
            if rrset.rdtype != a_type:
                continue
            for item in cast("list[Any]", rrset):
                addr = str(getattr(item, "address", "")).strip()
                if addr and addr not in addrs:
                    addrs.append(addr)
        if addrs:
            out[name] = tuple(addrs)

    await asyncio.gather(*(one(name, i) for i, name in enumerate(names)))
    return out


async def resolve_many(
    names: list[str], timeout: float, workers: int
) -> dict[str, tuple[str, ...]]:
    return await _resolve_many(names, timeout, workers)


async def resolve_existing(
    names: list[str], *, timeout: float = 2.0, workers: int = 1500
) -> list[str]:
    resolved = await _resolve_many(names, timeout, workers)
    return sorted(resolved)


async def _resolve_many_thread(
    names: list[str], timeout: float, workers: int
) -> dict[str, tuple[str, ...]]:
    semaphore = asyncio.Semaphore(max(workers, 1))
    out: dict[str, tuple[str, ...]] = {}

    async def one(name: str) -> None:
        async with semaphore:
            try:
                addrs = await asyncio.wait_for(asyncio.to_thread(_resolve, name), timeout=timeout)
            except TimeoutError:
                return
        if addrs:
            out[name] = addrs

    await asyncio.gather(*(one(name) for name in names))
    return out


async def _wildcard_ips(apex: str, timeout: float, workers: int) -> set[str]:
    probes = [f"{secrets.token_hex(8)}-stackscan.{apex}" for _ in range(3)]
    resolved = await _resolve_many(probes, timeout, workers)
    ips: set[str] = set()
    for addrs in resolved.values():
        ips.update(addrs)
    return ips


RECURSIVE_PREFIXES: tuple[str, ...] = (
    "www",
    "mail",
    "mx",
    "mx1",
    "mx2",
    "mx3",
    "smtp",
    "imap",
    "pop",
    "webmail",
    "ns",
    "ns1",
    "ns2",
    "api",
    "app",
    "web",
    "dev",
    "staging",
    "test",
    "vpn",
    "admin",
    "portal",
    "cdn",
    "static",
    "git",
    "ftp",
    "gateway",
    "remote",
    "autodiscover",
    "autoconfig",
    "cpanel",
    "server",
    "server1",
    "node1",
)
_MAX_RECURSIVE = 3000
_HOST_RE = re.compile("[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+")


def hostnames_in_records(values: tuple[str, ...], apex: str) -> set[str]:
    suffix = "." + apex
    found: set[str] = set()
    for value in values:
        for match in _HOST_RE.findall(value.lower()):
            host = match.strip(".")
            if host != apex and host.endswith(suffix):
                found.add(host)
    return found


def _parent_zones(name: str, apex: str) -> list[str]:
    zones: list[str] = []
    labels = name.split(".")
    apex_len = len(apex.split("."))
    while len(labels) > apex_len + 1:
        labels = labels[1:]
        zones.append(".".join(labels))
    return zones


async def enumerate_subdomains(
    host: str,
    *,
    san_names: tuple[str, ...] = (),
    dns_hosts: tuple[str, ...] = (),
    timeout: float = 3.0,
    workers: int = 100,
    limit: int = 5000,
    recursive: bool = True,
    passive: bool = True,
) -> list[Subdomain]:
    apex = apex_domain(host)
    if not apex:
        return []
    discovered: dict[str, Subdomain] = {}
    dns_workers = min(max(workers * 10, 1000), 1500)

    ct_coro = _cert_transparency(apex) if passive else _empty_set()
    axfr, wildcard, ct_names = await asyncio.gather(
        asyncio.to_thread(_zone_transfer, apex),
        _wildcard_ips(apex, timeout, dns_workers),
        ct_coro,
    )
    for name, addrs in axfr.items():
        discovered[name] = Subdomain(name=name, addresses=addrs, source="axfr")

    labels = await asyncio.to_thread(_ordered_labels, limit)
    candidates: dict[str, str] = {}
    for label in labels:
        candidates.setdefault(f"{label}.{apex}", "dns-wordlist")
    for san in san_names:
        san = san.lower().lstrip("*.").strip(".")
        if san and san != apex and san.endswith("." + apex):
            candidates.setdefault(san, "tls-san")
    for host_name in hostnames_in_records(dns_hosts, apex):
        candidates.setdefault(host_name, "dns-record")

    for ct_name in ct_names:
        candidates.setdefault(ct_name, "crt.sh")
    pending = [name for name in candidates if name not in discovered]
    await _resolve_into(discovered, candidates, pending, timeout, dns_workers, wildcard)

    for name, source in candidates.items():
        if source in ("crt.sh", "tls-san", "dns-record") and name not in discovered:
            discovered[name] = Subdomain(name=name, addresses=(), source=source)

    if recursive:
        bases: set[str] = set()
        for name in list(discovered):
            if name == apex or not name.endswith("." + apex):
                continue
            bases.add(name)
            bases.update(_parent_zones(name, apex))
        rec: dict[str, str] = {}
        for base in bases:
            for prefix in RECURSIVE_PREFIXES:
                cand = f"{prefix}.{base}"
                if cand not in discovered and cand not in candidates:
                    rec.setdefault(cand, "recursive")
        rec_pending = list(rec)[:_MAX_RECURSIVE]
        await _resolve_into(discovered, rec, rec_pending, timeout, dns_workers, wildcard)
    return sorted(discovered.values(), key=lambda sub: sub.name)


async def _resolve_into(
    discovered: dict[str, Subdomain],
    sources: dict[str, str],
    pending: list[str],
    timeout: float,
    workers: int,
    wildcard: set[str],
) -> None:
    resolved = await _resolve_many(pending, timeout, workers)
    for name, addrs in resolved.items():
        source = sources.get(name, "dns")

        if (
            wildcard
            and source not in ("tls-san", "dns-record", "axfr", "crt.sh")
            and (set(addrs) <= wildcard)
        ):
            continue
        discovered.setdefault(name, Subdomain(name=name, addresses=addrs, source=source))


async def _empty_set() -> set[str]:
    return set()


_CT_TIMEOUT = 25


async def _cert_transparency(apex: str) -> set[str]:

    async def safe(coro: Any) -> set[str]:
        try:
            return await coro
        except Exception:
            return set()

    crtsh_names = await safe(_crtsh(apex))
    if not crtsh_names:
        crtsh_names = await safe(_crtsh(apex))
    certspotter_names = await safe(_certspotter(apex))
    return crtsh_names | certspotter_names


def _ct_names_under(raw: object, apex: str) -> set[str]:
    suffix = "." + apex
    out: set[str] = set()
    for chunk in str(raw).replace(",", "\n").splitlines():
        name = chunk.strip().lower().lstrip("*.").strip(".")
        if name and name != apex and name.endswith(suffix) and " " not in name:
            out.add(name)
    return out


async def _crtsh(apex: str) -> set[str]:
    import aiohttp

    url = f"https://crt.sh/?q=%25.{apex}&output=json"
    timeout = aiohttp.ClientTimeout(total=_CT_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers={"User-Agent": "stackscan"}) as resp:
            if resp.status != 200:
                return set()
            rows = cast("list[dict[str, Any]]", await resp.json(content_type=None))
    found: set[str] = set()
    for row in rows:
        found |= _ct_names_under(row.get("name_value", ""), apex)
        found |= _ct_names_under(row.get("common_name", ""), apex)
    return found


async def _certspotter(apex: str) -> set[str]:
    import aiohttp

    url = (
        "https://api.certspotter.com/v1/issuances"
        f"?domain={apex}&include_subdomains=true&expand=dns_names"
    )
    timeout = aiohttp.ClientTimeout(total=_CT_TIMEOUT)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(url, headers={"User-Agent": "stackscan"}) as resp:
            if resp.status != 200:
                return set()
            rows = cast("list[dict[str, Any]]", await resp.json())
    found: set[str] = set()
    for row in rows:
        for name in cast("list[str]", row.get("dns_names") or []):
            found |= _ct_names_under(name, apex)
    return found
