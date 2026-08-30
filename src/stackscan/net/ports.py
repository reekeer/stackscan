from __future__ import annotations

import asyncio
import shutil
from typing import Any, cast

from stackscan.net.fingerprint import (
    fingerprint_banner,
    fingerprint_http,
    fingerprint_mysql,
    normalize_mysql_version,
    sanitize_banner,
)
from stackscan.types import Port, PortScan

COMMON_PORTS: dict[int, tuple[str, str]] = {
    21: ("ftp", "banner"),
    22: ("ssh", "banner"),
    23: ("telnet", "banner"),
    25: ("smtp", "banner"),
    53: ("domain", "none"),
    80: ("http", "http"),
    110: ("pop3", "banner"),
    111: ("rpcbind", "none"),
    135: ("msrpc", "none"),
    139: ("netbios-ssn", "none"),
    143: ("imap", "banner"),
    443: ("https", "http"),
    445: ("microsoft-ds", "none"),
    465: ("smtps", "banner"),
    554: ("rtsp", "rtsp"),
    587: ("submission", "banner"),
    631: ("ipp", "http"),
    993: ("imaps", "none"),
    995: ("pop3s", "none"),
    1433: ("ms-sql", "none"),
    1723: ("pptp", "none"),
    1883: ("mqtt", "banner"),
    2082: ("cpanel", "http"),
    2083: ("cpanel-ssl", "http"),
    2222: ("ssh-alt", "banner"),
    3000: ("http-dev", "http"),
    3306: ("mysql", "mysql"),
    3307: ("mysql", "mysql"),
    3389: ("ms-wbt-server", "none"),
    5432: ("postgresql", "none"),
    5900: ("vnc", "banner"),
    5985: ("wsman", "none"),
    6379: ("redis", "banner"),
    7547: ("cwmp", "http"),
    8000: ("http-alt", "http"),
    8080: ("http-proxy", "http"),
    8081: ("http-alt", "http"),
    8443: ("https-alt", "http"),
    8554: ("rtsp-alt", "rtsp"),
    8888: ("http-alt", "http"),
    9000: ("http-alt", "http"),
    9200: ("elasticsearch", "http"),
    11211: ("memcached", "none"),
    27017: ("mongodb", "none"),
}
_BANNER_BYTES = 512


def nmap_available() -> bool:
    return shutil.which("nmap") is not None


def default_ports() -> tuple[int, ...]:
    return tuple(sorted(COMMON_PORTS))


async def scan_ports(
    host: str,
    *,
    ports: tuple[int, ...] | None = None,
    timeout: float = 2.0,
    prefer_nmap: bool = True,
    workers: int = 100,
) -> PortScan:
    targets = ports or default_ports()
    if prefer_nmap and nmap_available():
        result = await asyncio.to_thread(_run_nmap, host, targets)
        if result is not None:
            return result
    return await _connect_scan(host, targets, timeout, workers)


def _run_nmap(host: str, ports: tuple[int, ...]) -> PortScan | None:
    try:
        import nmap
    except ImportError:
        return None
    try:
        scanner = cast("Any", nmap).PortScanner()
        port_arg = ",".join(str(p) for p in ports)
        scanner.scan(host, port_arg, arguments="-Pn -sV --version-light -T4")
    except Exception:
        return None
    found: list[Port] = []
    try:
        hosts = cast("list[str]", scanner.all_hosts())
    except Exception:
        return None
    for scanned in hosts:
        tcp = cast("dict[int, dict[str, Any]]", scanner[scanned].get("tcp", {}))
        for number, info in tcp.items():
            if info.get("state") != "open":
                continue
            product = info.get("product") or None
            version = info.get("version") or None
            os_tag = ""
            if version and (product or "").lower() in ("mysql", "mariadb"):
                product, version, os_tag = normalize_mysql_version(product, version)
            extra = info.get("extrainfo") or None
            if extra and version:
                version = f"{version} ({extra})"
            found.append(
                Port(
                    port=int(number),
                    protocol="tcp",
                    state="open",
                    service=info.get("name") or None,
                    product=product,
                    version=version,
                    host=host,
                    os=os_tag,
                )
            )
    found.sort(key=lambda p: p.port)
    return PortScan(scanner="nmap", ports=tuple(found))


async def _connect_scan(
    host: str, ports: tuple[int, ...], timeout: float, workers: int
) -> PortScan:
    semaphore = asyncio.Semaphore(max(workers, 1))

    async def probe(port: int) -> Port | None:
        async with semaphore:
            return await _probe_port(host, port, timeout)

    results = await asyncio.gather(*(probe(port) for port in ports))
    open_ports = tuple(sorted((p for p in results if p is not None), key=lambda p: p.port))
    note = "pure-Python connect scan (install nmap + python-nmap for full -sV detection)"
    return PortScan(scanner="connect", ports=open_ports, note=note)


def _os_from_banner(banner: str) -> str:
    from stackscan.net.fingerprint import extract_distro

    return extract_distro(banner) or ""


async def _probe_port(host: str, port: int, timeout: float) -> Port | None:
    service, probe = COMMON_PORTS.get(port, ("unknown", "banner"))
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (TimeoutError, OSError):
        return None
    product: str | None = None
    version: str | None = None
    os: str = ""
    state: str = "open"
    try:
        if probe == "banner":
            raw = await _read(reader, timeout)
            if raw:
                svc, product, version = fingerprint_banner(raw)
                service = svc or service
                if not product:
                    version = sanitize_banner(raw)[:80]
                os = _os_from_banner(raw)
        elif probe == "mysql":
            data = await _read_bytes(reader, timeout)
            if data:
                product, version, distro, auth_refused = fingerprint_mysql(data)
                service = (product or "mysql").lower()
                os = distro or ""
                if auth_refused:
                    state = "auth-refused"
        elif probe == "http":
            product, version, os = await _http_probe(host, port, reader, writer, timeout)
        elif probe == "rtsp":
            product, version = await _rtsp_probe(host, port, reader, writer, timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (TimeoutError, OSError):
            pass
    return Port(
        port=port,
        protocol="tcp",
        state=state,
        service=service,
        product=product,
        version=version,
        host=host,
        os=os,
    )


async def _read(reader: asyncio.StreamReader, timeout: float) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(_BANNER_BYTES), timeout=min(timeout, 2.5))
    except (TimeoutError, OSError):
        return None
    if not data:
        return None
    return sanitize_banner(data.decode("utf-8", "replace")).strip() or None


async def _read_bytes(reader: asyncio.StreamReader, timeout: float) -> bytes | None:
    try:
        data = await asyncio.wait_for(reader.read(_BANNER_BYTES), timeout=min(timeout, 2.5))
    except (TimeoutError, OSError):
        return None
    return data if data else None


async def _http_probe(
    host: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float
) -> tuple[str | None, str | None, str]:
    request = (
        f"GET / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: stackscan\r\nConnection: close\r\n\r\n"
    )
    try:
        writer.write(request.encode("ascii", "ignore"))
        await asyncio.wait_for(writer.drain(), timeout=min(timeout, 2.5))
    except (TimeoutError, OSError):
        return (None, None, "")
    raw = await _read(reader, timeout)
    if not raw:
        return (None, None, "")
    product, version = fingerprint_http(raw)
    os = _os_from_banner(raw)
    return (product, version, os)


async def _rtsp_probe(
    host: str, port: int, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float
) -> tuple[str | None, str | None]:
    request = f"OPTIONS rtsp://{host}:{port} RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: stackscan\r\n\r\n"
    try:
        writer.write(request.encode("ascii", "ignore"))
        await asyncio.wait_for(writer.drain(), timeout=min(timeout, 2.5))
    except (TimeoutError, OSError):
        return (None, None)
    raw = await _read(reader, timeout)
    if not raw:
        return (None, None)
    server = fingerprint_http(raw)
    if server != (None, None):
        return server
    return ("RTSP", None)
