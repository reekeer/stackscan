from __future__ import annotations

import asyncio
import csv
import urllib.request
from functools import lru_cache

import aiohttp

from stackscan.types import BruteTarget, CredFinding, PortScan
from stackscan.utils import db_dir

_CREDS_URL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Default-Credentials/default-passwords.csv"
_CREDS_TIMEOUT = 20
_CREDS_MAX_BYTES = 4 * 1024 * 1024
_DEVICE_KEYWORDS = (
    "camera",
    "ipcam",
    "netcam",
    "webcam",
    "dvr",
    "nvr",
    "cctv",
    "hikvision",
    "dahua",
    "axis",
    "foscam",
    "vivotek",
    "goahead",
    "boa",
    "rompager",
    "router",
    "gateway",
    "modem",
    "nas",
    "synology",
    "qnap",
    "printer",
    "webcamxp",
    "network camera",
    "surveillance",
    "uc-httpd",
    "go2rtc",
    "rtsp",
    "mikrotik",
    "routeros",
    "webfig",
    "openwrt",
    "dd-wrt",
    "pfsense",
    "opnsense",
    "ubnt",
    "ubiquiti",
    "unifi",
    "tp-link",
    "tplink",
    "d-link",
    "dlink",
    "netgear",
    "zyxel",
    "huawei",
    "tenda",
    "asuswrt",
    "idrac",
    "ilo",
    "ipmi",
    "supermicro",
)
_CAMERA_KEYWORDS = (
    "camera",
    "ipcam",
    "netcam",
    "webcam",
    "dvr",
    "nvr",
    "cctv",
    "hikvision",
    "dahua",
    "axis",
    "foscam",
    "vivotek",
    "webcamxp",
    "network camera",
    "surveillance",
    "go2rtc",
    "rtsp",
)
_BUILTIN_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", ""),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "password"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", "admin"),
    ("service", "service"),
    ("user", "user"),
)


def _download_creds() -> str:
    request = urllib.request.Request(_CREDS_URL, headers={"User-Agent": "stackscan"})
    with urllib.request.urlopen(request, timeout=_CREDS_TIMEOUT) as response:
        return response.read(_CREDS_MAX_BYTES).decode("utf-8", "replace")


def _parse_creds_csv(text: str) -> list[tuple[str, str]]:
    pairs: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    reader = csv.reader(text.splitlines())
    for i, row in enumerate(reader):
        if i == 0 or len(row) < 3:
            continue
        user = "" if row[1].strip() in ("<BLANK>", "<blank>") else row[1].strip()
        password = "" if row[2].strip() in ("<BLANK>", "<blank>") else row[2].strip()
        if len(user) > 40 or len(password) > 40 or " " in user:
            continue
        pair = (user, password)
        if pair in seen:
            continue
        seen.add(pair)
        pairs.append(pair)
    return pairs


@lru_cache(maxsize=1)
def load_default_creds() -> tuple[tuple[str, str], ...]:
    cache = db_dir() / "seclists-default-creds.csv"
    text: str | None = None
    if cache.is_file():
        try:
            text = cache.read_text("utf-8")
        except OSError:
            text = None
    if text is None:
        try:
            text = _download_creds()
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(text, encoding="utf-8")
        except (OSError, ValueError):
            text = None
    combined: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for pair in (*_BUILTIN_CREDS, *(_parse_creds_csv(text) if text else [])):
        if pair not in seen:
            seen.add(pair)
            combined.append(pair)
    return tuple(combined)


_RTSP_PORTS: frozenset[int] = frozenset({554, 8554})


def _http_ports(scan: PortScan | None) -> list[tuple[int, bool]]:
    if scan is None:
        return []
    out: list[tuple[int, bool]] = []
    for port in scan.ports:
        service = (port.service or "").lower()
        if port.port in (443, 8443, 2083) or "https" in service or "ssl" in service:
            out.append((port.port, True))
        elif (
            "http" in service
            or port.port in (80, 8080, 8000, 8081, 8888, 9000, 631, 7547)
            or port.port in _RTSP_PORTS
            or "rtsp" in service
        ):
            out.append((port.port, False))
    return out


def _looks_like_device(realm: str, server: str) -> bool:
    blob = f"{realm} {server}".lower()
    return any(keyword in blob for keyword in _DEVICE_KEYWORDS)


def _is_camera(realm: str, server: str) -> bool:
    blob = f"{realm} {server}".lower()
    return any(keyword in blob for keyword in _CAMERA_KEYWORDS)


async def detect_devices(
    host: str,
    scan: PortScan | None,
    *,
    timeout: float = 6.0,
    insecure: bool = True,
    workers: int = 10,
) -> tuple[list[CredFinding], list[BruteTarget]]:
    ports = _http_ports(scan)
    if not ports:
        return ([], [])
    connector = aiohttp.TCPConnector(ssl=False, limit=max(workers, 1))
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    semaphore = asyncio.Semaphore(max(workers, 1))
    findings: list[CredFinding] = []
    candidates: list[BruteTarget] = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:

        async def probe(port: int, tls: bool) -> None:
            async with semaphore:
                result = await _probe_endpoint(session, host, port, tls)
            if isinstance(result, BruteTarget):
                candidates.append(result)
            elif result is not None:
                findings.append(result)

        await asyncio.gather(*(probe(port, tls) for port, tls in ports))
    findings.sort(key=lambda f: f.target)
    candidates.sort(key=lambda c: (c.host, c.port))
    return (findings, candidates)


async def _probe_endpoint(
    session: aiohttp.ClientSession,
    host: str,
    port: int,
    tls: bool,
) -> CredFinding | BruteTarget | None:
    scheme = "https" if tls else "http"
    url = f"{scheme}://{host}:{port}/"
    target = f"{host}:{port}"
    try:
        async with session.get(url, allow_redirects=False) as resp:
            status = resp.status
            server = resp.headers.get("Server", "")
            realm = resp.headers.get("WWW-Authenticate", "")
    except (aiohttp.ClientError, TimeoutError, OSError):
        return None
    device = _looks_like_device(realm, server) or port in _RTSP_PORTS
    if status != 401:
        if device or _looks_like_device("", server):
            return CredFinding(
                target=target,
                service=f"{scheme} ({server or 'device'})",
                kind="open-no-auth",
                detail=f"HTTP {status} without authentication",
            )
        return None
    if not device:
        return None
    return BruteTarget(
        host=host,
        port=port,
        tls=tls,
        service=f"{scheme} ({server or realm or 'device'})",
        is_camera=_is_camera(realm, server) or port in _RTSP_PORTS,
    )


async def brute_devices(
    targets: list[BruteTarget],
    *,
    timeout: float = 6.0,
    insecure: bool = True,
    workers: int = 10,
    cred_limit: int = 100,
) -> list[CredFinding]:
    if not targets:
        return []
    creds = await asyncio.to_thread(load_default_creds)
    if cred_limit > 0:
        creds = creds[:cred_limit]
    connector = aiohttp.TCPConnector(ssl=False, limit=max(workers, 1))
    client_timeout = aiohttp.ClientTimeout(total=timeout)
    semaphore = asyncio.Semaphore(max(workers, 1))
    findings: list[CredFinding] = []
    async with aiohttp.ClientSession(connector=connector, timeout=client_timeout) as session:

        async def run(target: BruteTarget) -> None:
            async with semaphore:
                hit = await _try_defaults(session, target.url, creds)
            if hit is not None:
                username, password = hit
                findings.append(
                    CredFinding(
                        target=target.target,
                        service=target.service,
                        kind="default-creds",
                        detail="default credentials accepted via HTTP Basic auth",
                        username=username,
                        password=password,
                    )
                )
            else:
                findings.append(
                    CredFinding(
                        target=target.target,
                        service=target.service,
                        kind="auth-required",
                        detail="device auth required; no default credential matched",
                    )
                )

        await asyncio.gather(*(run(target) for target in targets))
    findings.sort(key=lambda f: (f.kind != "default-creds", f.target))
    return findings


async def _try_defaults(
    session: aiohttp.ClientSession, url: str, creds: tuple[tuple[str, str], ...]
) -> tuple[str, str] | None:
    for username, password in creds:
        auth = aiohttp.BasicAuth(username, password)
        try:
            async with session.get(url, auth=auth, allow_redirects=False) as resp:
                if resp.status not in (401, 403):
                    return (username, password)
        except (aiohttp.ClientError, TimeoutError, OSError):
            return None
        await asyncio.sleep(0.05)
    return None
