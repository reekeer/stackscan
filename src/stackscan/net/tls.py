"""TLS certificate inspection over the standard library ``ssl`` module."""

from __future__ import annotations

import socket
import ssl
from typing import Any, cast

from stackscan.types import TlsInfo


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _join_rdn(rdn: object) -> str:
    """Flatten ssl's nested RDN structure (tuple of tuples of (key, value))."""

    if not isinstance(rdn, (tuple, list)):
        return ""
    parts: list[str] = []
    for entry in cast("tuple[object, ...]", rdn):
        if not isinstance(entry, (tuple, list)):
            continue
        pair = cast("tuple[object, ...]", entry)
        if len(pair) == 2:
            parts.append(f"{pair[0]}={pair[1]}")
    return ", ".join(parts)


def _subject_alt_names(cert: dict[str, Any]) -> tuple[str, ...]:
    san_raw = cert.get("subjectAltName")
    if not isinstance(san_raw, (tuple, list)):
        return ()
    names: list[str] = []
    for entry in cast("tuple[object, ...]", san_raw):
        if not isinstance(entry, (tuple, list)):
            continue
        pair = cast("tuple[object, ...]", entry)
        if len(pair) == 2 and pair[0] == "DNS" and isinstance(pair[1], str):
            names.append(pair[1])
    return tuple(names)


def fetch_tls_info(
    host: str, port: int = 443, *, timeout: float = 8.0, insecure: bool = False
) -> TlsInfo | None:
    # ssl._create_unverified_context is the documented way to disable verification.
    if insecure:
        context = ssl._create_unverified_context()  # pyright: ignore[reportPrivateUsage]
    else:
        context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                raw_cert = tls.getpeercert()
                protocol = tls.version()
                cipher_tuple = tls.cipher()
    except (OSError, ssl.SSLError, ValueError):
        return None

    cipher = cipher_tuple[0] if cipher_tuple else None
    if not raw_cert:
        return TlsInfo(protocol=protocol, cipher=cipher)

    cert = cast("dict[str, Any]", raw_cert)
    return TlsInfo(
        subject=_join_rdn(cert.get("subject")) or None,
        issuer=_join_rdn(cert.get("issuer")) or None,
        subject_alt_names=_subject_alt_names(cert),
        not_before=_as_str(cert.get("notBefore")),
        not_after=_as_str(cert.get("notAfter")),
        protocol=protocol,
        cipher=cipher,
    )
