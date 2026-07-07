"""TLS certificate inspection over the standard library ``ssl`` module."""

from __future__ import annotations

import socket
import ssl
from typing import Any

from stackscan.types import TlsInfo


def _join_rdn(rdn: Any) -> str:
    parts: list[str] = []
    if not isinstance(rdn, (tuple, list)):
        return ""
    for entry in rdn:  # type: ignore[assignment]
        if isinstance(entry, (tuple, list)):
            for pair in entry:  # type: ignore[assignment]
                if isinstance(pair, (tuple, list)) and len(pair) == 2:
                    parts.append(f"{pair[0]}={pair[1]}")
    return ", ".join(parts)


def fetch_tls_info(host: str, port: int = 443, *, timeout: float = 8.0) -> TlsInfo | None:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                cert = tls.getpeercert()
                protocol = tls.version()
                cipher_tuple = tls.cipher()
    except (OSError, ssl.SSLError, ValueError):
        return None

    if not cert:
        return TlsInfo(protocol=protocol, cipher=cipher_tuple[0] if cipher_tuple else None)

    san: list[str] = []
    for kind, value in cert.get("subjectAltName", ()):  # type: ignore[union-attr]
        if kind == "DNS":
            san.append(str(value))

    return TlsInfo(
        subject=_join_rdn(cert.get("subject")) or None,
        issuer=_join_rdn(cert.get("issuer")) or None,
        subject_alt_names=tuple(san),
        not_before=cert.get("notBefore"),
        not_after=cert.get("notAfter"),
        protocol=protocol,
        cipher=cipher_tuple[0] if cipher_tuple else None,
    )
