from __future__ import annotations

import socket
import ssl
from typing import Any, cast

from stackscan.types import TlsInfo


def _as_str(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _join_rdn(rdn: object) -> str:

    if not isinstance(rdn, (tuple, list)):
        return ""
    parts: list[str] = []
    for rdn_entry in cast("tuple[object, ...]", rdn):
        if not isinstance(rdn_entry, (tuple, list)):
            continue
        for pair in cast("tuple[object, ...]", rdn_entry):
            if isinstance(pair, (tuple, list)) and len(cast("tuple[object, ...]", pair)) == 2:
                key, value = cast("tuple[object, object]", pair)
                parts.append(f"{key}={value}")
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
    insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    insecure_context.check_hostname = False
    insecure_context.verify_mode = ssl.CERT_NONE
    try:
        insecure_context.set_alpn_protocols(["h2", "http/1.1"])
    except NotImplementedError:
        pass
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with insecure_context.wrap_socket(sock, server_hostname=host) as tls:
                raw_cert = tls.getpeercert()
                protocol = tls.version()
                cipher_tuple = tls.cipher()
                alpn = tls.selected_alpn_protocol()
    except (OSError, ssl.SSLError, ValueError):
        return None
    trusted = True
    if not insecure:
        verify_context = ssl.create_default_context()
        try:
            verify_context.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with verify_context.wrap_socket(sock, server_hostname=host) as tls:
                    tls.getpeercert()
        except (OSError, ssl.SSLError, ValueError):
            trusted = False
    cipher = cipher_tuple[0] if cipher_tuple else None
    if not raw_cert:
        return TlsInfo(protocol=protocol, cipher=cipher, alpn=alpn, trusted=trusted)
    cert = cast("dict[str, Any]", raw_cert)
    return TlsInfo(
        subject=_join_rdn(cert.get("subject")) or None,
        issuer=_join_rdn(cert.get("issuer")) or None,
        subject_alt_names=_subject_alt_names(cert),
        not_before=_as_str(cert.get("notBefore")),
        not_after=_as_str(cert.get("notAfter")),
        protocol=protocol,
        cipher=cipher,
        alpn=alpn,
        trusted=trusted,
    )
