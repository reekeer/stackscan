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


def _tls_conn(
    host: str, port: int, timeout: float, context: ssl.SSLContext
) -> tuple[dict[str, Any] | None, str | None, tuple[str, str, int] | None, str | None] | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls:
                return (
                    cast("dict[str, Any] | None", tls.getpeercert()),
                    tls.version(),
                    tls.cipher(),
                    tls.selected_alpn_protocol(),
                )
    except (OSError, ssl.SSLError, ValueError):
        return None


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

    insecure_result = _tls_conn(host, port, timeout, insecure_context)
    if insecure_result is None:
        return None
    raw_cert, protocol, cipher_tuple, alpn = insecure_result

    trusted = True
    if not insecure:
        verify_context = ssl.create_default_context()
        try:
            verify_context.set_alpn_protocols(["h2", "http/1.1"])
        except NotImplementedError:
            pass
        verify_result = _tls_conn(host, port, timeout, verify_context)
        if verify_result is None:
            trusted = False
        else:
            raw_cert = verify_result[0] or raw_cert

    cipher = cipher_tuple[0] if cipher_tuple else None
    if not raw_cert:
        return TlsInfo(protocol=protocol, cipher=cipher, alpn=alpn, trusted=trusted)
    return TlsInfo(
        subject=_join_rdn(raw_cert.get("subject")) or None,
        issuer=_join_rdn(raw_cert.get("issuer")) or None,
        subject_alt_names=_subject_alt_names(raw_cert),
        not_before=_as_str(raw_cert.get("notBefore")),
        not_after=_as_str(raw_cert.get("notAfter")),
        protocol=protocol,
        cipher=cipher,
        alpn=alpn,
        trusted=trusted,
    )
