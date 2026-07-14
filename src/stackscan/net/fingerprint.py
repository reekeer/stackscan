from __future__ import annotations

import re

_BANNER_SIGNATURES: tuple[tuple[re.Pattern[str], str, str], ...] = (
    (re.compile("SSH-\\d+\\.\\d+-OpenSSH[_-]([\\w.]+)", re.I), "ssh", "OpenSSH"),
    (re.compile("SSH-\\d+\\.\\d+-Dropbear[_-]?([\\w.]+)?", re.I), "ssh", "Dropbear"),
    (re.compile("220[- ].*ProFTPD (\\d[\\w.]+)", re.I), "ftp", "ProFTPD"),
    (re.compile("220[- ].*\\(?vsFTPd (\\d[\\w.]+)\\)?", re.I), "ftp", "vsftpd"),
    (re.compile("220[- ].*Pure-FTPd", re.I), "ftp", "Pure-FTPd"),
    (re.compile("220[- ].*FileZilla Server (\\d[\\w.]+)", re.I), "ftp", "FileZilla"),
    (re.compile("220[- ].*Exim (\\d[\\w.]+)", re.I), "smtp", "Exim"),
    (re.compile("220[- ].*Postfix", re.I), "smtp", "Postfix"),
    (re.compile("220[- ].*Sendmail (\\d[\\w.]+)", re.I), "smtp", "Sendmail"),
    (re.compile("\\+OK.*Dovecot", re.I), "pop3", "Dovecot"),
    (re.compile("\\* OK.*Dovecot", re.I), "imap", "Dovecot"),
    (re.compile("^-ERR|^\\+PONG|^\\$\\d", re.I), "redis", "Redis"),
    (re.compile("RFB (\\d+\\.\\d+)", re.I), "vnc", "VNC"),
)
_HTTP_SERVER_RE = re.compile("^server:\\s*(.+?)\\s*$", re.I | re.M)
_SERVER_TOKEN_RE = re.compile("([A-Za-z][A-Za-z0-9._+-]*?)/([\\w.]+)")


def fingerprint_banner(banner: str) -> tuple[str | None, str | None, str | None]:
    for pattern, service, product in _BANNER_SIGNATURES:
        match = pattern.search(banner)
        if match:
            version = match.group(1) if match.groups() else None
            return (service, product, version)
    return (None, None, None)


def fingerprint_http(raw_response: str) -> tuple[str | None, str | None]:
    match = _HTTP_SERVER_RE.search(raw_response)
    if not match:
        return (None, None)
    server = match.group(1).strip()
    token = _SERVER_TOKEN_RE.search(server)
    if token:
        return (token.group(1), token.group(2))
    return (server, None)
