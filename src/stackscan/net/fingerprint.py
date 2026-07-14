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
_DISTRO_TAG_RE = re.compile(
    "(?P<os>(?:ubuntu|debian|centos|rhel|fedora|amzn|raspbian|alpine|rocky|almalinux))"
    "[-_ \\s]?(?P<version>[\\d.]+(?:[\\w._+-]*?)?)",
    re.I,
)


def sanitize_banner(text: str) -> str:
    return "".join(ch for ch in text if 32 <= ord(ch) <= 126).strip()


def extract_distro(text: str) -> str | None:
    lower = text.lower()
    ubuntu_match = re.search(r"(?:\dubuntu|0ubuntu0?[._])(\d[\d.]+)", lower)
    if ubuntu_match:
        return f"Ubuntu {ubuntu_match.group(1)}"
    debian_match = re.search(r"\+?deb(\d+)u?(\d+)?", lower)
    if debian_match:
        return f"Debian {debian_match.group(1)}"
    match = _DISTRO_TAG_RE.search(text)
    if not match:
        return None
    os = match.group("os").strip().title()
    version = match.group("version").strip("-_ ")
    if version:
        return f"{os} {version}"
    return os


def fingerprint_banner(banner: str) -> tuple[str | None, str | None, str | None]:
    clean = sanitize_banner(banner)
    for pattern, service, product in _BANNER_SIGNATURES:
        match = pattern.search(clean)
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


def fingerprint_mysql(data: bytes) -> tuple[str | None, str | None, str | None, bool]:
    if not data or len(data) < 5:
        return (None, None, None, False)
    pkt_type = data[4]
    if pkt_type == 0xFF:
        return (None, None, None, True)
    if pkt_type != 0x0A or len(data) < 6:
        return (None, None, None, False)
    version_end = data.find(0, 5)
    if version_end == -1:
        return (None, None, None, False)
    version_bytes = data[5:version_end]
    version = version_bytes.decode("utf-8", "replace")
    version = version.replace("\x00", "").strip()
    if not version:
        return (None, None, None, False)
    if version.startswith("5.5.5-"):
        version = version[6:]
        product = "MariaDB"
    elif "mariadb" in version.lower():
        product = "MariaDB"
    else:
        product = "MySQL"
    clean_version = version.split("-", 1)[0]
    distro = extract_distro(version)
    return (product, clean_version, distro, False)
