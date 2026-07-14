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
_DISTRO_PATTERNS: tuple[tuple[re.Pattern[str], str, int | None], ...] = (
    (re.compile(r"0ubuntu0[._](\d[\d.]+)", re.I), "Ubuntu", 1),
    (re.compile(r"\bubuntu[-_\s]?(\d[\d._]*)(?!ubuntu)", re.I), "Ubuntu", 1),
    (re.compile(r"\bubuntu\b", re.I), "Ubuntu", None),
    (re.compile(r"\+?deb(\d+)u?(\d+)?", re.I), "Debian", 1),
    (re.compile(r"\bdebian[_-]?(\d[\d._]*)?", re.I), "Debian", 1),
    (re.compile(r"\b(red\s*hat(?:\s*enterprise\s*linux|\s*linux)?|rhel)[-_\s]?(\d[\d._]*)?", re.I), "Red Hat", 2),
    (re.compile(r"\bcentos[-_\s]?(\d[\d._]*)?", re.I), "CentOS", 1),
    (re.compile(r"\bfedora[-_\s]?(\d[\d._]*)?", re.I), "Fedora", 1),
    (re.compile(r"\brocky\s*linux?[-_\s]?(\d[\d._]*)?", re.I), "Rocky Linux", 1),
    (re.compile(r"\balmalinux[-_\s]?(\d[\d._]*)?", re.I), "AlmaLinux", 1),
    (re.compile(r"\balpine[-_\s]?(\d[\d._]*)?", re.I), "Alpine", 1),
    (re.compile(r"\bamazon\s*linux?[-_\s]?(\d[\d._]*)?", re.I), "Amazon Linux", 1),
    (re.compile(r"\bamzn[-_\s]?(\d[\d._]*)?", re.I), "Amazon Linux", 1),
    (re.compile(r"\braspbian[-_\s]?(\d[\d._]*)?", re.I), "Raspbian", 1),
    (re.compile(r"\bsuse\b", re.I), "SUSE", None),
    (re.compile(r"\bopensuse\b", re.I), "openSUSE", None),
    (re.compile(r"\barch\s*linux\b", re.I), "Arch Linux", None),
    (re.compile(r"\bgentoo\b", re.I), "Gentoo", None),
    (re.compile(r"\bslackware\b", re.I), "Slackware", None),
    (re.compile(r"\bel(\d+)\b", re.I), "RHEL/CentOS", 1),
    (re.compile(r"\.fc(\d+)\b", re.I), "Fedora", 1),
    (re.compile(r"~bpo(\d+)\+[\w]+", re.I), "Debian Backports", 1),
)


def sanitize_banner(text: str) -> str:
    return "".join(ch for ch in text if 32 <= ord(ch) <= 126).strip()


def extract_distro(text: str) -> str | None:
    for pattern, name, version_group in _DISTRO_PATTERNS:
        match = pattern.search(text)
        if not match:
            continue
        version = None
        if version_group:
            group = match.group(version_group)
            if group:
                version = group.strip("._- ")
        if version:
            return f"{name} {version}"
        return name
    return None


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
