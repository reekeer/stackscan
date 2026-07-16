from __future__ import annotations

import re

from stackscan.types import FetchResult
from stackscan.utils import host_of

_BLOCK_HOST_MARKERS: frozenset[str] = frozenset(
    {
        "block.",
        "blocked.",
        "blockpage.",
        "block-page.",
        "zapret.",
        "zapret-info.",
        "warning.",
        "restrict.",
        "restricted.",
        "filter.",
        "filtered.",
        "safekids.",
        "familyfilter.",
        "safesurf.",
        "netfilter.",
        "rkn.",
        "court.",
        "censorship.",
        "censored.",
        "notice.",
        "copyright.",
        "abuse.",
        "phishing.",
        "malware.",
    }
)

_BLOCK_BODY_MARKERS: frozenset[str] = frozenset(
    {
        "доступ ограничен",
        "доступ к сайту запрещен",
        "доступ к ресурсу ограничен",
        "доступ запрещен",
        "сайт заблокирован",
        "запрещенный сайт",
        "сайт ограничен",
        "доступ к информационному ресурсу ограничен",
        "решение суда",
        "роскомнадзор",
        "rkn.gov.ru",
        "запрет",
        "санкции",
        "доступ к сайту ограничен по решению суда",
        "страница блокировки",
        "доступ ограничен по требованию",
        "access to this site has been blocked",
        "access to the site has been blocked",
        "blocked by your internet provider",
        "blocked by your isp",
        "this website has been blocked",
        "this site has been blocked",
        "site blocked",
        "access denied by",
        "blockpage",
        "blocked page",
        "internet filter",
        " parental control",
    }
)

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _title(text: str) -> str:
    match = _TITLE_RE.search(text)
    return match.group(1).lower() if match else ""


def _location_host(location: str) -> str:
    from urllib.parse import urlparse

    parsed = urlparse(location.strip())
    return (parsed.hostname or "").lower()


def _is_same_family(original: str, final: str) -> bool:
    """Return True when final host is the original host or its subdomain."""
    return final == original or final.endswith("." + original)


def _block_message(url: str) -> str:
    host = host_of(url) or url
    return f"[!] Your ISP blocked resource: {host} (skipped)"


def detect_isp_block(url: str, fetched: FetchResult) -> str | None:
    """Detect provider/ISP block pages and return a warning message."""
    original = (host_of(url) or "").lower()
    final = (host_of(fetched.url) or "").lower()
    body = fetched.body.lower()
    title = _title(fetched.body)

    if fetched.status == 451:
        return _block_message(url)

    if title and any(marker in title for marker in _BLOCK_BODY_MARKERS):
        return _block_message(url)

    if final and original and final != original:
        if any(marker in final for marker in _BLOCK_HOST_MARKERS):
            return _block_message(url)

    if any(marker in body for marker in _BLOCK_BODY_MARKERS):
        return _block_message(url)

    # Redirect target (even when not followed) points to a known block host.
    if fetched.status in (301, 302, 307, 308):
        location = (fetched.headers.get("location") or "").lower()
        loc_host = _location_host(location)
        if any(marker in loc_host for marker in _BLOCK_HOST_MARKERS):
            return _block_message(url)

    # External redirect to a non-target host that looks like a block page.
    if fetched.status in (301, 302, 307, 308) and final and original:
        if not _is_same_family(original, final):
            location = (fetched.headers.get("location") or "").lower()
            if any(marker in final for marker in _BLOCK_HOST_MARKERS):
                return _block_message(url)
            if any(marker in location for marker in _BLOCK_HOST_MARKERS):
                return _block_message(url)
            if any(marker in body for marker in _BLOCK_BODY_MARKERS):
                return _block_message(url)

    return None
