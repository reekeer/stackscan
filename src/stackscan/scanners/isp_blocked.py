from __future__ import annotations

from stackscan.types import FetchResult
from stackscan.utils import host_of

_BLOCK_HOST_MARKERS: frozenset[str] = frozenset(
    {
        "block.",
        "blocked.",
        "blockpage.",
        "zapret.",
        "warning.",
        "restrict.",
        "filter.",
        "safekids.",
        "familyfilter.",
        "rkn.",
        "court.",
        "censorship.",
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
        "access to this site has been blocked",
        "blocked by your internet provider",
        "blocked by your isp",
        "this website has been blocked",
    }
)


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

    if fetched.status == 451:
        return _block_message(url)

    if final and original and final != original:
        if any(marker in final for marker in _BLOCK_HOST_MARKERS):
            return _block_message(url)

    if any(marker in body for marker in _BLOCK_BODY_MARKERS):
        return _block_message(url)

    # External redirect to a non-target host that looks like a block page.
    if fetched.status in (301, 302, 307, 308) and final and original:
        if not _is_same_family(original, final):
            if any(marker in final for marker in _BLOCK_HOST_MARKERS):
                return _block_message(url)
            if any(marker in body for marker in _BLOCK_BODY_MARKERS):
                return _block_message(url)

    return None
