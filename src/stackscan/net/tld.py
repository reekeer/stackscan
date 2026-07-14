from __future__ import annotations

import re
import urllib.request
from functools import lru_cache
from itertools import product

from stackscan.utils import db_dir

_TLD_URL = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
_TLD_TIMEOUT = 20
_TLD_MAX_BYTES = 2 * 1024 * 1024
_MAX_CANDIDATES = 50000
_FALLBACK_TLDS: tuple[str, ...] = (
    "com",
    "net",
    "org",
    "info",
    "biz",
    "io",
    "co",
    "ru",
    "az",
    "de",
    "fr",
    "uk",
    "us",
    "cn",
    "jp",
    "in",
    "br",
    "it",
    "es",
    "nl",
    "pl",
    "ua",
    "kz",
    "gov",
    "edu",
    "xyz",
    "app",
    "dev",
    "online",
    "site",
    "tech",
    "lol",
    "me",
    "tv",
    "cc",
)
_SLOT_RE = re.compile("^\\*+(\\d*)$")


def _parse_tlds(text: str) -> tuple[str, ...]:
    out: list[str] = []
    for line in text.splitlines():
        line = line.strip().lower()
        if not line or line.startswith("#"):
            continue
        out.append(line)
    return tuple(out)


@lru_cache(maxsize=1)
def load_tlds() -> tuple[str, ...]:
    cache = db_dir() / "iana-tlds.txt"
    if cache.is_file():
        try:
            parsed = _parse_tlds(cache.read_text("utf-8"))
            if parsed:
                return parsed
        except OSError:
            pass
    try:
        request = urllib.request.Request(_TLD_URL, headers={"User-Agent": "stackscan"})
        with urllib.request.urlopen(request, timeout=_TLD_TIMEOUT) as response:
            text = response.read(_TLD_MAX_BYTES).decode("utf-8", "replace")
    except (OSError, ValueError):
        return _FALLBACK_TLDS
    try:
        cache.parent.mkdir(parents=True, exist_ok=True)
        cache.write_text(text, encoding="utf-8")
    except OSError:
        pass
    return _parse_tlds(text) or _FALLBACK_TLDS


def has_wildcard(target: str) -> bool:
    return "*" in target


def _slot_values(spec: str, tlds: tuple[str, ...]) -> list[str]:
    match = _SLOT_RE.match(spec)
    if match is None:
        return [spec]
    length = match.group(1)
    if length:
        n = int(length)
        return [t for t in tlds if len(t) == n]
    return list(tlds)


def expand_wildcard_target(target: str, tlds: tuple[str, ...] | None = None) -> list[str]:
    tlds = tlds if tlds is not None else load_tlds()
    host = target.strip()
    for prefix in ("https://", "http://"):
        if host.startswith(prefix):
            host = host[len(prefix) :]
    host = host.split("/", 1)[0].strip(".").lower()
    if "*" not in host:
        return [host]
    labels = host.split(".")
    per_label = [_slot_values(label, tlds) for label in labels]
    total = 1
    for values in per_label:
        total *= max(len(values), 1)
        if total > _MAX_CANDIDATES:
            break
    out: list[str] = []
    for combo in product(*per_label):
        candidate = ".".join(combo)
        if candidate and "*" not in candidate:
            out.append(candidate)
        if len(out) >= _MAX_CANDIDATES:
            break
    return out
