from __future__ import annotations

import sys
from dataclasses import dataclass
from typing import Any

BG = "#050713"
BG_SOFT = "#0c1024"
BG_PANEL = "#0b1026"
TEXT = "#f5f7ff"
MUTED = "#9aa3c7"
ACCENT = "#7d78ea"
ACCENT_2 = "#a855f7"
ACCENT_SOFT = "#c3bef6"
DANGER = "#fb7185"
WARN = "#fbbf24"
SUCCESS = "#34d399"
BORDER = "#1c2140"
CREDIT = "Created by reekeer · https://github.com/reekeer/stackscan"
SEVERITY = {
    "CRITICAL": DANGER,
    "HIGH": "#fb923c",
    "MEDIUM": WARN,
    "LOW": ACCENT_SOFT,
    "NONE": MUTED,
    "UNKNOWN": MUTED,
}


@dataclass(frozen=True)
class Glyphs:
    unicode: bool
    arrow: str
    section: str
    bullet: str
    ok: str
    warn: str
    err: str
    info: str
    ask: str
    done: str


_ASCII = Glyphs(False, "->", ">", "-", "[+]", "[!]", "[x]", "[*]", "[?]", "*")
_UNICODE = Glyphs(True, "→", "▸", "·", "✅", "⚠️", "❌", "ℹ️", "❓", "\U0001f680")


def supports_unicode(console: Any | None = None) -> bool:
    encoding = getattr(console, "encoding", None) if console is not None else None
    if not encoding:
        encoding = getattr(sys.stdout, "encoding", None) or ""
    encoding = str(encoding).lower()
    if "utf" in encoding:
        return True
    try:
        "→▸✅".encode(encoding or "ascii")
        return True
    except (UnicodeEncodeError, LookupError):
        return False


def glyphs(console: Any | None = None) -> Glyphs:
    return _UNICODE if supports_unicode(console) else _ASCII
