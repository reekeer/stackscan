"""URL helpers."""

from __future__ import annotations


def normalize_url(raw: str) -> str:
    if raw.startswith(("http://", "https://")):
        return raw
    return "https://" + raw
