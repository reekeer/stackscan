from __future__ import annotations

from stackscan import theme


class _Console:
    def __init__(self, encoding: str) -> None:
        self.encoding = encoding


def test_supports_unicode_by_encoding() -> None:
    assert theme.supports_unicode(_Console("utf-8")) is True
    assert theme.supports_unicode(_Console("UTF-8")) is True
    assert theme.supports_unicode(_Console("ansi_x3.4-1968")) is False
    assert theme.supports_unicode(_Console("ascii")) is False


def test_glyphs_switch_on_capability() -> None:
    unicode = theme.glyphs(_Console("utf-8"))
    ascii_glyphs = theme.glyphs(_Console("ascii"))
    assert unicode.unicode is True
    assert unicode.arrow == "→"
    assert unicode.section == "▸"
    assert ascii_glyphs.unicode is False
    assert ascii_glyphs.arrow == "->"
    assert ascii_glyphs.section == ">"
