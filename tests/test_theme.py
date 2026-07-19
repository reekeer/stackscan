from __future__ import annotations

from stackscan import theme


class _Console:
    def __init__(self, encoding: str) -> None:
        self.encoding = encoding


def test_glyphs_are_ascii_only() -> None:
    for console in (_Console("utf-8"), _Console("ascii"), None):
        g = theme.glyphs(console)
        assert g.unicode is False
        assert g.arrow == "->"
        assert g.section == ">"
        assert g.warn == "[!]"
        assert g.err == "[x]"
        for value in (g.ok, g.warn, g.err, g.info, g.ask, g.done, g.run, g.arrow, g.bullet):
            value.encode("ascii")
