from __future__ import annotations

from stackscan.analyzers.social import parse_social


def test_parse_social_extracts_known_platforms() -> None:
    body = """
    <a href="https://twitter.com/acme">x</a>
    <a href="https://www.instagram.com/acme_co/">ig</a>
    <a href="https://t.me/acmechannel">tg</a>
    <a href="mailto:hi@acme.test">mail</a>
    <a href="tel:+15551234567">call</a>
    <a href="/about">internal</a>
    <a href="https://facebook.com/sharer/sharer.php?u=x">share</a>
    """
    links = parse_social(body, "https://acme.test")
    by_platform = {link.platform: link for link in links}
    assert by_platform["Twitter/X"].handle == "acme"
    assert by_platform["Instagram"].handle == "acme_co"
    assert by_platform["Telegram"].handle == "acmechannel"
    assert by_platform["Email"].handle == "hi@acme.test"
    assert by_platform["Phone"].handle == "+15551234567"
    assert "Facebook" not in by_platform


def test_parse_social_dedupes_and_ignores_non_social() -> None:
    body = '<a href="https://x.com/acme">a</a><a href="https://x.com/acme">b</a>'
    links = parse_social(body, "https://acme.test")
    assert len(links) == 1
    assert links[0].platform == "Twitter/X"
