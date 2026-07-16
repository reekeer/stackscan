from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from stackscan.types import SocialLink

_HREF_RE = re.compile("href\\s*=\\s*[\\\"']([^\\\"'>\\s]+)", re.IGNORECASE)

_SOCIAL_DOMAINS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Twitter/X", ("twitter.com", "x.com")),
    ("Facebook", ("facebook.com", "fb.com", "fb.me")),
    ("Instagram", ("instagram.com",)),
    ("LinkedIn", ("linkedin.com",)),
    ("YouTube", ("youtube.com", "youtu.be")),
    ("GitHub", ("github.com",)),
    ("GitLab", ("gitlab.com",)),
    ("Telegram", ("t.me", "telegram.me")),
    ("TikTok", ("tiktok.com",)),
    ("VK", ("vk.com",)),
    ("Discord", ("discord.gg", "discord.com")),
    ("Reddit", ("reddit.com",)),
    ("Pinterest", ("pinterest.com",)),
    ("Threads", ("threads.net",)),
    ("Mastodon", ("mastodon.social",)),
    ("Medium", ("medium.com",)),
    ("WhatsApp", ("wa.me", "whatsapp.com")),
)

_SHARE_PATHS = frozenset(
    {"share", "sharer", "sharer.php", "intent", "dialog", "home", "widgets", "oauth"}
)


def _social_link(raw: str, base_url: str) -> SocialLink | None:
    value = raw.strip()
    low = value.lower()
    if low.startswith("mailto:"):
        addr = value[7:].split("?", 1)[0].strip()
        if addr and "@" in addr and "." in addr.split("@", 1)[-1]:
            return SocialLink("Email", "mailto:" + addr, addr)
        return None
    if low.startswith("tel:"):
        num = value[4:].strip()
        if sum(char.isdigit() for char in num) >= 6:
            return SocialLink("Phone", value, num)
        return None
    if low.startswith("//"):
        value = "https:" + value
    elif not low.startswith(("http://", "https://")):
        if not base_url:
            return None
        value = urljoin(base_url, value)
    parts = urlsplit(value)
    host = parts.netloc.lower().split("@")[-1].split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    for platform, domains in _SOCIAL_DOMAINS:
        if any(host == domain or host.endswith("." + domain) for domain in domains):
            handle = parts.path.strip("/")
            if handle.split("/", 1)[0].lower() in _SHARE_PATHS:
                return None
            return SocialLink(platform, value.split("#", 1)[0], handle)
    return None


def parse_social(body: str, base_url: str = "") -> list[SocialLink]:
    found: list[SocialLink] = []
    seen: set[tuple[str, str]] = set()
    for raw in _HREF_RE.findall(body):
        link = _social_link(raw, base_url)
        if link is None:
            continue
        key = (link.platform, link.url)
        if key in seen:
            continue
        seen.add(key)
        found.append(link)
    found.sort(key=lambda link: (link.platform.lower(), link.url))
    return found
