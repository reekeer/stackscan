from __future__ import annotations

from collections.abc import Iterable

from stackscan.types import Headers, InfraInfo

_Signature = tuple[str, str, str | None]
CDN_SIGNATURES: tuple[_Signature, ...] = (
    ("Cloudflare", "server", "cloudflare"),
    ("Cloudflare", "cf-ray", None),
    ("Fastly", "x-served-by", "cache-"),
    ("Fastly", "x-fastly-request-id", None),
    ("Akamai", "server", "akamaighost"),
    ("Akamai", "x-akamai-transformed", None),
    ("Amazon CloudFront", "server", "cloudfront"),
    ("Amazon CloudFront", "x-amz-cf-id", None),
    ("Google Cloud", "via", "1.1 google"),
    ("Vercel", "server", "vercel"),
    ("Vercel", "x-vercel-id", None),
    ("Netlify", "server", "netlify"),
    ("Netlify", "x-nf-request-id", None),
    ("BunnyCDN", "server", "bunnycdn"),
    ("KeyCDN", "server", "keycdn"),
    ("Sucuri", "x-sucuri-id", None),
    ("StackPath", "x-hw", None),
)
WAF_SIGNATURES: tuple[_Signature, ...] = (
    ("Cloudflare", "cf-ray", None),
    ("Sucuri", "x-sucuri-id", None),
    ("Sucuri", "server", "sucuri"),
    ("Imperva Incapsula", "x-iinfo", None),
    ("Imperva Incapsula", "x-cdn", "incapsula"),
    ("Akamai", "server", "akamaighost"),
    ("F5 BIG-IP", "server", "big-ip"),
    ("Barracuda", "server", "barracuda"),
    ("AWS WAF", "x-amzn-waf-action", None),
)
SERVER_SIGNATURES: tuple[_Signature, ...] = (
    ("nginx", "server", "nginx"),
    ("Apache", "server", "apache"),
    ("Apache Traffic Server", "server", "atsserver"),
    ("OpenResty", "server", "openresty"),
    ("Caddy", "server", "caddy"),
    ("LiteSpeed", "server", "litespeed"),
    ("Microsoft-IIS", "server", "microsoft-iis"),
    ("Envoy", "server", "envoy"),
    ("HAProxy", "server", "haproxy"),
    ("Traefik", "x-traefik-router", None),
    ("gunicorn", "server", "gunicorn"),
    ("uvicorn", "server", "uvicorn"),
    ("Werkzeug", "server", "werkzeug"),
    ("Jetty", "server", "jetty"),
    ("Tomcat", "server", "tomcat"),
)


def _collect(headers: Headers, signatures: tuple[_Signature, ...]) -> list[str]:
    found: list[str] = []
    for label, name, needle in signatures:
        value = headers.get(name.lower())
        if value is None:
            continue
        if needle is None or needle in value.lower():
            if label not in found:
                found.append(label)
    return found


def _cookie_names(cookies: tuple[str, ...]) -> list[str]:
    names: list[str] = []
    for raw in cookies:
        first = raw.split(";", 1)[0].strip()
        name = first.split("=", 1)[0].strip().lower()
        if name:
            names.append(name)
    return names


def _proxy_notes(headers: Headers, host: str) -> list[str]:
    notes: list[str] = []
    server = (headers.get("server") or "").lower()
    if "via" in headers:
        notes.append(f"Via header present: {headers['via']}")
    if "openresty" in server:
        notes.append("OpenResty edge (commonly Nginx Proxy Manager)")
    host = host.lower()
    for name, value in headers.items():
        if name == "_raw":
            continue
        low = value.lower()
        if host and (low == host or low.endswith("." + host) or host in low.split()):
            notes.append(f"Header '{name}' reflects requested host (reverse proxy likely)")
            break
    return notes


_ROLE_LABEL: dict[str, str] = {"cdn": "CDN", "waf": "WAF", "proxy": "reverse proxy"}
_ROLE_ORDER: tuple[str, ...] = ("cdn", "waf", "proxy")
_ORG_SUFFIXES: tuple[str, ...] = (
    ", inc.",
    ", inc",
    " inc.",
    " inc",
    " llc",
    " ltd",
    " ltd.",
    " gmbh",
    " corporation",
    " technologies",
)


def _canonical_provider(org: str) -> str:
    name = org.strip()
    low = name.lower()
    for suffix in _ORG_SUFFIXES:
        if low.endswith(suffix):
            name = name[: -len(suffix)].strip()
            low = name.lower()
    return name


def summarize_edge(infra: InfraInfo, cdn_orgs: Iterable[str] = (), *, sep: str = " → ") -> str:
    roles: dict[str, list[str]] = {}
    order: list[str] = []
    role_names = {"cdn": infra.cdn, "waf": infra.waf, "proxy": infra.proxy}
    for role in _ROLE_ORDER:
        for name in role_names[role]:
            if name not in roles:
                roles[name] = []
                order.append(name)
            if role not in roles[name]:
                roles[name].append(role)
    for org in cdn_orgs:
        name = _canonical_provider(org)
        if not name:
            continue
        if any(name.lower() in known.lower() or known.lower() in name.lower() for known in roles):
            continue
        roles[name] = ["cdn"]
        order.append(name)
    if not order:
        return ""
    order.sort(key=lambda n: 0 if ({"waf", "proxy"} & set(roles[n])) else 1)
    parts: list[str] = []
    for name in order:
        labels = ", ".join(_ROLE_LABEL[r] for r in _ROLE_ORDER if r in roles[name])
        parts.append(f"{name} ({labels})" if labels else name)
    return sep.join(parts)


def analyze_infra(headers: Headers, cookies: tuple[str, ...], host: str) -> InfraInfo:
    cdn = _collect(headers, CDN_SIGNATURES)
    waf = _collect(headers, WAF_SIGNATURES)
    server = _collect(headers, SERVER_SIGNATURES)
    proxy: list[str] = []
    notes = _proxy_notes(headers, host)
    cookie_names = _cookie_names(cookies)
    if any(name.startswith("bigipserver") for name in cookie_names):
        if "F5 BIG-IP" not in waf:
            waf.append("F5 BIG-IP")
        proxy.append("F5 BIG-IP")
    if "__cfduid" in cookie_names or "__cf_bm" in cookie_names:
        if "Cloudflare" not in cdn:
            cdn.append("Cloudflare")
    for label in ("OpenResty", "Envoy", "HAProxy", "Traefik", "Apache Traffic Server"):
        if label in server and label not in proxy:
            proxy.append(label)
    return InfraInfo(
        cdn=tuple(cdn), waf=tuple(waf), proxy=tuple(proxy), server=tuple(server), notes=tuple(notes)
    )
