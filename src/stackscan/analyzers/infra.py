"""Heuristic detection of edge infrastructure: CDN, WAF, reverse proxy, server.

These rules only read what a server voluntarily returns in its response headers
and cookies. Nothing here probes, fuzzes, or attempts to bypass a protection --
it is pure interpretation of publicly returned metadata.
"""

from __future__ import annotations

from stackscan.types import Headers, InfraInfo

# (label, header_name, needle). needle=None means "header present is enough";
# otherwise the (lowercased) header value must contain the needle.
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

# Reverse-proxy / origin server software.
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

    # Nginx Proxy Manager fronts apps with OpenResty and typically strips origin
    # headers, so an OpenResty server with no application fingerprint is a strong
    # hint. Not definitive -- reported as a note, not a hard detection.
    if "openresty" in server:
        notes.append("OpenResty edge (commonly Nginx Proxy Manager)")

    # A reverse proxy that reflects the requested host back in a header often
    # indicates virtual-host routing (e.g. Nginx Proxy Manager forwarding by
    # Host). We only flag exact host/subdomain reflection.
    host = host.lower()
    for name, value in headers.items():
        if name == "_raw":
            continue
        low = value.lower()
        if host and (low == host or low.endswith("." + host) or host in low.split()):
            notes.append(f"Header '{name}' reflects requested host (reverse proxy likely)")
            break

    return notes


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

    # Anything acting as a front (CDN/WAF/OpenResty/Traefik/Envoy) is a proxy.
    for label in ("OpenResty", "Envoy", "HAProxy", "Traefik", "Apache Traffic Server"):
        if label in server and label not in proxy:
            proxy.append(label)

    return InfraInfo(
        cdn=tuple(cdn),
        waf=tuple(waf),
        proxy=tuple(proxy),
        server=tuple(server),
        notes=tuple(notes),
    )
