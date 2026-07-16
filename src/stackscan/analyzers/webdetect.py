from __future__ import annotations

from stackscan.types import Headers, Technology

_Signature = tuple[str, str, tuple[str, ...]]
_SERVICE_SIGNATURES: tuple[_Signature, ...] = (
    (
        "Matrix Synapse",
        "admin-panel",
        ("synapse is running", "/_matrix/", "x-matrix", "server: synapse", "org.matrix"),
    ),
    ("Element", "service", ("io.element.web", "element-web", "riot-web", "vector-web")),
    ("MikroTik RouterOS", "admin-panel", ("mikrotik", "routeros", "webfig")),
    ("phpMyAdmin", "admin-panel", ("phpmyadmin", "pma_username")),
    ("Adminer", "admin-panel", ("adminer.org", 'name="auth[server]"')),
    ("Portainer", "admin-panel", ("portainer",)),
    ("Proxmox VE", "admin-panel", ("proxmox", "pvedash")),
    ("Uptime Kuma", "admin-panel", ("uptime kuma", "uptime-kuma")),
    ("Gitea", "admin-panel", ("gitea", "gitea-org")),
    ("Vaultwarden", "admin-panel", ("vaultwarden", "bitwarden_rs")),
)
_MAX_BODY = 200_000


def _blob(headers: Headers, body: str) -> str:
    header_str = " ".join(f"{key}: {value}" for key, value in headers.items() if key != "_raw")
    return (header_str + " " + body[:_MAX_BODY]).lower()


def detect_web_services(headers: Headers, body: str, location: str = "") -> list[Technology]:
    blob = _blob(headers, body)
    out: list[Technology] = []
    seen: set[str] = set()
    for name, category, needles in _SERVICE_SIGNATURES:
        key = name.lower()
        if key in seen:
            continue
        if any(needle in blob for needle in needles):
            seen.add(key)
            out.append(
                Technology(
                    name=name,
                    categories=(category,),
                    evidence=("content",),
                    location=location,
                    confidence=80,
                )
            )
    return out
