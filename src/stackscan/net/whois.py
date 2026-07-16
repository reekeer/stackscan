from __future__ import annotations

from typing import Any, cast

from stackscan.net.tld import registrable_domain
from stackscan.types import WhoisInfo

_RDAP_ENDPOINT = "https://rdap.org/domain/"
_RDAP_TIMEOUT = 12.0
_PRIVACY_MARKERS: tuple[str, ...] = (
    "privacy",
    "redacted",
    "whoisguard",
    "contact privacy",
    "domains by proxy",
    "perfect privacy",
    "withheld",
    "identity protection",
    "data protected",
    "not disclosed",
    "private by design",
    "withheldforprivacy",
    "gdpr",
    "obscured",
    "protection service",
)


async def lookup_whois(host: str, *, timeout: float = _RDAP_TIMEOUT) -> WhoisInfo | None:
    domain = registrable_domain(host)
    if not domain or "." not in domain:
        return None
    import aiohttp

    client_timeout = aiohttp.ClientTimeout(total=timeout)
    try:
        async with aiohttp.ClientSession(timeout=client_timeout) as session:
            async with session.get(
                _RDAP_ENDPOINT + domain,
                headers={"User-Agent": "stackscan", "Accept": "application/rdap+json"},
            ) as resp:
                if resp.status != 200:
                    return None
                data = cast("dict[str, Any]", await resp.json(content_type=None))
    except (aiohttp.ClientError, TimeoutError, ValueError, OSError):
        return None
    return _parse_rdap(domain, data)


def _vcard(entity: dict[str, Any] | None) -> dict[str, str]:
    if not entity:
        return {}
    arr = entity.get("vcardArray")
    if not isinstance(arr, list) or len(cast("list[Any]", arr)) < 2:
        return {}
    fields = cast("list[Any]", arr)[1]
    if not isinstance(fields, list):
        return {}
    out: dict[str, str] = {}
    for entry in cast("list[Any]", fields):
        if not isinstance(entry, list) or len(cast("list[Any]", entry)) < 4:
            continue
        item = cast("list[Any]", entry)
        key = str(item[0]).lower()
        raw: Any = item[3]
        if isinstance(raw, list):
            text = " ".join(str(part) for part in cast("list[Any]", raw) if part)
        else:
            text = str(raw).strip()
        if text and key not in out:
            out[key] = text
    return out


def _find_role(entities: list[dict[str, Any]], role: str) -> dict[str, Any] | None:
    for entity in entities:
        roles = [str(r).lower() for r in cast("list[Any]", entity.get("roles") or [])]
        if role in roles:
            return entity
    return None


def _registrar_name(entity: dict[str, Any] | None) -> str | None:
    if not entity:
        return None
    vcard = _vcard(entity)
    name = vcard.get("fn") or vcard.get("org")
    if name:
        return name
    handle = entity.get("handle")
    return str(handle) if handle else None


def _registrar_url(entity: dict[str, Any] | None) -> str | None:
    if not entity:
        return None
    url = _vcard(entity).get("url")
    if url:
        return url
    for link in cast("list[dict[str, Any]]", entity.get("links") or []):
        href = link.get("href")
        if href and link.get("rel") in ("about", "self"):
            return str(href)
    return None


def _nameservers(data: dict[str, Any]) -> tuple[str, ...]:
    out: list[str] = []
    for ns in cast("list[dict[str, Any]]", data.get("nameservers") or []):
        name = str(ns.get("ldhName") or ns.get("unicodeName") or "").rstrip(".").lower()
        if name and name not in out:
            out.append(name)
    return tuple(out)


def _dnssec(data: dict[str, Any]) -> str:
    secure = data.get("secureDNS")
    if not isinstance(secure, dict):
        return ""
    signed = cast("dict[str, Any]", secure).get("delegationSigned")
    if signed is True:
        return "signed"
    if signed is False:
        return "unsigned"
    return ""


def _event(events: list[dict[str, Any]], action: str) -> str | None:
    for event in events:
        if str(event.get("eventAction", "")).lower() == action:
            date = event.get("eventDate")
            return str(date) if date else None
    return None


def _privacy(
    registrant_entity: dict[str, Any] | None, registrar: str | None
) -> tuple[bool, str, str | None]:
    if registrant_entity is None:
        return (False, "not published (registrar/registry withholds registrant)", None)
    vcard = _vcard(registrant_entity)
    fn = vcard.get("fn")
    org = vcard.get("org")
    email = vcard.get("email")
    blob = " ".join(part for part in (fn, org, email) if part).lower()
    contact = org or fn or email
    if not blob:
        return (False, "redacted for privacy", None)
    if any(marker in blob for marker in _PRIVACY_MARKERS):
        return (False, f"privacy service ({contact})" if contact else "privacy service", None)
    if registrar and contact and registrar.split(",")[0].lower() in contact.lower():
        return (False, f"registrar-provided privacy ({registrar})", None)
    return (True, "public", contact)


def _parse_rdap(domain: str, data: dict[str, Any]) -> WhoisInfo:
    entities = cast("list[dict[str, Any]]", data.get("entities") or [])
    registrar_entity = _find_role(entities, "registrar")
    registrar = _registrar_name(registrar_entity)
    registrant_entity = _find_role(entities, "registrant")
    events = cast("list[dict[str, Any]]", data.get("events") or [])
    statuses = tuple(str(s) for s in cast("list[Any]", data.get("status") or []))
    public, note, contact = _privacy(registrant_entity, registrar)
    return WhoisInfo(
        domain=domain,
        registrar=registrar,
        registrar_url=_registrar_url(registrar_entity),
        registrant=contact,
        registrant_public=public,
        privacy=note,
        created=_event(events, "registration"),
        updated=_event(events, "last changed"),
        expires=_event(events, "expiration"),
        nameservers=_nameservers(data),
        dnssec=_dnssec(data),
        statuses=statuses,
    )
