from __future__ import annotations

import base64
import html
import json
from functools import lru_cache
from importlib import resources
from typing import Any
from xml.sax.saxutils import escape

from stackscan import __version__, theme
from stackscan.utils import host_of

Payload = dict[str, Any]


@lru_cache(maxsize=1)
def _logo_data_uri() -> str:
    try:
        raw = resources.files("stackscan.data").joinpath("reekeer-logo.png").read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, OSError):
        return ""
    return "data:image/png;base64," + base64.b64encode(raw).decode("ascii")


def to_json(payload: Payload) -> str:
    return json.dumps(payload, ensure_ascii=False, indent=2)


def build_graph(reports: list[dict[str, Any]]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: set[tuple[str, str, str]] = set()

    def node(nid: str, label: str, type_: str, meta: dict[str, Any] | None = None) -> str:
        if nid not in nodes:
            nodes[nid] = {"id": nid, "label": label, "type": type_, "meta": meta or {}}
        return nid

    def edge(source: str, target: str, relation: str) -> None:
        edges.add((source, target, relation))

    for report in reports:
        url = report.get("final_url") or report.get("url") or "unknown"
        label = url.replace("https://", "").replace("http://", "").split("/")[0]
        target_id = node(
            f"target:{url}", label, "target", {"url": url, "status": report.get("status")}
        )

        network = report.get("network") or {}
        for ip in list(network.get("ipv4") or []) + list(network.get("ipv6") or []):
            ip_id = node(f"ip:{ip}", ip, "ip")
            edge(target_id, ip_id, "resolves_to")

        for sub in report.get("subdomains") or []:
            name = sub.get("name") or ""
            sub_id = node(f"sub:{name}", name, "subdomain", {"source": sub.get("source")})
            edge(target_id, sub_id, "has_subdomain")
            for addr in sub.get("addresses") or []:
                ip_id = node(f"ip:{addr}", addr, "ip")
                edge(sub_id, ip_id, "resolves_to")

        port_scan = report.get("ports") or {}
        for port_info in port_scan.get("ports") or []:
            port_num = port_info.get("port")
            proto = port_info.get("protocol", "tcp")
            port_host = port_info.get("host") or label
            port_id = node(
                f"port:{port_host}:{port_num}/{proto}",
                f"{port_num}/{proto}",
                "port",
                {
                    "service": port_info.get("service"),
                    "product": port_info.get("product"),
                    "version": port_info.get("version"),
                    "host": port_host,
                },
            )
            edge(target_id, port_id, "exposes")

        for cve in report.get("cves") or []:
            cve_id_str = cve.get("id") or "unknown"
            cve_id = node(
                f"cve:{cve_id_str}",
                cve_id_str,
                "cve",
                {"severity": cve.get("severity"), "cvss": cve.get("cvss")},
            )
            edge(target_id, cve_id, "affected_by")

        for svc in report.get("services") or []:
            svc_name = svc.get("name") or "unknown"
            svc_id = node(
                f"service:{url}:{svc_name}",
                svc_name,
                "service",
                {"kind": svc.get("kind"), "severity": svc.get("severity")},
            )
            edge(target_id, svc_id, "runs")

    return {
        "nodes": list(nodes.values()),
        "edges": [{"source": s, "target": t, "relation": r} for s, t, r in edges],
    }


def to_xml(payload: Payload) -> str:
    lines = ['<?xml version="1.0" encoding="UTF-8"?>']
    lines.append("<stackscan>")
    _xml_node(lines, "meta", {k: v for k, v in payload.items() if k != "results"}, 1)
    lines.append("  <results>")
    for report in payload.get("results", []):
        _xml_node(lines, "result", report, 2)
    lines.append("  </results>")
    lines.append("</stackscan>")
    return "\n".join(lines) + "\n"


def _xml_node(lines: list[str], name: str, value: Any, depth: int) -> None:
    pad = "  " * depth
    tag = _xml_tag(name)
    if isinstance(value, dict):
        lines.append(f"{pad}<{tag}>")
        for key, val in value.items():
            _xml_node(lines, str(key), val, depth + 1)
        lines.append(f"{pad}</{tag}>")
    elif isinstance(value, list):
        lines.append(f"{pad}<{tag}>")
        for item in value:
            _xml_node(lines, "item", item, depth + 1)
        lines.append(f"{pad}</{tag}>")
    elif value is None:
        lines.append(f"{pad}<{tag}/>")
    else:
        lines.append(f"{pad}<{tag}>{escape(str(value))}</{tag}>")


def _xml_tag(name: str) -> str:
    tag = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in name)
    if not tag or tag[0].isdigit():
        tag = f"_{tag}"
    return tag


def to_html(payload: Payload) -> str:
    reports: list[dict[str, Any]] = payload.get("results", [])
    cards = "\n".join(_html_card(r) for r in reports)
    graph = _html_graph(reports)
    generated = html.escape(str(payload.get("generated_at", "")))
    elapsed = payload.get("elapsed_seconds", 0)
    logo = _logo_data_uri()
    logo_img = f'<img class="brand-icon" src="{logo}" alt="reekeer">' if logo else ""
    return _HTML_TEMPLATE.format(
        css=_CSS,
        logo=logo_img,
        credit=html.escape(theme.CREDIT),
        version=html.escape(__version__),
        generated=generated,
        elapsed=elapsed,
        count=len(reports),
        graph=graph,
        cards=cards,
    )


def _e(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _chips(items: list[Any], cls: str = "chip") -> str:
    return "".join(f'<span class="{cls}">{_e(i)}</span>' for i in items if i)


def _kv(label: str, value: str) -> str:
    return f'<div class="kv"><span class="k">{_e(label)}</span><span class="v">{value}</span></div>'


def _section(title: str, body: str) -> str:
    if not body:
        return ""
    return f"<section><h3>{_e(title)}</h3>{body}</section>"


def _html_card(r: dict[str, Any]) -> str:
    host = _e(r.get("final_url") or r.get("url"))
    status = r.get("status")
    if r.get("error") and status is None:
        badge = '<span class="badge bad">unavailable</span>'
    else:
        badge = f'<span class="badge ok">{_e(status)}</span>'
    elapsed = r.get("elapsed")
    meta = f"{elapsed:.2f}s" if isinstance(elapsed, (int, float)) else ""
    body_parts: list[str] = []
    net = r.get("network") or {}
    if net:
        rows = []
        for label, key in (
            ("IPv4", "ipv4"),
            ("IPv6", "ipv6"),
            ("MX", "mx"),
            ("NS", "ns"),
            ("TXT", "txt"),
            ("CNAME", "cname"),
            ("SOA", "soa"),
            ("CAA", "caa"),
        ):
            vals = net.get(key) or []
            if vals:
                rows.append(_kv(label, _chips(vals)))
        for rrtype, vals in sorted((net.get("extras") or {}).items()):
            if vals:
                rows.append(_kv(rrtype, _chips(vals)))
        domains = net.get("domains") or []
        if domains:
            rows.append(_kv("Domains", _chips(sorted(set(domains)))))
        body_parts.append(_section("Network / DNS", "".join(rows)))
    whois = r.get("whois") or {}
    if whois:
        registrar = whois.get("registrar") or ""
        if registrar and whois.get("registrar_url"):
            registrar += f" · {whois['registrar_url']}"
        rows = _kv("Registrar", _e(registrar)) if registrar else ""
        if whois.get("registrant_public") and whois.get("registrant"):
            rows += _kv("Registrant", _e(whois["registrant"]))
        elif whois.get("privacy"):
            rows += _kv("Registrant", _e(whois["privacy"]))
        dates = []
        if whois.get("created"):
            dates.append(f"registered {_e(str(whois['created'])[:10])}")
        if whois.get("updated"):
            dates.append(f"updated {_e(str(whois['updated'])[:10])}")
        if whois.get("expires"):
            dates.append(f"expires {_e(str(whois['expires'])[:10])}")
        if dates:
            rows += _kv("Dates", " · ".join(dates))
        if whois.get("nameservers"):
            rows += _kv("Nameservers", _chips(whois["nameservers"]))
        if whois.get("dnssec"):
            rows += _kv("DNSSEC", _e(whois["dnssec"]))
        if whois.get("statuses"):
            rows += _kv("Status", _e(", ".join(whois["statuses"])))
        if rows:
            body_parts.append(_section("Registration (WHOIS)", rows))
    ipinfo = r.get("ip_info") or []
    if ipinfo:
        rows = "".join(
            _kv(
                _e(i.get("ip")),
                _e(", ".join(x for x in (i.get("city"), i.get("country")) if x))
                + f" · {_e(i.get('org') or i.get('isp') or '')}"
                + (f" · {_e(i.get('asn'))}" if i.get("asn") else "")
                + (" · CDN/proxy" if i.get("is_cdn") else "")
                + (f" · source: {_e(i.get('source'))}" if i.get("source") else ""),
            )
            for i in ipinfo
        )
        body_parts.append(_section("IP intelligence", rows))
    protocols = r.get("protocols") or []
    if protocols:
        body_parts.append(_section("Protocol", _chips(protocols)))
    tls = r.get("tls") or {}
    if tls:
        tls_rows = ""
        if tls.get("issuer"):
            tls_rows += _kv("Issuer", _e(tls["issuer"]))
        if tls.get("not_after"):
            tls_rows += _kv("Valid until", _e(tls["not_after"]))
        if tls.get("alpn"):
            tls_rows += _kv("ALPN", _e(tls["alpn"]))
        body_parts.append(_section("TLS", tls_rows))
    techs = r.get("technologies") or []
    if techs:
        by_cat: dict[str, list[str]] = {}
        for t in techs:
            cats = t.get("categories") or ["uncategorized"]
            for c in cats:
                label = t.get("name", "")
                loc = t.get("location")
                if loc and loc != host_of(r.get("url") or ""):
                    label += f" @{loc}"
                conf = t.get("confidence")
                if isinstance(conf, int):
                    label += f" ({conf}%)"
                by_cat.setdefault(c, []).append(label)
        rows = "".join(
            (_kv(cat, _chips(sorted(set(names)))) for cat, names in sorted(by_cat.items()))
        )
        body_parts.append(_section("Technologies", rows))
    services = r.get("services") or []
    if services:
        rows = "".join(
            f"<tr><td>{_e(s.get('name'))}</td><td>{_e(s.get('kind'))}</td>"
            f'<td><span class="sev sev-{_e((s.get("severity") or "info").lower())}">'
            f"{_e(s.get('severity'))}</span></td><td>{_e(s.get('evidence'))}</td></tr>"
            for s in services
        )
        body_parts.append(
            _section(
                "Services",
                f"<table><thead><tr><th>Service</th><th>Kind</th><th>Severity</th><th>Evidence</th></tr></thead><tbody>{rows}</tbody></table>",
            )
        )
    software = r.get("software") or []
    if software:
        names = [f"{s.get('name')} {s.get('version')}".strip() for s in software]
        body_parts.append(_section("Software", _chips(list(dict.fromkeys(names)))))
    cves = r.get("cves") or []
    if cves:
        rows = "".join(_html_cve_row(c) for c in cves)
        body_parts.append(
            _section(
                "Vulnerabilities (CVE)",
                f'<table class="cve"><thead><tr><th>Severity</th><th>CVE</th><th>Affects</th><th>Source</th><th>Confidence</th><th>Summary</th></tr></thead><tbody>{rows}</tbody></table>',
            )
        )
    ports = r.get("ports") or {}
    plist = ports.get("ports") or []
    if plist:
        rows = "".join(
            f"<tr><td>{_e(p.get('port'))}/{_e(p.get('protocol'))}</td>"
            f"<td>{_e(p.get('host'))}</td><td>{_e(p.get('service'))}</td>"
            f"<td>{_e(' '.join(x for x in (p.get('product'), p.get('version')) if x))}</td></tr>"
            for p in plist
        )
        body_parts.append(
            _section(
                "Open ports",
                f"<table><thead><tr><th>Port</th><th>Host</th><th>Service</th><th>Product</th></tr></thead><tbody>{rows}</tbody></table>",
            )
        )
    creds = r.get("creds") or []
    if creds:
        rows = "".join(_html_cred_row(c) for c in creds)
        body_parts.append(
            _section("Default creds / open devices", f'<div class="creds">{rows}</div>')
        )
    subs = r.get("subdomains") or []
    if subs:
        rows = "".join(
            _kv(_e(s.get("name")), _e(", ".join(s.get("addresses") or []))) for s in subs
        )
        body_parts.append(_section(f"Subdomains ({len(subs)})", rows))
    exp = r.get("exposure") or {}
    exp_flags = [k for k in ("git_exposed", "robots_txt", "sitemap", "security_txt") if exp.get(k)]
    if exp_flags:
        body_parts.append(_section("Exposure", _chips(exp_flags)))
    social = r.get("social") or []
    if social:
        rows = "".join(
            _kv(
                _e(s.get("platform")),
                f'<a href="{_e(s.get("url"))}">{_e(s.get("url"))}</a>',
            )
            for s in social
        )
        body_parts.append(_section("Social & contacts", rows))
    danger = any((c.get("severity") or "").upper() in ("CRITICAL", "HIGH") for c in cves) or any(
        c.get("kind") in ("default-creds", "open-no-auth") for c in creds
    )
    cls = "card danger" if danger else "card"
    return f"""<article class="{cls}"><header><h2>{host}</h2><div class="badges">{badge}<span class="meta">{_e(meta)}</span></div></header>{"".join(body_parts)}</article>"""


def _html_cve_row(c: dict[str, Any]) -> str:
    sev = (c.get("severity") or "UNKNOWN").upper()
    cvss = c.get("cvss")
    sev_label = f"{sev} {cvss:.1f}" if isinstance(cvss, (int, float)) else sev
    conf = int(c.get("confidence") or 0)
    affects = f"{c.get('product')} {c.get('version') or ''}".strip()
    if c.get("unconfirmed"):
        affects += " · unconfirmed · version-only"
    sources = ", ".join(c.get("sources") or ())
    summary = c.get("summary") or ""
    caveat = c.get("caveat")
    if caveat:
        summary = f"{caveat} — {summary}"
    return f"""<tr><td><span class="sev sev-{sev.lower()}">{_e(sev_label)}</span></td><td>{_e(c.get("id"))}</td><td>{_e(affects)}</td><td>{_e(sources) or "-"}</td><td><div class="bar"><span style="width:{conf}%"></span></div>{conf}%</td><td class="sum">{_e(summary)}</td></tr>"""


def _html_cred_row(c: dict[str, Any]) -> str:
    kind = c.get("kind")
    if kind == "default-creds":
        tag = f"""<span class="sev sev-critical">DEFAULT {_e(c.get("username"))}:{_e(c.get("password"))}</span>"""
    elif kind == "open-no-auth":
        tag = '<span class="sev sev-critical">OPEN / NO AUTH</span>'
    else:
        tag = '<span class="chip">auth required</span>'
    return f"""<div class="kv"><span class="k">{_e(c.get("target"))}</span><span class="v">{tag} {_e(c.get("detail"))}</span></div>"""


def _html_graph(reports: list[dict[str, Any]]) -> str:
    graph = build_graph(reports)
    if not graph["edges"]:
        return ""

    type_color = {
        "target": theme.ACCENT,
        "subdomain": theme.ACCENT_2,
        "ip": theme.SUCCESS,
        "port": theme.WARN,
        "cve": theme.DANGER,
        "service": theme.ACCENT_SOFT,
    }
    present_types = sorted(
        {n["type"] for n in graph["nodes"]},
        key=lambda t: ["target", "subdomain", "ip", "port", "service", "cve"].index(t),
    )
    if len(present_types) < 2:
        return ""

    graph_json = json.dumps(
        {
            "nodes": [
                {
                    "id": n["id"],
                    "label": _short(n["label"]),
                    "type": n["type"],
                    "color": type_color.get(n["type"], theme.TEXT),
                    "meta": n.get("meta") or {},
                }
                for n in graph["nodes"]
            ],
            "edges": graph["edges"],
        },
        ensure_ascii=False,
    )

    legend_items = "".join(
        f'<span class="graph-legend-item"><span class="graph-legend-dot" style="background:{type_color[t]}"></span>{t}</span>'
        for t in present_types
    )

    graph_html = f"""<div class="graph-wrap">
<svg id="netgraph" class="graph" xmlns="http://www.w3.org/2000/svg">
  <g class="graph-viewport"><g class="edges"></g><g class="nodes"></g></g>
</svg>
<div class="graph-tooltip"></div>
<div class="graph-legend">{legend_items}</div>
</div>
<script>
(function(){{
  const colors = {json.dumps(type_color)};
  const data = {graph_json};
  const svg = document.getElementById('netgraph');
  const viewport = svg.querySelector('.graph-viewport');
  const edgesG = svg.querySelector('.edges');
  const nodesG = svg.querySelector('.nodes');
  const tooltip = svg.parentNode.querySelector('.graph-tooltip');
  const width = svg.clientWidth || 960;
  const height = 500;
  svg.setAttribute('viewBox', `0 0 ${{width}} ${{height}}`);

  data.nodes.forEach(n => {{
    n.x = width/2 + (Math.random()-0.5)*width*0.4;
    n.y = height/2 + (Math.random()-0.5)*height*0.4;
    n.vx = 0; n.vy = 0;
  }});

  const nodeById = {{}};
  data.nodes.forEach(n => nodeById[n.id] = n);

  function createElements() {{
    data.edges.forEach(e => {{
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'line');
      line.setAttribute('stroke', '{theme.BORDER}');
      line.setAttribute('stroke-opacity', '0.55');
      line.setAttribute('stroke-width', '1');
      line.dataset.source = e.source;
      line.dataset.target = e.target;
      edgesG.appendChild(line);
    }});
    data.nodes.forEach(n => {{
      const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
      g.style.cursor = 'grab';
      const circle = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
      circle.setAttribute('r', 6);
      circle.setAttribute('fill', n.color);
      circle.setAttribute('stroke', '{theme.BG}');
      circle.setAttribute('stroke-width', 2);
      const text = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      text.textContent = n.label;
      text.setAttribute('fill', '{theme.TEXT}');
      text.setAttribute('font-size', '12');
      text.setAttribute('dy', 4);
      text.setAttribute('dx', 10);
      g.appendChild(circle);
      g.appendChild(text);
      g.addEventListener('mouseenter', ev => showTip(ev, n));
      g.addEventListener('mouseleave', hideTip);
      g.addEventListener('mousedown', ev => startDrag(ev, n, g));
      g.dataset.id = n.id;
      nodesG.appendChild(g);
    }});
  }}

  function showTip(ev, n) {{
    const meta = Object.entries(n.meta || {{}}).map(([k,v]) => `${{k}}: ${{v}}`).join('<br>');
    tooltip.innerHTML = `<strong>${{n.label}}</strong> (${{n.type}})${{meta ? '<br>' + meta : ''}}`;
    tooltip.style.opacity = 1;
    moveTip(ev);
  }}
  function moveTip(ev) {{
    const rect = svg.getBoundingClientRect();
    tooltip.style.left = (ev.clientX - rect.left + 12) + 'px';
    tooltip.style.top = (ev.clientY - rect.top + 12) + 'px';
  }}
  function hideTip() {{ tooltip.style.opacity = 0; }}

  let dragged = null;
  let dragG = null;
  function startDrag(ev, n, g) {{
    dragged = n; dragG = g; g.style.cursor = 'grabbing';
    ev.preventDefault();
  }}
  svg.addEventListener('mousemove', ev => {{
    if (dragged) {{
      const pt = svg.createSVGPoint();
      pt.x = ev.clientX; pt.y = ev.clientY;
      const loc = pt.matrixTransform(viewport.getCTM().inverse());
      dragged.x = loc.x; dragged.y = loc.y; dragged.vx = 0; dragged.vy = 0;
    }} else if (panning) {{
      pan.x += ev.movementX; pan.y += ev.movementY;
      updateTransform();
    }}
    if (tooltip.style.opacity === '1') moveTip(ev);
  }});
  window.addEventListener('mouseup', () => {{
    if (dragG) dragG.style.cursor = 'grab';
    dragged = null; dragG = null; panning = false;
  }});

  let pan = {{x:0, y:0}};
  let panning = false;
  svg.addEventListener('mousedown', ev => {{
    if (ev.target === svg || ev.target === viewport || ev.target === edgesG) {{
      panning = true; ev.preventDefault();
    }}
  }});
  svg.addEventListener('wheel', ev => {{
    ev.preventDefault();
    const s = ev.deltaY > 0 ? 0.9 : 1.1;
    pan.k = (pan.k || 1) * s;
    updateTransform();
  }}, {{passive: false}});
  function updateTransform() {{
    viewport.setAttribute('transform', `translate(${{pan.x}},${{pan.y}}) scale(${{pan.k || 1}})`);
  }}

  function tick() {{
    for (let i = 0; i < data.nodes.length; i++) {{
      const a = data.nodes[i];
      for (let j = i+1; j < data.nodes.length; j++) {{
        const b = data.nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx*dx + dy*dy || 1;
        let f = 8000 / d2;
        let d = Math.sqrt(d2);
        dx /= d; dy /= d;
        if (dragged !== a) {{ a.vx += dx*f; a.vy += dy*f; }}
        if (dragged !== b) {{ b.vx -= dx*f; b.vy -= dy*f; }}
      }}
    }}
    data.edges.forEach(e => {{
      const a = nodeById[e.source], b = nodeById[e.target];
      if (!a || !b) return;
      let dx = b.x - a.x, dy = b.y - a.y;
      let d = Math.sqrt(dx*dx + dy*dy) || 1;
      let f = (d - 80) * 0.003;
      dx /= d; dy /= d;
      if (dragged !== a) {{ a.vx += dx*f; a.vy += dy*f; }}
      if (dragged !== b) {{ b.vx -= dx*f; b.vy -= dy*f; }}
    }});
    data.nodes.forEach(n => {{
      if (n === dragged) return;
      n.vx += (width/2 - n.x) * 0.0003;
      n.vy += (height/2 - n.y) * 0.0003;
      n.vx *= 0.92; n.vy *= 0.92;
      n.x += n.vx; n.y += n.vy;
      n.x = Math.max(20, Math.min(width-20, n.x));
      n.y = Math.max(20, Math.min(height-20, n.y));
    }});

    data.nodes.forEach(n => {{
      const g = nodesG.querySelector(`[data-id="${{n.id}}"]`);
      if (g) g.setAttribute('transform', `translate(${{n.x}},${{n.y}})`);
    }});
    Array.from(edgesG.children).forEach(line => {{
      const a = nodeById[line.dataset.source];
      const b = nodeById[line.dataset.target];
      if (!a || !b) return;
      line.setAttribute('x1', a.x); line.setAttribute('y1', a.y);
      line.setAttribute('x2', b.x); line.setAttribute('y2', b.y);
    }});
    requestAnimationFrame(tick);
  }}

  createElements();
  tick();
}})();
</script>"""
    return _section("Network graph", graph_html)


def _short(label: str) -> str:
    label = label.replace("https://", "").replace("http://", "").rstrip("/")
    return label if len(label) <= 28 else label[:27] + "…"


_CSS = f"\n:root {{ color-scheme: dark; }}\n* {{ box-sizing: border-box; }}\nbody {{ margin:0; background:{theme.BG}; color:{theme.TEXT};\n  font-family: ui-monospace, SFMono-Regular, Menlo, monospace; padding:32px; }}\na {{ color:{theme.ACCENT}; }}\n.brand {{ max-width:1000px; margin:0 auto 24px; display:flex; align-items:center; gap:12px; }}\n.brand-icon {{ flex:0 0 auto; width:48px; height:48px; object-fit:cover;\n  border-radius:50%; background:{theme.BG_SOFT}; border:1px solid {theme.BORDER};\n  box-shadow:0 8px 20px rgba(125,120,234,0.30); }}\n.brand-copy strong {{ display:block; font-size:22px; letter-spacing:0.01em; white-space:nowrap;\n  color:{theme.TEXT}; font-weight:800; }}\n.brand-copy sup {{ margin-left:6px; font-size:11px; font-weight:600; letter-spacing:0.16em;\n  text-transform:lowercase; color:{theme.ACCENT}; vertical-align:super; }}\n.brand-sub {{ color:{theme.MUTED}; font-size:12px; margin-top:2px; }}\n.credit {{ max-width:1000px; margin:28px auto 0; color:{theme.MUTED}; font-size:12px;\n  text-align:center; border-top:1px solid {theme.BORDER}; padding-top:14px; }}\n.wrap {{ max-width:1000px; margin:0 auto; display:flex; flex-direction:column; gap:20px; }}\n.card {{ background:{theme.BG_PANEL}; border:1px solid {theme.BORDER};\n  border-radius:14px; padding:20px 24px; }}\n.card.danger {{ border-color:{theme.DANGER}; box-shadow:0 0 0 1px {theme.DANGER}22; }}\n.card header {{ display:flex; justify-content:space-between; align-items:center;\n  gap:12px; flex-wrap:wrap; border-bottom:1px solid {theme.BORDER}; padding-bottom:12px; }}\n.card h2 {{ margin:0; font-size:18px; word-break:break-all; }}\n.badges {{ display:flex; gap:8px; align-items:center; }}\n.badge {{ padding:2px 10px; border-radius:999px; font-size:12px; font-weight:700; }}\n.badge.ok {{ background:{theme.SUCCESS}22; color:{theme.SUCCESS}; }}\n.badge.bad {{ background:{theme.DANGER}22; color:{theme.DANGER}; }}\n.meta {{ color:{theme.MUTED}; font-size:12px; }}\nsection {{ margin-top:16px; }}\nsection h3 {{ color:{theme.ACCENT_2}; font-size:13px; text-transform:uppercase;\n  letter-spacing:1px; margin:0 0 8px; }}\n.kv {{ display:flex; gap:12px; padding:3px 0; font-size:13px; align-items:baseline; }}\n.kv .k {{ color:{theme.ACCENT}; min-width:120px; text-align:right; font-weight:700; }}\n.kv .v {{ color:{theme.TEXT}; word-break:break-word; }}\n.chip {{ display:inline-block; background:{theme.BG_SOFT}; border:1px solid {theme.BORDER};\n  color:{theme.TEXT}; border-radius:6px; padding:1px 8px; margin:2px; font-size:12px; }}\ntable {{ width:100%; border-collapse:collapse; font-size:12px; }}\nth {{ text-align:left; color:{theme.MUTED}; font-weight:600; padding:4px 8px;\n  border-bottom:1px solid {theme.BORDER}; }}\ntd {{ padding:5px 8px; border-bottom:1px solid {theme.BORDER}22; vertical-align:top; }}\n.sum {{ color:{theme.MUTED}; }}\n.sev {{ padding:1px 7px; border-radius:5px; font-weight:700; white-space:nowrap; }}\n.sev-critical {{ background:{theme.DANGER}; color:#111; }}\n.sev-high {{ background:{theme.SEVERITY['HIGH']}; color:#111; }}\n.sev-medium {{ background:{theme.WARN}; color:#111; }}\n.sev-low {{ background:{theme.ACCENT_SOFT}; color:#111; }}\n.bar {{ display:inline-block; width:80px; height:7px; border-radius:4px;\n  background:{theme.BG_SOFT}; overflow:hidden; margin-right:6px; vertical-align:middle; }}\n.bar span {{ display:block; height:100%; background:linear-gradient(90deg,{theme.ACCENT},{theme.ACCENT_SOFT}); }}\n.graph {{ width:100%; height:500px; cursor:grab; }}\n.graph-wrap {{ position:relative; background:{theme.BG_SOFT}; border:1px solid {theme.BORDER}; border-radius:10px; overflow:hidden; }}\n.graph:active {{ cursor:grabbing; }}\n.graph-legend {{ display:flex; flex-wrap:wrap; gap:12px; margin-top:12px; }}\n.graph-legend-item {{ display:flex; align-items:center; gap:6px; font-size:12px; color:{theme.MUTED}; text-transform:capitalize; }}\n.graph-legend-dot {{ width:10px; height:10px; border-radius:50%; }}\n.graph-tooltip {{ position:absolute; pointer-events:none; background:{theme.BG_PANEL}; border:1px solid {theme.BORDER}; border-radius:6px; padding:6px 10px; font-size:12px; color:{theme.TEXT}; opacity:0; transition:opacity 0.15s; z-index:10; max-width:260px; }}\n"
_HTML_TEMPLATE = '<!doctype html>\n<html lang="en"><head><meta charset="utf-8">\n<meta name="viewport" content="width=device-width, initial-scale=1">\n<title>reekeer report</title>\n<meta name="generator" content="reekeer/stackscan" \n<style>{css}</style></head>\n<body>\n<header class="brand">\n  {logo}\n  <div class="brand-copy">\n    <strong>reekeer<sup>report</sup></strong>\n    <div class="brand-sub">stackscan · {count} target(s) · {elapsed}s · {generated}</div>\n  </div>\n</header>\n<div class="wrap">\n{graph}\n{cards}\n</div>\n<footer class="credit">{credit} · v{version}</footer>\n</body></html>\n'
