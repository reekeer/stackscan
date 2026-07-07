# stackscan

Full web **stack analyzer**. Given one or more targets, `stackscan` fetches them
over HTTP(S) and reports:

- **Technologies** — CMS, frameworks, languages, libraries, analytics, etc.,
  matched against one or more [sigdb](https://github.com/reekeer/sigdb)
  signature databases (headers, cookies, `<meta>`, `<script src>`, HTML).
- **Edge infrastructure** — what sits in front of the origin: CDN (Cloudflare,
  Fastly, Akamai, CloudFront, …), WAF (Cloudflare, Sucuri, Incapsula, F5, …),
  reverse proxy / server software (nginx, OpenResty / Nginx Proxy Manager,
  Caddy, Traefik, Envoy, IIS, …).
- **Network** — resolved IPv4/IPv6, reverse DNS, optional CNAME chain, and
  optional offline IP geolocation.
- **TLS** — certificate subject/issuer, SANs, validity window, protocol/cipher.
- **Security headers** — which hardening headers are present or missing.
- **Exposure** — passively observed public resources (`robots.txt`,
  `sitemap.xml`, `security.txt`) and accidental `.git` exposure.

Everything stackscan does is a read of what a server voluntarily returns to any
client. It never authenticates, fuzzes, brute-forces, or attempts to bypass a
protection — it only interprets public responses.

## Install

```bash
pip install "stackscan @ git+https://github.com/reekeer/stackscan.git"

# optional extras
pip install "stackscan[dns]"   # CNAME chains via dnspython
pip install "stackscan[geo]"   # IP geolocation via geoip2 + a MaxMind .mmdb
```

`stackscan` needs at least one compiled `.sigdb` database. By default it looks
for `~/reekeer/sigdb/sigdb.sigdb`, plus every source you have configured (see
below). Pass `--sigdb PATH` to point at a specific one.

## Usage

```bash
# Scan one or more targets
stackscan example.com https://another.example

# Read targets from a file (one per line, '#' comments allowed)
stackscan -f targets.txt

# JSON report (full detail)
stackscan --json example.com

# Faster/lighter: skip network-level passes
stackscan --no-dns --no-tls --no-geo --no-probe example.com

# Geolocate IPs from a local MaxMind database
stackscan --geoip-db /path/GeoLite2-City.mmdb example.com
```

Bare hostnames are normalized to `https://`.

## Signature sources

Add extra signature databases from the internet or git. Sources are compiled
locally and merged with the default database on every scan.

```bash
# Add an HTTP source (a .sigdb file, or a rules JSON that stackscan compiles)
stackscan sigdb add https://sigdb.imalive.lol

# Add a git repository containing a .sigdb or sigdb.json / rules.json
stackscan sigdb add https://github.com/reekeer/db_stacks.git

stackscan sigdb list
stackscan sigdb update            # re-fetch/recompile all sources
stackscan sigdb remove <id|url>
```

Sources are recorded under `$XDG_CONFIG_HOME/stackscan/` and cached under
`$XDG_CACHE_HOME/stackscan/`.

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `targets` | – | Target URLs or hostnames. |
| `-f`, `--file` | – | File with targets, one per line. |
| `--sigdb` | `~/reekeer/sigdb/sigdb.sigdb` | Explicit `.sigdb` path (overrides default). |
| `--no-sources` | off | Ignore configured sources. |
| `--timeout` | `12.0` | Per-request timeout in seconds. |
| `--user-agent` | `stackscan/2.0 …` | Custom `User-Agent` header. |
| `--insecure` | off | Disable TLS certificate verification. |
| `--max-bytes` | `1000000` | Maximum response body bytes to read. |
| `--concurrency` | `10` | Number of concurrent requests. |
| `--geoip-db` | – | MaxMind `.mmdb` for IP geolocation. |
| `--no-dns` / `--no-tls` / `--no-geo` / `--no-probe` | off | Skip a pass. |
| `--json` | off | Emit JSON instead of a table. |
| `--show-empty` | off | Include targets with no findings. |
| `--version` | – | Print the version and exit. |

## Development

```bash
ruff check . && black --check . && pyright && pytest
```

## License

MIT
