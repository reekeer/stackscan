# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [2.7.1] - 2026-08-28

### Added

- **Progress inside reekeer.** A scan says how far along it is with `reekeer.progress` — one bar per target, staged the same way the terminal's is — and reekeer draws it: a line that rewrites itself at the prompt, a real bar in the window. The `rich` display is not built at all when reekeer is hosting, because it is a *live* display and that is cursor movement: pointed anywhere that is not a terminal it rendered nothing whatever, which is what a two-minute scan looked like from inside the shell, and forcing it would have sent one frame of escape sequences per update into a log that cannot replay them. Standalone output is untouched, and a reekeer too old to have `reekeer.progress` simply gets none.

- **A form in the reekeer window.** `embed.form()` declares which of stackscan's flags are worth a control — the targets, `--full`/`--ports`/`--subdomains`/`--default-creds`, and the bounds worth reaching for when a scan is too slow — and reekeer draws exactly those. It replaces reekeer reading `stackscan --help` and making a control out of every flag it found, which produced a column thirty deep in which the target of the scan looked no different from `--no-bell`. Everything left out still parses on the argument line under the form.

- **`--disable` and `--export` are checkboxes in the window.** Both are a comma list argparse reads as one value, so the form declares them as a closed set you tick several of — reekeer draws a box per pass and sends the ticked ones as `--disable dns,tls`. Standalone the flag is unchanged.

### Changed

- **No brute prompt inside reekeer.** The mid-scan `Try to brute? [Y]es / [N]o` reads `/dev/tty`, which the shell's worker has no terminal for — the prompt hung with nowhere for an answer to come from, and its stdin fallback would have swallowed the next protocol message. Hosted, the choice is made before the run: `--full-auto` is a switch on the form, on brute-forces every discovered device, off leaves them found but untried. Standalone the prompt is exactly as it was.

- **The host block no longer repeats the elapsed time.** The summary line already ends `… in 1m 40s` and reekeer's status bar carries a live clock, so an `elapsed` row in the host table was the same number a third time. Dropped from the reekeer document; standalone output is unchanged.

### Fixed

- **The standalone progress bar is one rewriting line again, not a column of `]0;stackscan …`.** `rich.Progress` redirects `sys.stderr` through a proxy that reprints whatever is written to it as a line above the bar, so the per-stage window-title escape — written straight to stderr each stage — was captured and echoed as visible text instead of retitling the window, one dead line per stage. The title now holds while the live display is up and is set only around it, so the bar rewrites itself in place as intended.

- **A bare IP whose homepage is down is scanned instead of skipped whole.** A literal address has no A record, so it resolved to an empty set and every pass keyed off that set — the port scan, IP enrichment, virtual-host discovery — quietly had nothing to work on and the target came back empty. The IP is now seeded as its own address, so `--full` against an IP still scans ports, fingerprints services and detects the OS even when nothing answers on 80/443. Subdomain enumeration, which cannot apply to an address, is skipped rather than resolving a wordlist against it.

- **One stack across many subdomains is one row, not twenty.** The technologies table repeated a
  finding — `leavepulse-ui`, `frontend` — once per host it was seen on, so a stack shared by a dozen
  subdomains filled the table with the same name a dozen times. Identical stacks now collapse to a
  single row whose Host cell lists the domains (primary first), and the confidence column shows a
  range when it varies between them.

- **The brute prompt shows `> ` and takes the answer.** Reading and writing `/dev/tty` through a single `r+` handle swallowed the prompt — it never reached the screen before the read blocked — so `Y` looked like it did nothing. The prompt and the read now use separate terminal handles (falling back to stderr/stdin only when there is no `/dev/tty`), and the brute pass draws a bar while it runs and prints what it found, so a long check reads as working rather than hung.

## [2.7.0] - 2026-08-13

### Added

- **reekeer plugin.** `[tool.reekeer]` in `pyproject.toml` mounts stackscan at `/tools/recon/stackscan` (alias `ss`); `/plugins install reekeer/stackscan` is all it takes. Hosted there the scan is handed back as data and the shell renders it in its own tables, glyphs and palette, so a stackscan report and a built-in listing look like the same program. Standalone output is untouched, and `--export json-t` still wins over both.
- **Runner mode.** `stackscan --runner` (or `STACKSCAN_RUNNER=1`) claims jobs from a StackScan panel, scans them with the normal engine and posts the results back, over HTTP alone. Configurable by flag or environment, `--once` for a single cycle, and a `Dockerfile` that ships it as a non-root image.

### Changed

- Under reekeer, stackscan no longer draws its banner, renames the terminal window or rings the bell: the shell owns the screen there, and an escape sequence sent down a worker's pipe is just text somebody has to print.
- Runner mode is refused inside the reekeer shell — it is a loop that runs until killed, and a shell command that never answers is not a command.

## [2.6.4] - 2026-07-19

### Added

- `stackscan sigdb add` now treats a database base URL/directory/git repo (with `sigdb/` and `stackscan/`) as a single source, pulling the compiled signatures via `sigdb/manifest.json` and the CVE database (`stackscan/cve.json.gz`) and subdomain wordlist (`stackscan/subdomains.txt`) alongside it. Defaults to `https://db.imalive.lol`.
- `stackscan sigdb list` always shows the built-in `db.imalive.lol` database (`/sigdb` + `/stackscan`) as a `Default` row.

### Changed

- Drop the emoji/unicode glyphs and use plain ASCII markers everywhere (`[+]`, `[!]`, `[x]`, `[?]`, `->`).

### Fixed

- Read the brute-force `y/n` prompt (and print it) through the controlling terminal (`/dev/tty`) so the answer registers even when stderr is redirected.
- Harden virtual-host discovery: skip edge IPs whose unknown-Host responses are flaky (varying status across probes), cutting bogus vhost subdomains.

## [2.6.3] - 2026-07-17

### Added

- Web-login default-credential checks: MikroTik RouterOS (REST), UniFi (`/api/login`), and generic HTML login forms, in addition to HTTP Basic auth (authorized targets only, same prompts/flags as the device checks).

### Changed

- `stackscan sigdb add` auto-detects the source type (no `--type`) and defaults to `https://db.imalive.lol/sigdb` when no argument is given.

### Removed

- The `--sigdb` flag; manage signatures with `stackscan sigdb` sources instead.

## [2.6.2] - 2026-07-17

### Added

- `stackscan sigdb` now manages signature sources by type: `add <src> [--type path|web|git]`, `remove`, `enable`, `disable`, `list`. Web sources accept a `.sigdb`, a rules JSON, or a `manifest.json` (which resolves and fetches the compiled sigdb), so a served `db.imalive.lol` database can be added directly.

### Changed

- Rebuild the bundled signature database from the consolidated `db.imalive.lol` category shards.

## [2.6.1] - 2026-07-17

### Added

- Detect self-hosted apps and admin panels (Gitea/Forgejo, Matrix Synapse/Element/synapse-admin, MikroTik, Proxmox, Portainer, Grafana, Jellyfin, the *arr stack, Vaultwarden, Keycloak and ~90 more) from the rebuilt signature database, surfaced as admin-panel/service findings.
- Cover MikroTik/RouterOS, pfSense/OPNsense, UniFi and other device/panel keywords in the default-credential check.

### Fixed

- Skip virtual-host discovery on catch-all/wildcard edge IPs (e.g. Cloudflare) so a wildcard domain no longer yields hundreds of bogus `mail.*`/`www.www.*` subdomains.
- Reject bogus phone numbers (`tel:8`) and malformed `mailto:` addresses in the social/contacts parser.
- Read the brute-force confirmation prompt from the controlling terminal (`/dev/tty`) so `y/n` works during a scan.

### Changed

- Use emoji for warnings/errors and verbose scan lines when the terminal supports unicode.

## [2.6.0] - 2026-07-16

### Added

- WHOIS/RDAP now reports nameservers, DNSSEC status, the last-changed date, and the registrar URL.
- DNS resolution now queries HTTPS, SVCB, and DS records and surfaces them in terminal and HTML reports.
- Verbose scans (`-v`) now use the staged per-target progress view with more granular stage labels.

### Changed

- Technologies table now shows the target host for edge/CDN/WAF/proxy entries instead of `-`.
- Scan pipeline is split into finer stages (social links, takeovers, CDN detection, virtual hosts, software extraction, IP/WHOIS/creds enrichment, service/OS classification) so the progress bar updates more often.
- Removed the unicode spinner from progress bars to avoid rendering issues in some terminals.

### Removed

- Dropped the Infrastructure, Security headers, and Hosts & OS sections from the terminal report.
- Dropped the Infrastructure and Hosts & OS sections from the HTML export.

## [2.5.0] - 2026-07-16

### Added

- Show full social/contact URLs in the report instead of bare handles (e.g. the complete Discord invite link).
- Update the terminal title with live scan status and ring the terminal bell when the scan finishes (opt out with `--no-bell`).
- Detect terminal unicode support and use emoji/unicode glyphs (arrow, section markers, status icons) when available, falling back to ASCII otherwise.

### Changed

- Advance the progress bar through long port-scan and subdomain phases (per host and per sub-phase) so it keeps moving instead of sitting still, and show the staged per-target view by default for single-target scans.

## [2.4.0] - 2026-07-16

### Added

- WHOIS/RDAP lookup showing the domain registrar, registration and expiry dates, and whether the registrant contact is public or withheld for privacy (disable with `--disable whois`).
- Single "behind X" edge summary that groups each provider's CDN/WAF/proxy roles and chains layered services front-to-back (e.g. Cloudflare (CDN, WAF) → Amazon CloudFront).
- Modern application subdomain labels (`agents`, `ws`, `gateway`, `functions`, `webhooks`, …) in the priority wordlist so common app hosts are tried within the default limit.

### Changed

- Resolve DNS via cached public resolvers (Cloudflare and Google plus censorship-resistant fallbacks) instead of the system resolver, cutting per-domain record lookups from ~10s to sub-second and caching results within a run. Deep hosts that the system resolver missed now resolve reliably.
- Break scans into finer, accurately-counted stages and show the staged progress view by default for single-target scans.
- Query crt.sh once and retry only on failure to avoid doubling the certificate-transparency wait.

### Fixed

- Hide distro-backported and SSH banner CVEs below the default confidence threshold so phantom CVEs no longer surface unless the threshold is lowered.
- Decode `\uXXXX`/`\xXX` escapes when extracting hostnames from page content, fixing bogus subdomains like `u002fcdn.example.com` and recovering the real escaped ones.
- Stop scraping page prose and crypto tokens (e.g. `ed25519`) as generic technologies/software; truncate scraped product names at connective stopwords.
- Only query NVD live when `--cve-online` is passed, matching the documented offline default.

## [2.3.0] - 2026-07-16

### Added

- `--cve-min-confidence` flag (default 50) to suppress low-confidence CVE noise.
- Virtual-host (vhost) brute on discovered web ports to find subdomains that do not appear in DNS or certificate transparency logs.
- Passive subdomain extraction from the primary page body, JavaScript, and links.
- Generic detection of services that expose a commit hash as `Product Core (hash)`.
- Expanded bundled DNS wordlist with common SaaS/platform labels.

### Fixed

- Filter out CSS utility class tokens (e.g. `backdrop-blur`, `px-4`) so they no longer trigger false framework matches such as "Backdrop".
- Grade backported CVE confidence by range precision: vague "before X" ranges get lower confidence than pinned ranges.
- Derive the distro/OS tag from nmap port banners when `Port.os` is empty so backported OpenSSH/nginx versions are capped at low confidence.
- Recognize Oracle Linux and SLES as backporting distros in CVE detection.
- Reject REJECTED/replaced/deprecated CVEs and entries without an English summary when rebuilding the offline CVE database.

## [2.2.2] - 2026-07-14

### Added

- Infer and display technology versions from sigdb `versions` constraints.
- Tokenize CSS `class` attributes for sigdb framework matching.

### Fixed

- Parse MySQL/MariaDB handshake and grade DB exposure by auth state instead of always CRITICAL.
- Account for distro backports in CVE matching; mark banner-only matches as unconfirmed and exclude them from headline critical count.
- Derive the distro/OS tag from nmap port banners when `Port.os` is empty so backported OpenSSH/nginx versions are capped at low confidence.
- Proceed on self-signed or IP TLS certificates instead of aborting the target.
- Probe RTSP/camera ports (`554`, `8554`) for default credentials.
- Do not treat infrastructure server software as an OS.
- Classify port-banner OS source as `banner` rather than `network`.

### Changed

- Updated builtin sigdb to the latest rebuild with native `versions` support.

## [2.2.1] - 2024-07-08

### Changed

- Updated installation link.
- Removed generated reports from repository.
- Moved pipeline documentation to docs.

## [2.2.0] - 2024-07-08

### Added

- Version text in the banner.
- Per-technology detection confidence percentage.
- `--parse-social` flag to extract social and contact links.
- `--full-auto` flag to auto-accept brute-force prompts on discovered devices.
- Prompt before brute-forcing found devices.

### Fixed

- Exit cleanly on keyboard interrupt without traceback spam.
- Resolve CVE confidence to fixed 98/91/85 tiers.

## [2.1.0] - 2024-06-24

### Added

- `sigdb` integration and loader module.
- Technology detection via sigdb `match_all` and `match_text`.
- HTTP and git signature source management.
- Full-stack scan pipeline orchestration.
- Rich scan report data models.
- DNS, TLS and optional geolocation inspection.
- CDN, WAF, reverse proxy detection and security headers audit.
- Passive well-known and git-exposure probes.
- CLI analysis pipeline and sigdb source subcommands.
- Optional DNS and geo extras.

### Changed

- Removed `frameworks.json` support; use sigdb only.

### Fixed

- Correct sigdb imports from `sigdb.core`.
- Parse `Set-Cookie` headers individually.
- Forward `--insecure` flag to TLS certificate inspection.
- Pass parsed HTTPS port to TLS certificate inspection.
- Drain response remainder after `max_bytes` read.
- Bound signature source downloads to 50 MB and read in chunks.
- Require `.git/HEAD` body to start with `ref:`.

## [1.0.0] - 2024-06-10

### Added

- Initial release of stackscan.
- Project configuration and dependency lock.

[2.6.0]: https://github.com/reekeer/stackscan/compare/v2.5.0...v2.6.0
[2.5.0]: https://github.com/reekeer/stackscan/compare/v2.4.0...v2.5.0
[2.4.0]: https://github.com/reekeer/stackscan/compare/v2.3.0...v2.4.0
[2.3.0]: https://github.com/reekeer/stackscan/compare/v2.2.2...v2.3.0
[2.2.2]: https://github.com/reekeer/stackscan/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/reekeer/stackscan/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/reekeer/stackscan/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/reekeer/stackscan/compare/v1.0.0...v2.1.0
[1.0.0]: https://github.com/reekeer/stackscan/releases/tag/v1.0.0
