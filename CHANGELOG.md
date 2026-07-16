# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
