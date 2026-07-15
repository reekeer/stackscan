# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/reekeer/stackscan/compare/v2.2.2...HEAD
[2.2.2]: https://github.com/reekeer/stackscan/compare/v2.2.1...v2.2.2
[2.2.1]: https://github.com/reekeer/stackscan/compare/v2.2.0...v2.2.1
[2.2.0]: https://github.com/reekeer/stackscan/compare/v2.1.0...v2.2.0
[2.1.0]: https://github.com/reekeer/stackscan/compare/v1.0.0...v2.1.0
[1.0.0]: https://github.com/reekeer/stackscan/releases/tag/v1.0.0
