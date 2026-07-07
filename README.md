# stackscan

Lightweight Wappalyzer-like technology stack detector. `stackscan` fetches one
or more targets over HTTP(S) and matches their headers, cookies, and HTML
against a [sigdb](https://github.com/reekeer/sigdb) signature database.

## Install

```bash
pip install "stackscan @ git+https://github.com/reekeer/stackscan.git"
```

`stackscan` needs a compiled `.sigdb` file to match against. By default it looks
for `~/reekeer/sigdb/sigdb.sigdb`; pass `--sigdb` to point at another path.

## Usage

```bash
# Scan one or more targets
stackscan example.com https://another.example

# Read targets from a file (one per line, '#' comments allowed)
stackscan -f targets.txt

# Use a specific signature database
stackscan --sigdb ./sigdb.sigdb example.com

# JSON output
stackscan --json example.com
```

Bare hostnames are normalized to `https://`.

## Options

| Option | Default | Description |
|--------|---------|-------------|
| `targets` | – | Target URLs or hostnames. |
| `-f`, `--file` | – | File with targets, one per line. |
| `--sigdb` | `~/reekeer/sigdb/sigdb.sigdb` | Path to the `.sigdb` database. |
| `--timeout` | `12.0` | Per-request timeout in seconds. |
| `--user-agent` | `stackscan/1.0 (+https://example.invalid)` | Custom `User-Agent` header. |
| `--insecure` | off | Disable TLS certificate verification. |
| `--max-bytes` | `1000000` | Maximum response body bytes to read. |
| `--concurrency` | `10` | Number of concurrent requests. |
| `--json` | off | Emit JSON instead of a table. |
| `--show-empty` | off | Include targets with no detections in table output. |
| `--version` | – | Print the version and exit. |

## License

MIT
