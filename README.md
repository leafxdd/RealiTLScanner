# RealiTLScanner

[中文文档](README_zh.md)

A high-performance TLS certificate scanner with integrated Reality protocol domain evaluation. Scans IP/CIDR/domain targets for TLS certificates and evaluates domain feasibility through multiple detectors (CDN, GFW, redirect, hot website, etc.).

## Features

- TLS certificate scanning (IP, CIDR, domain) with context-aware cancellation
- Concurrent scanning with configurable thread count
- GeoIP location lookup (configurable data dir)
- **Domain feasibility detection**: CDN, GFW, TLS validation (SAN + wildcard via `VerifyHostname`), hot website, redirect, HTTP status
- **Post-quantum probe (PQC)**: offers `X25519MLKEM768` first in the handshake (falls back to X25519 — crypto/tls sends a key share for both, so no HelloRetryRequest penalty), records the negotiated curve; a dest that negotiates it behaves like current Chrome — a stronger steal-a-neighbour signal, counted toward the star rating and flagged in the 备注 column
- **De-risk blocklist**: vetoes proxy-keyword cert domains, proxy panels (detected via the `Server` header — x-ui / sing-box / …), and dynamic-DNS / NAS suffixes; flags cheap TLDs as a soft (−1 star) signal — surfaced in the 备注 column
- **SSRF-safe detector probes**: redirect/status detectors reject private, loopback, link-local, and metadata addresses
- **Neighbour discovery (`-bgp`)**: smart-select the best covering prefix for a single `-addr` IP — a host often sits under several overlapping announced prefixes (e.g. /24, /21, /20), so it enumerates them (Team Cymru seed + RIPEstat `routing-status`) and picks the `/20`–`/24` sweet spot (centre `/21`), then counts how many neighbours bgp.tools has actually seen there and aborts if that exceeds `-max-hosts` (default 4096) unless `-yes`
- **Two-phase scan (`-probe-first`)**: a fast concurrent TCP liveness pre-filter weeds out dead/firewalled hosts before the expensive TLS scan; auto-enabled with `-bgp` and CIDR range scans
- **Star rating** (0-6): handshake time, CDN, popularity, certificate validity, post-quantum support
- **Formatted table output** with color coding (auto-disabled on non-TTY / `NO_COLOR`)
- **Scan statistics**: per-pipeline `attempted / tls_failed / dropped` counters surfaced in summary
- **Graceful Ctrl+C**: in scan mode, interrupt scanning phase to immediately proceed to detection with collected domains
- **Concurrent-safe data manager**: `singleflight`-deduplicated downloads, size-capped (200 MiB default) responses
- Docker support

## Building

Requirement: Go 1.26+

```bash
make build
# or
go build -o RealiTLScanner ./cmd/realitlscanner

# Stripped, reproducible builds:
go build -trimpath -ldflags='-s -w' -o RealiTLScanner ./cmd/realitlscanner
```

### Cross-compile

```bash
# Linux x86_64
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o RealiTLScanner-linux-amd64 ./cmd/realitlscanner

# Linux ARM64
GOOS=linux GOARCH=arm64 go build -trimpath -ldflags='-s -w' -o RealiTLScanner-linux-arm64 ./cmd/realitlscanner

# Windows
GOOS=windows GOARCH=amd64 go build -trimpath -ldflags='-s -w' -o RealiTLScanner-windows-amd64.exe ./cmd/realitlscanner
```

## Usage

### Basic Scanning

Scan IP range and output domains to CSV file:

```bash
# Scan a specific IP, IP CIDR or domain:
./RealiTLScanner -addr 1.2.3.0/24

# Scan from file:
./RealiTLScanner -in targets.txt

# Crawl domains from URL:
./RealiTLScanner -url https://launchpad.net/ubuntu/+archivemirrors

# Custom port, threads, timeout:
./RealiTLScanner -addr 107.172.1.0/24 -port 443 -thread 10 -timeout 5

# Save to file (default: out.csv):
./RealiTLScanner -addr 1.2.3.0/24 -out results.csv

# Continuously scan neighbour IPs outward from a single IP/domain (default: just that one host):
./RealiTLScanner -addr 1.2.3.4 -infinite

# Continue even if GeoIP download fails:
./RealiTLScanner -addr 1.2.3.0/24 -skip-download
```

On first run, `Country.mmdb` (GeoIP database) is automatically downloaded. If download fails, the program stops by default. Use `-skip-download` to continue without GeoIP.

### Scan with Detection (`scan`)

Scan domains and evaluate feasibility with formatted table output:

```bash
# Scan IP range, detect and display results:
./RealiTLScanner scan -addr 1.2.3.0/24

# Read domains from a previously generated CSV file:
./RealiTLScanner scan -csv results.csv

# Directly specify domains:
./RealiTLScanner scan apple.com www.tesla.com example.com

# Also save results to file:
./RealiTLScanner scan -csv results.csv -out report.txt

# Custom threads and timeout:
./RealiTLScanner scan -addr 1.2.3.0/24 -thread 16 -timeout 10

# Continue even if data file download fails:
./RealiTLScanner scan -addr 1.2.3.0/24 -skip-download
```

Data files (gfwlist, Country.mmdb) are automatically downloaded on first `scan` run. If download fails, the program stops by default. Use `-skip-download` to continue with limited detection.

Note: Basic mode (without `scan`) only downloads `Country.mmdb`. The `scan` command additionally downloads `gfwlist.conf` for GFW detection.

#### Output Example

```
------------------------------------------------------------------------------------------------------------------------------
最终域名                           基础条件     握手时间       证书时间       CDN      热门     推荐     页面状态     备注
------------------------------------------------------------------------------------------------------------------------------
cdn77.akamai-edge.net              ✓            142ms          312天          无       -        ******   200          PQC
shop.bingserve.com                 ✓            274ms          83天           无       -        ****     200
blog.example.xyz                   ✓            210ms          120天          无       -        ****     200          廉价/PQC
vless.cheapvps.top                 ✗            156ms          88天           无       -                 200          代理
sub.host-panel.net                 ✗            203ms          41天           无       -                 200          面板
home.duckdns.org                   ✗            318ms          60天           无       -                 -            动态DNS

------------------------------------------------------------------------------------------------------------------------------
检测完成: 6 个域名, 3 个适合 (50.0%), 耗时 12.9s
扫描统计: attempted=256  tls_failed=210  dropped=15
```

Color output is automatically disabled when stdout is not a TTY (redirected to a file/pipe) or when the `NO_COLOR` environment variable is set.

| Column | Description |
|--------|-------------|
| 最终域名 | Domain from TLS certificate (column auto-fits the longest domain — never truncated) |
| 基础条件 | TLS 1.3 + H2 + valid cert + issuer (✓/✗) |
| 握手时间 | TLS handshake latency (green ≤200ms, yellow ≤500ms, red >500ms) |
| 证书时间 | Days until certificate expiry (green ≥60, yellow ≥30, red <30) |
| CDN | CDN detection level (无/low/medium/high) |
| 热门 | Popular website flag (✓ = hot, - = not) |
| 推荐 | Star rating 0-6 based on overall quality |
| 页面状态 | HTTP status code |
| 备注 | Flags that hit are stacked with `/` (e.g. `代理/廉价/PQC`). Hard veto: 代理 (proxy keyword), 面板 (proxy panel via `Server` header), 动态DNS, NAS; soft: 廉价 (cheap TLD); bonus: PQC (negotiated post-quantum key exchange). Blank means clean |

#### Star Rating Criteria

| Criterion | Stars |
|-----------|-------|
| Base conditions pass (TLS 1.3 + H2 + SNI match) | +1 |
| Handshake time ≤ 200ms | +1 |
| No CDN detected | +1 |
| Not a popular/hot website | +1 |
| Certificate valid ≥ 60 days | +1 |
| Post-quantum key exchange (X25519MLKEM768) | +1 |

> **De-risk overrides** (blocklist detector): a hard hit — proxy keyword in the cert domain, a proxy-panel `Server` header (x-ui / sing-box / …), or a dynamic-DNS / NAS suffix — vetoes the candidate (`✗`, score forced to 0). A cheap TLD (`.xyz` / `.top` / `.win` / …) is only a soft signal: it stays feasible but loses one star.

### Neighbour Discovery (BGP prefix expansion)

Instead of guessing a CIDR or walking neighbours one-by-one with `-infinite`, `-bgp` expands a single IP to the prefix its origin AS announces and scans that — the natural "steal a neighbour" scope. Works in both basic and `scan` modes.

```bash
# Smart-select the best covering prefix for a single IP and scan it:
./RealiTLScanner -addr 104.249.172.234 -bgp
./RealiTLScanner scan -addr 104.249.172.234 -bgp

# Refuse if bgp.tools shows more active neighbours than the cap, unless forced:
./RealiTLScanner -addr 1.2.3.4 -bgp -max-hosts 1024          # refuse if >1024 active neighbours
./RealiTLScanner -addr 1.2.3.4 -bgp -yes                     # force past the cap

# Two-phase scan: a cheap TCP liveness pre-filter before the full TLS scan
# (skips dead/firewalled hosts so they don't each burn the full -timeout).
# Auto-on with -bgp and CIDR scans; pass it explicitly for an -in file of ranges:
./RealiTLScanner -in ranges.txt -probe-first
```

**Smart prefix selection.** A single IP is usually covered by several overlapping announced prefixes — on bgp.tools one host might sit under a `/24`, a `/21` and a `/20` at once. `-bgp` enumerates them (a Team Cymru seed plus RIPEstat `routing-status`, which already drops near-invisible routes) and ranks toward the `/20`–`/24` sweet spot centred on `/21`: enough neighbours to find a good target, but not a `/14`'s worth to grind through. No API key required.

**Active-neighbour count.** After picking a prefix, `-bgp` fetches bgp.tools' heatmap for it and counts how many addresses bgp.tools has actually seen in use — a quick up-front estimate (it reflects bgp.tools' ping view, not a substitute for the real TCP/TLS probe that follows). If that count exceeds `-max-hosts`, the scan aborts unless you pass `-yes`. A `/20`–`/24` prefix can never exceed the 4096 default, so the gate only really matters when the IP is announced solely as something broader.

| Flag | Effect | Default |
|------|--------|---------|
| `-bgp` | Smart-select the best covering BGP prefix for `-addr <ip>` (`/20`–`/24`) and scan it | off |
| `-max-hosts N` | Abort if bgp.tools shows more than N active neighbours in the chosen prefix; override with `-yes` | 4096 |
| `-yes` | Force scanning past the `-max-hosts` active-neighbour cap | off |
| `-probe-first` | Two-phase scan: TCP liveness pre-filter before the full TLS scan | off (auto-on with `-bgp` / CIDR `-addr`) |
| `-infinite` | Walk neighbour IPs outward from a single IP/domain (basic mode) | off |

### Single Domain Check

```bash
# Full check on a single domain (TLS + all detectors):
./RealiTLScanner check example.com

# Custom port, timeout, data dir:
./RealiTLScanner check example.com -port 443 -timeout 5 -data-dir /opt/realitls

# Continue even if data file download fails:
./RealiTLScanner check example.com -skip-download
```

`check` returns a non-zero exit code on failure, suitable for shell scripting:

| Exit | Meaning |
|------|---------|
| 0 | Success |
| 1 | Missing domain argument or DNS resolution failure |
| 2 | TLS scan error (dial/handshake failed, cert missing) |
| 3 | Data file download failure (use `-skip-download` to soften) |

### Version

```bash
./RealiTLScanner version
```

### Docker

```bash
# Build:
docker build -t realitlscanner .

# Run:
docker run --rm realitlscanner -addr 1.1.1.0/24
docker run --rm realitlscanner scan -addr 1.1.1.0/24
docker run --rm realitlscanner scan apple.com www.tesla.com
```

## Data Files

Required data files are **automatically downloaded** on first run:

| File | Used By | Purpose | Source |
|------|---------|---------|--------|
| `Country.mmdb` | Basic + Scan | GeoIP lookup | [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip/releases) |
| `gfwlist.conf` | Scan only | GFW block detection | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) |
| `cdn_keywords.txt` | Scan only | CDN detection | Built-in (embedded) |
| `hot_websites.txt` | Scan only | Hot website detection | Built-in (embedded) |
| `blocklist_keywords.txt` | Scan only | De-risk blocklist (proxy/dynamic-DNS/NAS/cheap-TLD) | Built-in (embedded) |

- Basic mode downloads: `Country.mmdb`
- Scan mode downloads: `Country.mmdb` + `gfwlist.conf`
- CDN keywords and hot websites are embedded in the binary (no download needed)
- Use `-skip-download` to continue if download fails

## Project Structure

```
cmd/realitlscanner/     CLI entry point (subcommand routing, url-fetch with timeout/size cap)
internal/
  types/                Shared types (Host, ScanResult, TLSInfo, CertValidResult)
  scanner/              TLS scanning (ctx-aware) + CSV domain parser + StrictDomainName validator
                        + BGP smart prefix selection (Cymru/RIPEstat) + bgp.tools neighbour count + TCP liveness pre-filter
  detector/             Detector interface + CDN/GFW/HotSite/Location/Redirect/Status/TLSCheck/Blocklist + scorer
                        + safe-target gate (loopback/private/metadata rejection)
  pipeline/             Channel-based scan→detect→output orchestration with attempted/failed/dropped stats
  output/               Output writers (CSV, JSON, JSONL, table)
  data/                 Data file management (embed + downloaded with singleflight + size cap)
  geo/                  GeoIP lookup (path-configurable)
```

## Testing

```bash
make test
# or
go test -race ./...
```

## Security Notes

- **Scanner uses `InsecureSkipVerify=true`**: by design — the goal is to discover Reality-feasible servers, not to validate PKI. `CertValidResult.Valid` reflects basic feasibility (TLS 1.3 + h2 ALPN + non-empty CertDomain/Issuer); `CertValidResult.SNIMatch` uses `x509.VerifyHostname` (handles wildcards). Consumers needing true validation must verify independently.
- **Redirect/Status detectors**: HTTP probes only run against publicly routable domains. Loopback, link-local (`127.0.0.0/8`, `::1`, `169.254.0.0/16`), private (`10/8`, `172.16/12`, `192.168/16`, ULA), and cloud metadata (`169.254.169.254`, etc.) addresses are rejected client-side before any request is sent.
- **Data downloads**: capped at 200 MiB (`Content-Length` pre-check + `LimitReader`); singleflight prevents duplicate concurrent downloads.
- **Proxy hygiene**: all upper- and lower-case proxy env vars (`HTTP_PROXY`/`http_proxy`/...) are cleared at startup for all subcommands.

## Acknowledgements

- [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) - Original project
- [V2RaySSR/RealityChecker](https://github.com/V2RaySSR/RealityChecker) - Domain detection logic reference
