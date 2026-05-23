# RealiTLScanner

[中文文档](README_zh.md)

A high-performance TLS certificate scanner with integrated Reality protocol domain evaluation. Scans IP/CIDR/domain targets for TLS certificates and evaluates domain feasibility through multiple detectors (CDN, GFW, redirect, hot website, etc.).

## Features

- TLS certificate scanning (IP, CIDR, domain) with context-aware cancellation
- Concurrent scanning with configurable thread count
- GeoIP location lookup (configurable data dir)
- **Domain feasibility detection**: CDN, GFW, TLS validation (SAN + wildcard via `VerifyHostname`), hot website, redirect, HTTP status
- **SSRF-safe detector probes**: redirect/status detectors reject private, loopback, link-local, and metadata addresses
- **Star rating** (0-5): handshake time, CDN, popularity, certificate validity
- **Formatted table output** with color coding (auto-disabled on non-TTY / `NO_COLOR`)
- **Scan statistics**: per-pipeline `attempted / tls_failed / dropped` counters surfaced in summary
- **Graceful Ctrl+C**: in scan mode, interrupt scanning phase to immediately proceed to detection with collected domains
- **Concurrent-safe data manager**: `singleflight`-deduplicated downloads, size-capped (200 MiB default) responses
- Docker support

## Building

Requirement: Go 1.21+

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
---------------------------------------------------------------------------------------------------------------------
最终域名                           基础条件     握手时间       证书时间       CDN      热门     推荐     页面状态
---------------------------------------------------------------------------------------------------------------------
yz.iosjy.top                       ✓            341ms          69天           无       -        ****     200
blog.bingserve.xyz                 ✓            447ms          83天           无       -        ****     200
yingyaozw.com                      ✓            439ms          246天          无       -        ****     200
code.memoncler.com                 ✓            783ms          5天            无       -        ***      -
o03.cc                             ✗            1624ms         88天           无       -        ***      405

---------------------------------------------------------------------------------------------------------------------
检测完成: 31 个域名, 29 个适合 (93.5%), 耗时 12.9s
扫描统计: attempted=256  tls_failed=210  dropped=15
```

Color output is automatically disabled when stdout is not a TTY (redirected to a file/pipe) or when the `NO_COLOR` environment variable is set.

| Column | Description |
|--------|-------------|
| 最终域名 | Domain from TLS certificate |
| 基础条件 | TLS 1.3 + H2 + valid cert + issuer (✓/✗) |
| 握手时间 | TLS handshake latency (green ≤200ms, yellow ≤500ms, red >500ms) |
| 证书时间 | Days until certificate expiry (green ≥60, yellow ≥30, red <30) |
| CDN | CDN detection level (无/low/medium/high) |
| 热门 | Popular website flag (✓ = hot, - = not) |
| 推荐 | Star rating 0-5 based on overall quality |
| 页面状态 | HTTP status code |

#### Star Rating Criteria

| Criterion | Stars |
|-----------|-------|
| Base conditions pass (TLS 1.3 + H2 + SNI match) | +1 |
| Handshake time ≤ 200ms | +1 |
| No CDN detected | +1 |
| Not a popular/hot website | +1 |
| Certificate valid ≥ 60 days | +1 |

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
  detector/             Detector interface + CDN/GFW/HotSite/Location/Redirect/Status/TLSCheck + scorer
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
