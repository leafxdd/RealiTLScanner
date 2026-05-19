# RealiTLScanner

A high-performance TLS certificate scanner with integrated Reality protocol domain evaluation. Scans IP/CIDR/domain targets for TLS certificates and evaluates domain feasibility through multiple detectors (CDN, GFW, redirect, hot website, etc.).

## Features

- TLS certificate scanning (IP, CIDR, domain)
- Concurrent scanning with configurable thread count
- Infinity mode (auto-expand from single IP/domain)
- GeoIP location lookup
- **Domain feasibility detection**: CDN, GFW, TLS validation, hot website, redirect, HTTP status
- **Star rating** (0-5): handshake time, CDN, popularity, certificate validity
- **Formatted table output** with color coding
- **Real-time progress reporting**
- Docker support

## Building

Requirement: Go 1.21+

```bash
make build
# or
go build -o RealiTLScanner ./cmd/realitlscanner
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
```

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
```

#### Output Example

```
------------------------------------------------------------------------------------------------
最终域名                           基础条件     握手时间       证书时间       CDN      热门     推荐     页面状态
------------------------------------------------------------------------------------------------
yz.iosjy.top                   ✓          341ms        69天         无       -      ****     200
blog.bingserve.xyz             ✓          447ms        83天         无       -      ****     200
yingyaozw.com                  ✓          439ms        246天        无       -      ****     200
code.memoncler.com             ✓          783ms        5天          无       -      ***      -
o03.cc                         ✗          1624ms       88天         无       -      ***      405

------------------------------------------------------------------------------------------------
检测完成: 31 个域名, 29 个适合 (93.5%), 耗时 12.9s
```

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
# Full check on a single domain:
./RealiTLScanner check example.com
```

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

## GeoIP

Place a MaxMind GeoLite2/GeoIP2 Country Database named `Country.mmdb` in the working directory. Download from [here](https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb).

## Data Files

Detection features use the following data files:

| File | Purpose | Source |
|------|---------|--------|
| `Country.mmdb` | GeoIP lookup | [Loyalsoldier/geoip](https://github.com/Loyalsoldier/geoip/releases) |
| `gfwlist.conf` | GFW block detection | [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules) |
| `cdn_keywords.txt` | CDN detection | Built-in (embedded) |
| `hot_websites.txt` | Hot website detection | Built-in (embedded) |

CDN keywords and hot websites are embedded in the binary. GeoIP and GFW list are downloaded on first use.

## Project Structure

```
cmd/realitlscanner/     CLI entry point (subcommand routing)
internal/
  types/                Shared types (Host, ScanResult)
  scanner/              TLS scanning + CSV domain parser
  detector/             Detector interface + implementations + scorer
  pipeline/             Channel-based scan→detect→output orchestration
  output/               Output writers (CSV, JSON, table) + progress
  data/                 Data file management (embed + download)
  geo/                  GeoIP lookup
```

## Testing

```bash
make test
# or
go test -race ./...
```
