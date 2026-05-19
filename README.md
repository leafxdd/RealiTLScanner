# RealiTLScanner

A high-performance TLS certificate scanner with integrated Reality protocol domain evaluation. Scans IP/CIDR/domain targets for TLS certificates and optionally evaluates domain feasibility through multiple detectors (CDN, GFW, redirect, hot website, etc.).

## Features

- TLS certificate scanning (IP, CIDR, domain)
- Concurrent scanning with configurable thread count
- Infinity mode (auto-expand from single IP/domain)
- GeoIP location lookup
- **Integrated detectors**: CDN detection, GFW block detection, TLS validation, hot website identification, redirect detection
- **Multiple output formats**: CSV, JSON, JSONL
- **Real-time progress reporting**
- **Subcommand CLI**: `scan`, `check`, `version`
- Docker support

## Building

Requirement: Go 1.21+

```bash
make build
# or
go build -o RealiTLScanner ./cmd/realitlscanner
```

## Usage

### Basic Scanning (backward compatible)

```bash
# Scan a specific IP, IP CIDR or domain (infinity mode auto-enabled for single IP/domain):
./RealiTLScanner -addr 1.2.3.4

# Scan from file:
./RealiTLScanner -in targets.txt

# Crawl domains from URL:
./RealiTLScanner -url https://launchpad.net/ubuntu/+archivemirrors

# Custom port, threads, timeout:
./RealiTLScanner -addr 107.172.1.0/24 -port 443 -thread 10 -timeout 5

# Verbose output:
./RealiTLScanner -addr 1.2.3.0/24 -v

# Save to file:
./RealiTLScanner -addr 1.2.3.0/24 -out results.csv
```

### Scan with Detection

```bash
# Enable all detectors (CDN, GFW, TLS check, hot website, redirect, etc.):
./RealiTLScanner scan -addr 1.2.3.0/24 -detect

# JSON output:
./RealiTLScanner scan -addr 1.2.3.0/24 -detect -format json

# JSONL output (streaming, one result per line):
./RealiTLScanner scan -addr 1.2.3.0/24 -detect -format jsonl

# Extended CSV (includes detection columns):
./RealiTLScanner scan -addr 1.2.3.0/24 -detect -format csv-extended

# Batch mode (scan all first, then detect):
./RealiTLScanner scan -addr 1.2.3.0/24 -detect -batch

# Select specific detectors:
./RealiTLScanner scan -addr 1.2.3.0/24 -detect -detectors cdn,gfw,tls_check

# Specify data files directory:
./RealiTLScanner scan -addr 1.2.3.0/24 -detect -data-dir ./data
```

### Single Domain Check

```bash
# Full check on a single domain (scan + all detectors + formatted report):
./RealiTLScanner check example.com

# With custom port:
./RealiTLScanner check example.com -port 8443
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
docker run --rm realitlscanner -addr 1.1.1.1
docker run --rm realitlscanner scan -addr 1.1.1.0/24 -detect -format json
docker run --rm realitlscanner check example.com
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

CDN keywords and hot websites are embedded in the binary. GeoIP and GFW list are downloaded on first use when `--detect` is enabled.

## Output Formats

### CSV (default)

```csv
IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
202.70.64.2,ntc.net.np,*.ntc.net.np,"GlobalSign nv-sa",NP
103.194.167.213,mirror.i3d.net,*.i3d.net,"Sectigo Limited",JP
```

### CSV Extended (`-format csv-extended`)

```csv
IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE,CDN_LEVEL,GFW_BLOCKED,SCORE
1.2.3.4,example.com,example.com,"Let's Encrypt",US,none,false,85
```

### JSON (`-format json`)

```json
{
  "metadata": { "version": "2.0", "timestamp": "..." },
  "results": [
    {
      "ip": "1.2.3.4",
      "origin": "example.com",
      "tls": { "version": "0x0304", "alpn": "h2", "cert_domain": "...", "cert_issuer": "..." },
      "geo_code": "US",
      "cdn": { "level": "none" },
      "gfw": { "blocked": false },
      "feasible": true
    }
  ],
  "summary": { "total_scanned": 100, "feasible_count": 5, "detection_rate": "5%" }
}
```

### JSONL (`-format jsonl`)

One JSON object per line, suitable for streaming and piping.

## Project Structure

```
cmd/realitlscanner/     CLI entry point (subcommand routing)
internal/
  types/                Shared types (Host, ScanResult)
  scanner/              TLS scanning logic
  detector/             Detector interface + implementations
  pipeline/             Channel-based scan→detect→output orchestration
  output/               Multi-format output (CSV, JSON, JSONL, progress)
  data/                 Data file management (embed + download)
  geo/                  GeoIP lookup
```

## Testing

```bash
make test
# or
go test -race ./...
```
