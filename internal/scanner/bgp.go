package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ASInfo is the BGP-table view of an IP: the covering announced prefix (which
// may be /22, /23 or /24 depending on how the origin AS announces its space)
// plus origin ASN / country / AS name when available.
type ASInfo struct {
	ASN     int
	Prefix  netip.Prefix
	Country string
	ASName  string
	Source  string // "cymru" | "ripestat"
}

// Overridable endpoints / client — package vars so tests can point them at a
// local stub instead of the real network.
var (
	cymruWhoisAddr  = "whois.cymru.com:43"
	ripestatBaseURL = "https://stat.ripe.net/data/network-info/data.json"
	bgpHTTPClient   = &http.Client{Timeout: 15 * time.Second}
	cymruTimeout    = 10 * time.Second
	// bgpUserAgent is an honest UA (no browser spoofing) so upstreams can
	// identify and rate-limit us fairly.
	bgpUserAgent = "RealiTLScanner (+https://github.com/xtls/RealiTLScanner)"
)

// ResolvePrefix maps an IP to its covering BGP-announced prefix. Team Cymru's
// whois service (port 43, purpose-built for automation, broadly reachable) is
// tried first; RIPEstat's Data API is the fallback. Both draw from public route
// collectors (RIPE RIS et al.), so the covering prefix is the natural scan
// scope for neighbour discovery.
func ResolvePrefix(ctx context.Context, ip netip.Addr) (ASInfo, error) {
	if !ip.IsValid() {
		return ASInfo{}, errors.New("invalid IP")
	}
	info, errCymru := resolvePrefixCymru(ctx, ip)
	if errCymru == nil {
		return info, nil
	}
	info, errRipe := resolvePrefixRIPEstat(ctx, ip)
	if errRipe == nil {
		return info, nil
	}
	return ASInfo{}, fmt.Errorf("prefix lookup failed (cymru: %v; ripestat: %v)", errCymru, errRipe)
}

func resolvePrefixCymru(ctx context.Context, ip netip.Addr) (ASInfo, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", cymruWhoisAddr)
	if err != nil {
		return ASInfo{}, err
	}
	defer conn.Close()

	deadline := time.Now().Add(cymruTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	// Bulk protocol with the verbose modifier returns the 7-field record
	// including the BGP Prefix; the server closes the connection after `end`.
	query := fmt.Sprintf("begin\nverbose\n%s\nend\n", ip.String())
	if _, err := io.WriteString(conn, query); err != nil {
		return ASInfo{}, err
	}
	data, err := io.ReadAll(io.LimitReader(conn, 64<<10))
	if err != nil {
		return ASInfo{}, err
	}
	return parseCymruVerbose(string(data))
}

// parseCymruVerbose parses Team Cymru's verbose bulk response. Lines look like:
//
//	15169   | 8.8.8.8 | 8.8.8.0/24 | US | arin | 1992-12-01 | GOOGLE, US
//
// preceded by a "Bulk mode; ..." banner. The first line carrying a routable
// BGP Prefix wins.
func parseCymruVerbose(resp string) (ASInfo, error) {
	for _, line := range strings.Split(resp, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Bulk mode") {
			continue
		}
		fields := strings.Split(line, "|")
		if len(fields) < 7 {
			continue
		}
		for i := range fields {
			fields[i] = strings.TrimSpace(fields[i])
		}
		prefixStr := fields[2]
		if prefixStr == "" || prefixStr == "NA" {
			continue
		}
		prefix, err := netip.ParsePrefix(prefixStr)
		if err != nil {
			continue
		}
		asn := 0
		// fields[0] may carry multiple origins (MOAS) e.g. "1234 5678";
		// take the first.
		if toks := strings.Fields(fields[0]); len(toks) > 0 {
			asn, _ = strconv.Atoi(toks[0])
		}
		return ASInfo{
			ASN:     asn,
			Prefix:  prefix,
			Country: fields[3],
			ASName:  fields[6],
			Source:  "cymru",
		}, nil
	}
	return ASInfo{}, errors.New("cymru: no routed prefix in response")
}

func resolvePrefixRIPEstat(ctx context.Context, ip netip.Addr) (ASInfo, error) {
	u := fmt.Sprintf("%s?resource=%s&sourceapp=RealiTLScanner", ripestatBaseURL, url.QueryEscape(ip.String()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return ASInfo{}, err
	}
	req.Header.Set("User-Agent", bgpUserAgent)
	resp, err := bgpHTTPClient.Do(req)
	if err != nil {
		return ASInfo{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return ASInfo{}, fmt.Errorf("ripestat HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return ASInfo{}, err
	}
	return parseRIPEstatNetworkInfo(body)
}

func parseRIPEstatNetworkInfo(body []byte) (ASInfo, error) {
	var r struct {
		Data struct {
			Prefix string   `json:"prefix"`
			ASNs   []string `json:"asns"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return ASInfo{}, err
	}
	if r.Data.Prefix == "" {
		return ASInfo{}, errors.New("ripestat: empty prefix")
	}
	prefix, err := netip.ParsePrefix(r.Data.Prefix)
	if err != nil {
		return ASInfo{}, err
	}
	asn := 0
	if len(r.Data.ASNs) > 0 {
		asn, _ = strconv.Atoi(r.Data.ASNs[0])
	}
	return ASInfo{ASN: asn, Prefix: prefix, Source: "ripestat"}, nil
}

// PrefixAddrCount returns the total number of addresses a prefix spans — the
// scan size if we expand it wholesale. An IPv4 /24 is 256, a /22 is 1024, a
// /16 is 65536. Counts that would overflow int (large IPv6 prefixes we never
// enumerate) are clamped to math.MaxInt so the cap check still trips.
func PrefixAddrCount(p netip.Prefix) int {
	if !p.IsValid() {
		return 0
	}
	hostBits := p.Addr().BitLen() - p.Bits()
	if hostBits < 0 {
		return 0
	}
	if hostBits >= 63 {
		return math.MaxInt
	}
	return 1 << uint(hostBits)
}

// WithinHostCap is the single source of truth for the expansion safety policy:
// an expansion of count hosts is allowed when it fits under max, or when the
// user explicitly opted in with -yes. Keeps a /16 (65536) from being scanned by
// accident while letting a /22 (1024) through under the default 4096 cap.
func WithinHostCap(count, max int, yes bool) bool {
	return yes || count <= max
}

// ResolveAddrPrefix maps a single IP (or a domain, resolved via DNS) to its
// BGP-announced covering prefix and reports how many addresses that prefix
// spans. It rejects a CIDR input: -bgp expands a single host into its
// neighbourhood, and a CIDR is already a range. The count lets the caller apply
// WithinHostCap before committing to the scan.
func ResolveAddrPrefix(ctx context.Context, addr string, enableIPv6 bool) (netip.Prefix, int, error) {
	if _, _, err := net.ParseCIDR(addr); err == nil {
		return netip.Prefix{}, 0, fmt.Errorf("-bgp expects a single IP or domain, got CIDR %q", addr)
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		// Not a literal IP — try resolving it as a domain.
		netIP, lerr := LookupIP(addr, enableIPv6)
		if lerr != nil {
			return netip.Prefix{}, 0, fmt.Errorf("resolve %q: %w", addr, lerr)
		}
		ip, err = netip.ParseAddr(netIP.String())
		if err != nil {
			return netip.Prefix{}, 0, fmt.Errorf("parse resolved IP %q: %w", netIP, err)
		}
	}
	if ip.Is6() && !enableIPv6 {
		return netip.Prefix{}, 0, fmt.Errorf("%s is IPv6; pass -46 to expand its prefix", ip)
	}
	info, err := ResolvePrefix(ctx, ip)
	if err != nil {
		return netip.Prefix{}, 0, err
	}
	return info.Prefix, PrefixAddrCount(info.Prefix), nil
}
