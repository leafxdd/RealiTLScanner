package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"time"
)

// --- Smart prefix selection for -bgp neighbour discovery -------------------
//
// A single IP is usually covered by several overlapping announced prefixes: on
// bgp.tools one host might sit under a /24, a /21 and a /20 all at once. For
// neighbour discovery we want the prefix that gives a useful-but-bounded scan
// scope — enough neighbours to find a good Reality target, but not a /14's
// worth to grind through. SelectPrefix enumerates the covering prefixes (Team
// Cymru for a seed, RIPEstat routing-status for the overlapping set) and ranks
// them toward a /21-ish sweet spot.

// routing-status reports a prefix's visibility (how many RIS peers see it) plus
// its less- and more-specific overlapping routes. RIPEstat already excludes
// very-low-visibility routes (<10 RIS full-feed peers) from those lists, so the
// overlap set is effectively pre-filtered to the high-visibility prefixes we
// want — we never have to query each candidate's visibility separately.
var (
	ripestatRoutingStatusURL = "https://stat.ripe.net/data/routing-status/data.json"
	// routing-status can be slow; give it room. The context deadline is the
	// real bound and a failure/timeout degrades gracefully to the Cymru seed,
	// so the client timeout is just a backstop.
	routingStatusTimeout = 30 * time.Second
	routingStatusClient  = &http.Client{Timeout: routingStatusTimeout}
)

// Prefix-length selection window. The sweet spot for neighbour discovery is a
// /20–/24: enough hosts to find a neighbour, not so many the scan is huge. We
// aim for /21 as the centre and treat /24 as in-bounds (some IPs are only ever
// announced as a /24, so forbidding it outright is too strict).
const (
	selectWindowLo   = 20 // /20 — least-specific end of the comfortable window
	selectWindowHi   = 24 // /24 — most-specific end
	selectTargetBits = 21 // /21 — centre of the sweet spot
)

// PrefixCandidate is one announced prefix covering the target IP, tagged with
// how visible RIPEstat reports it (ris_peers_seeing / total_ris_peers). The
// visibility is carried for logging only — ranking is purely length-based,
// because RIPEstat's overlap lists are already pre-filtered to visible routes.
type PrefixCandidate struct {
	Prefix      netip.Prefix
	Visibility  float64 // 0..1; 0 when unknown / not reported
	PeersSeeing int
	PeersTotal  int
}

// SelectPrefix resolves the best covering prefix to expand for neighbour
// discovery around ip. It seeds from ResolvePrefix (Cymru, fast), asks RIPEstat
// routing-status to enumerate the overlapping prefixes, and ranks them toward
// the /20–/24 sweet spot (centre /21). It returns the chosen prefix plus the
// full candidate list (best-first) for logging.
//
// RIPEstat enumeration is best-effort: if it fails or times out, selection
// falls back to the lone Cymru seed prefix (still run through the same ranking).
func SelectPrefix(ctx context.Context, ip netip.Addr) (netip.Prefix, []PrefixCandidate, error) {
	if !ip.IsValid() || !ip.Is4() {
		return netip.Prefix{}, nil, fmt.Errorf("smart prefix selection needs an IPv4 address, got %q", ip)
	}
	seed, err := ResolvePrefix(ctx, ip)
	if err != nil {
		return netip.Prefix{}, nil, err
	}

	candidates := enumerateCandidates(ctx, ip, seed.Prefix)
	if len(candidates) == 0 {
		// Defensive: the seed is always included, so this should be unreachable.
		return seed.Prefix, []PrefixCandidate{{Prefix: seed.Prefix}}, nil
	}
	rankCandidates(candidates)
	return candidates[0].Prefix, candidates, nil
}

// SelectAddrPrefix is the -bgp entry point: it turns addr (a literal IP, or a
// domain via DNS) into an IPv4 address and runs SelectPrefix on it. It rejects
// a CIDR — -bgp expands a single host into its neighbourhood, and a CIDR is
// already a range.
func SelectAddrPrefix(ctx context.Context, addr string, enableIPv6 bool) (netip.Prefix, []PrefixCandidate, error) {
	ip, err := parseTargetIPv4(addr, enableIPv6)
	if err != nil {
		return netip.Prefix{}, nil, err
	}
	return SelectPrefix(ctx, ip)
}

// parseTargetIPv4 resolves a -bgp target to an IP address: it rejects a CIDR,
// parses a literal IP, or falls back to a DNS lookup for a domain, and refuses
// IPv6 unless enableIPv6 (neighbour discovery is IPv4-only regardless, but the
// flag keeps the error message consistent with the rest of the CLI).
func parseTargetIPv4(addr string, enableIPv6 bool) (netip.Addr, error) {
	if _, _, err := net.ParseCIDR(addr); err == nil {
		return netip.Addr{}, fmt.Errorf("-bgp expects a single IP or domain, got CIDR %q", addr)
	}
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		netIP, lerr := LookupIP(addr, enableIPv6)
		if lerr != nil {
			return netip.Addr{}, fmt.Errorf("resolve %q: %w", addr, lerr)
		}
		ip, err = netip.ParseAddr(netIP.String())
		if err != nil {
			return netip.Addr{}, fmt.Errorf("parse resolved IP %q: %w", netIP, err)
		}
	}
	if ip.Is6() && !enableIPv6 {
		return netip.Addr{}, fmt.Errorf("%s is IPv6; pass -46 to expand its prefix", ip)
	}
	return ip, nil
}

// enumerateCandidates returns the announced prefixes covering ip: the Cymru
// seed, plus RIPEstat's less-/more-specific overlaps that still contain ip. The
// seed is always present, so the result is never empty.
func enumerateCandidates(ctx context.Context, ip netip.Addr, seed netip.Prefix) []PrefixCandidate {
	byPrefix := map[netip.Prefix]*PrefixCandidate{}
	add := func(p netip.Prefix, seeing, total int) {
		if !p.IsValid() || !p.Addr().Is4() {
			return
		}
		p = p.Masked()
		if !p.Contains(ip) {
			return // overlaps elsewhere in the parent block don't cover our host
		}
		c, ok := byPrefix[p]
		if !ok {
			c = &PrefixCandidate{Prefix: p}
			byPrefix[p] = c
		}
		if total > 0 && total >= c.PeersTotal {
			c.PeersSeeing, c.PeersTotal = seeing, total
			c.Visibility = float64(seeing) / float64(total)
		}
	}

	add(seed, 0, 0)
	if rs, err := queryRoutingStatus(ctx, seed); err == nil {
		add(seed, rs.seeing, rs.total) // the seed's own visibility, now known
		for _, p := range rs.overlaps {
			add(p, 0, 0)
		}
	}

	out := make([]PrefixCandidate, 0, len(byPrefix))
	for _, c := range byPrefix {
		out = append(out, *c)
	}
	return out
}

// rankCandidates sorts candidates best-first for neighbour discovery:
//  1. inside the [/20,/24] window beats outside it;
//  2. closer to the /21 centre beats farther — this is what keeps a /21 ahead
//     of a /24 (so /24,/21,/20 → /21) rather than just grabbing the most
//     specific;
//  3. on a genuine distance tie (e.g. /20 vs /22), the more-specific wins —
//     the user's "选小的" (smaller range).
func rankCandidates(cs []PrefixCandidate) {
	inWindow := func(bits int) bool { return bits >= selectWindowLo && bits <= selectWindowHi }
	abs := func(n int) int {
		if n < 0 {
			return -n
		}
		return n
	}
	sort.SliceStable(cs, func(i, j int) bool {
		bi, bj := cs[i].Prefix.Bits(), cs[j].Prefix.Bits()
		if wi, wj := inWindow(bi), inWindow(bj); wi != wj {
			return wi // in-window first
		}
		if di, dj := abs(bi-selectTargetBits), abs(bj-selectTargetBits); di != dj {
			return di < dj // closer to /21 first
		}
		return bi > bj // tie → more-specific (larger Bits = smaller range)
	})
}

// routingStatus is the slice of a routing-status response we use: the queried
// prefix's IPv4 visibility plus its overlapping (less- and more-specific) routes.
type routingStatus struct {
	seeing   int
	total    int
	overlaps []netip.Prefix
}

func queryRoutingStatus(ctx context.Context, prefix netip.Prefix) (routingStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, routingStatusTimeout)
	defer cancel()

	u := fmt.Sprintf("%s?resource=%s&sourceapp=RealiTLScanner", ripestatRoutingStatusURL, url.QueryEscape(prefix.String()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return routingStatus{}, err
	}
	req.Header.Set("User-Agent", bgpUserAgent) // honest UA, never a browser spoof
	resp, err := routingStatusClient.Do(req)
	if err != nil {
		return routingStatus{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return routingStatus{}, fmt.Errorf("ripestat routing-status HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	if err != nil {
		return routingStatus{}, err
	}
	return parseRoutingStatus(body)
}

// parseRoutingStatus pulls the IPv4 visibility ratio and the overlapping
// prefixes out of a routing-status response. Unparseable prefix strings are
// skipped; unknown JSON fields (e.g. less_specifics' numeric "origin") are
// ignored.
func parseRoutingStatus(body []byte) (routingStatus, error) {
	type overlap struct {
		Prefix string `json:"prefix"`
	}
	var r struct {
		Data struct {
			Visibility struct {
				V4 struct {
					Seeing int `json:"ris_peers_seeing"`
					Total  int `json:"total_ris_peers"`
				} `json:"v4"`
			} `json:"visibility"`
			LessSpecifics []overlap `json:"less_specifics"`
			MoreSpecifics []overlap `json:"more_specifics"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return routingStatus{}, err
	}
	rs := routingStatus{
		seeing: r.Data.Visibility.V4.Seeing,
		total:  r.Data.Visibility.V4.Total,
	}
	collect := func(entries []overlap) {
		for _, e := range entries {
			if p, err := netip.ParsePrefix(e.Prefix); err == nil {
				rs.overlaps = append(rs.overlaps, p)
			}
		}
	}
	collect(r.Data.LessSpecifics)
	collect(r.Data.MoreSpecifics)
	return rs, nil
}
