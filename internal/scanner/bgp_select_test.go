package scanner

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestParseRoutingStatus(t *testing.T) {
	body := []byte(`{"data":{` +
		`"visibility":{"v4":{"ris_peers_seeing":324,"total_ris_peers":326}},` +
		`"less_specifics":[{"prefix":"154.219.96.0/20"},{"prefix":"154.219.96.0/21"}],` +
		`"more_specifics":[{"prefix":"154.219.96.0/24"}]}}`)
	rs, err := parseRoutingStatus(body)
	if err != nil {
		t.Fatal(err)
	}
	if rs.seeing != 324 || rs.total != 326 {
		t.Errorf("visibility = %d/%d, want 324/326", rs.seeing, rs.total)
	}
	if len(rs.overlaps) != 3 {
		t.Fatalf("overlaps = %v, want 3 entries", rs.overlaps)
	}
	got := map[string]bool{}
	for _, p := range rs.overlaps {
		got[p.String()] = true
	}
	for _, want := range []string{"154.219.96.0/20", "154.219.96.0/21", "154.219.96.0/24"} {
		if !got[want] {
			t.Errorf("overlaps missing %s (got %v)", want, rs.overlaps)
		}
	}
}

func TestParseRoutingStatus_IgnoresNumericOrigin(t *testing.T) {
	// less_specifics carries a numeric "origin" — we only read "prefix", and the
	// numeric field must not break parsing.
	rs, err := parseRoutingStatus([]byte(`{"data":{"less_specifics":[{"prefix":"1.2.0.0/20","origin":401701}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(rs.overlaps) != 1 || rs.overlaps[0].String() != "1.2.0.0/20" {
		t.Errorf("overlaps = %v, want [1.2.0.0/20]", rs.overlaps)
	}
}

// cand builds a length-only candidate; only Bits() matters for ranking.
func cand(bits int) PrefixCandidate {
	return PrefixCandidate{Prefix: netip.PrefixFrom(netip.MustParseAddr("10.0.0.0"), bits).Masked()}
}

func TestRankCandidates(t *testing.T) {
	// Every one of the user's real bgp.tools examples, plus the tie rule.
	cases := []struct {
		name string
		bits []int
		want int
	}{
		{"腾讯 only /19", []int{19}, 19},
		{"HK /24 /21 /20 → /21", []int{24, 21, 20}, 21},
		{"US /23 /16 → /23 (/16 too broad)", []int{23, 16}, 23},
		{"JP /14 /21 /24 → /21", []int{14, 21, 24}, 21},
		{"103 /22 /23 /24 → /22", []int{22, 23, 24}, 22},
		{"tie /20 vs /22 → 选小的 /22", []int{20, 22}, 22},
		{"only broad /16 /14 → closest /16", []int{16, 14}, 16},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cs := make([]PrefixCandidate, len(tc.bits))
			for i, b := range tc.bits {
				cs[i] = cand(b)
			}
			rankCandidates(cs)
			if got := cs[0].Prefix.Bits(); got != tc.want {
				t.Errorf("winner = /%d, want /%d (order %v)", got, tc.want, cs)
			}
		})
	}
}

// stubRoutingStatus points ripestatRoutingStatusURL at a server returning body
// for any request, and restores it on cleanup.
func stubRoutingStatus(t *testing.T, status int, body string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Honest UA — identify the tool, never spoof a browser.
		if ua := r.Header.Get("User-Agent"); ua != bgpUserAgent {
			t.Errorf("User-Agent = %q, want honest %q", ua, bgpUserAgent)
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	old := ripestatRoutingStatusURL
	ripestatRoutingStatusURL = srv.URL
	t.Cleanup(func() { ripestatRoutingStatusURL = old })
}

func TestSelectPrefix_PrefersSweetSpotOverSeed(t *testing.T) {
	// Cymru hands back a narrow /24 seed; routing-status reveals a covering /22.
	// Selection must climb to the /22 sweet spot, not stay on the /24.
	addr, cleanup := startCymruStub(t,
		"Bulk mode; whois.cymru.com\n64500 | 203.0.113.37 | 203.0.113.0/24 | US | arin | 2020-01-01 | EXAMPLE, US\n")
	defer cleanup()
	oldCymru := cymruWhoisAddr
	cymruWhoisAddr = addr
	defer func() { cymruWhoisAddr = oldCymru }()

	stubRoutingStatus(t, http.StatusOK, `{"data":{`+
		`"visibility":{"v4":{"ris_peers_seeing":300,"total_ris_peers":326}},`+
		`"less_specifics":[{"prefix":"203.0.112.0/22"}],"more_specifics":[]}}`)

	prefix, cands, err := SelectPrefix(context.Background(), netip.MustParseAddr("203.0.113.37"))
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != "203.0.112.0/22" {
		t.Errorf("selected %s, want the /22 sweet spot 203.0.112.0/22", prefix)
	}
	// Both the /24 seed and the /22 overlap should be in the candidate list, and
	// the seed must carry the visibility routing-status reported for it.
	var seedSeen bool
	for _, c := range cands {
		if c.Prefix.String() == "203.0.113.0/24" {
			seedSeen = true
			if c.PeersTotal != 326 || c.PeersSeeing != 300 {
				t.Errorf("seed visibility = %d/%d, want 300/326", c.PeersSeeing, c.PeersTotal)
			}
		}
	}
	if !seedSeen {
		t.Errorf("candidate list %v missing the /24 seed", cands)
	}
}

func TestSelectPrefix_FallsBackToSeedOnRIPEstatError(t *testing.T) {
	// routing-status is down (500). Selection must degrade to the lone Cymru
	// seed rather than failing the whole resolve.
	addr, cleanup := startCymruStub(t,
		"Bulk mode; whois.cymru.com\n64500 | 198.51.100.10 | 198.51.100.0/22 | US | arin | 2020-01-01 | EXAMPLE, US\n")
	defer cleanup()
	oldCymru := cymruWhoisAddr
	cymruWhoisAddr = addr
	defer func() { cymruWhoisAddr = oldCymru }()

	stubRoutingStatus(t, http.StatusInternalServerError, "boom")

	prefix, cands, err := SelectPrefix(context.Background(), netip.MustParseAddr("198.51.100.10"))
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != "198.51.100.0/22" {
		t.Errorf("selected %s, want the seed 198.51.100.0/22", prefix)
	}
	if len(cands) != 1 {
		t.Errorf("candidates = %v, want just the seed", cands)
	}
}

func TestSelectPrefix_IPv6Rejected(t *testing.T) {
	if _, _, err := SelectPrefix(context.Background(), netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Error("expected SelectPrefix to reject IPv6 (neighbour discovery is IPv4-only)")
	}
}

func TestParseTargetIPv4(t *testing.T) {
	if _, err := parseTargetIPv4("1.2.3.0/24", false); err == nil {
		t.Error("expected CIDR input to be rejected (-bgp expands a single host)")
	}
	if _, err := parseTargetIPv4("2001:db8::1", false); err == nil {
		t.Error("expected IPv6 without -46 to be rejected")
	}
	ip, err := parseTargetIPv4("104.249.172.234", false)
	if err != nil {
		t.Fatal(err)
	}
	if ip.String() != "104.249.172.234" {
		t.Errorf("ip = %s, want 104.249.172.234", ip)
	}
}

func TestSelectAddrPrefix_RejectsCIDR(t *testing.T) {
	if _, _, err := SelectAddrPrefix(context.Background(), "1.2.3.0/24", false); err == nil {
		t.Error("expected -bgp smart selection to reject a CIDR input")
	}
}

func TestSelectAddrPrefix_IP(t *testing.T) {
	addr, cleanup := startCymruStub(t,
		"Bulk mode; whois.cymru.com\n4837 | 104.249.172.234 | 104.249.172.0/22 | US | arin | 2015-01-01 | EXAMPLE, US\n")
	defer cleanup()
	oldCymru := cymruWhoisAddr
	cymruWhoisAddr = addr
	defer func() { cymruWhoisAddr = oldCymru }()
	// routing-status down → falls back to the lone Cymru seed (/22).
	stubRoutingStatus(t, http.StatusInternalServerError, "boom")

	prefix, cands, err := SelectAddrPrefix(context.Background(), "104.249.172.234", false)
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != "104.249.172.0/22" {
		t.Errorf("prefix = %s, want 104.249.172.0/22", prefix)
	}
	if len(cands) == 0 {
		t.Error("expected at least the seed candidate")
	}
}
