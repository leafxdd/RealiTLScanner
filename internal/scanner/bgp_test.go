package scanner

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"
)

func TestParseCymruVerbose(t *testing.T) {
	resp := "Bulk mode; whois.cymru.com [2026-06-05 12:00:00 +0000]\n" +
		"15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 1992-12-01 | GOOGLE, US\n"
	info, err := parseCymruVerbose(resp)
	if err != nil {
		t.Fatal(err)
	}
	if info.ASN != 15169 {
		t.Errorf("ASN = %d, want 15169", info.ASN)
	}
	if info.Prefix.String() != "8.8.8.0/24" {
		t.Errorf("Prefix = %s, want 8.8.8.0/24", info.Prefix)
	}
	if info.Country != "US" {
		t.Errorf("Country = %q, want US", info.Country)
	}
	if info.ASName != "GOOGLE, US" {
		t.Errorf("ASName = %q, want 'GOOGLE, US'", info.ASName)
	}
	if info.Source != "cymru" {
		t.Errorf("Source = %q, want cymru", info.Source)
	}
}

func TestParseCymruVerbose_LargerPrefix(t *testing.T) {
	// A /22 covering prefix — the case the user observed on bgp.tools.
	resp := "Bulk mode; whois.cymru.com\n" +
		"4837 | 104.249.172.234 | 104.249.172.0/22 | US | arin | 2015-01-01 | EXAMPLE, US\n"
	info, err := parseCymruVerbose(resp)
	if err != nil {
		t.Fatal(err)
	}
	if info.Prefix.Bits() != 22 {
		t.Errorf("prefix bits = %d, want 22 (%s)", info.Prefix.Bits(), info.Prefix)
	}
}

func TestParseCymruVerbose_NotRouted(t *testing.T) {
	resp := "Bulk mode; whois.cymru.com\nNA | 192.0.2.1 | NA | NA | NA | NA | NA\n"
	if _, err := parseCymruVerbose(resp); err == nil {
		t.Error("expected error for non-routed (NA) response")
	}
}

func TestParseCymruVerbose_MOASFirstOrigin(t *testing.T) {
	resp := "Bulk mode;\n1234 5678 | 1.2.3.4 | 1.2.3.0/24 | NL | ripencc | 2020-01-01 | MULTI, NL\n"
	info, err := parseCymruVerbose(resp)
	if err != nil {
		t.Fatal(err)
	}
	if info.ASN != 1234 {
		t.Errorf("MOAS ASN = %d, want first origin 1234", info.ASN)
	}
}

func TestParseRIPEstatNetworkInfo(t *testing.T) {
	body := []byte(`{"status":"ok","data":{"prefix":"8.8.8.0/24","asns":["15169"]}}`)
	info, err := parseRIPEstatNetworkInfo(body)
	if err != nil {
		t.Fatal(err)
	}
	if info.Prefix.String() != "8.8.8.0/24" {
		t.Errorf("Prefix = %s, want 8.8.8.0/24", info.Prefix)
	}
	if info.ASN != 15169 {
		t.Errorf("ASN = %d, want 15169", info.ASN)
	}
	if info.Source != "ripestat" {
		t.Errorf("Source = %q, want ripestat", info.Source)
	}
}

func TestParseRIPEstatNetworkInfo_EmptyPrefix(t *testing.T) {
	if _, err := parseRIPEstatNetworkInfo([]byte(`{"data":{"prefix":"","asns":[]}}`)); err == nil {
		t.Error("expected error for empty prefix")
	}
	if _, err := parseRIPEstatNetworkInfo([]byte(`not json`)); err == nil {
		t.Error("expected error for malformed JSON")
	}
}

// startCymruStub runs a one-shot TCP server speaking enough of the Cymru
// protocol to answer a single query, then returns the listener address and a
// cleanup func.
func startCymruStub(t *testing.T, response string) (addr string, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf) // drain the begin/verbose/ip/end request
		_, _ = io.WriteString(conn, response)
	}()
	return ln.Addr().String(), func() { ln.Close(); <-done }
}

func TestResolvePrefix_CymruIntegration(t *testing.T) {
	addr, cleanup := startCymruStub(t,
		"Bulk mode; whois.cymru.com\n13335 | 1.1.1.1 | 1.1.1.0/24 | US | arin | 2010-01-01 | CLOUDFLARENET, US\n")
	defer cleanup()

	oldAddr := cymruWhoisAddr
	cymruWhoisAddr = addr
	defer func() { cymruWhoisAddr = oldAddr }()

	info, err := ResolvePrefix(context.Background(), netip.MustParseAddr("1.1.1.1"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Source != "cymru" || info.Prefix.String() != "1.1.1.0/24" || info.ASN != 13335 {
		t.Errorf("got %+v, want cymru 1.1.1.0/24 AS13335", info)
	}
}

func TestResolvePrefix_FallsBackToRIPEstat(t *testing.T) {
	// Cymru stub returns a non-routable answer → parse error → fallback.
	addr, cleanup := startCymruStub(t, "Bulk mode;\nNA | 9.9.9.9 | NA | NA | NA | NA | NA\n")
	defer cleanup()
	oldAddr := cymruWhoisAddr
	cymruWhoisAddr = addr
	defer func() { cymruWhoisAddr = oldAddr }()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("resource") != "9.9.9.9" {
			t.Errorf("unexpected resource param: %q", r.URL.Query().Get("resource"))
		}
		_, _ = io.WriteString(w, `{"data":{"prefix":"9.9.9.0/24","asns":["19281"]}}`)
	}))
	defer srv.Close()
	oldURL := ripestatBaseURL
	ripestatBaseURL = srv.URL
	defer func() { ripestatBaseURL = oldURL }()

	info, err := ResolvePrefix(context.Background(), netip.MustParseAddr("9.9.9.9"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Source != "ripestat" || info.Prefix.String() != "9.9.9.0/24" || info.ASN != 19281 {
		t.Errorf("got %+v, want ripestat 9.9.9.0/24 AS19281", info)
	}
}

func TestResolvePrefix_InvalidIP(t *testing.T) {
	if _, err := ResolvePrefix(context.Background(), netip.Addr{}); err == nil {
		t.Error("expected error for invalid IP")
	}
}

func TestPrefixAddrCount(t *testing.T) {
	cases := []struct {
		prefix string
		want   int
	}{
		{"1.2.3.0/24", 256},
		{"1.2.0.0/22", 1024},
		{"1.2.0.0/23", 512},
		{"1.0.0.0/16", 65536},
		{"1.2.3.4/32", 1},
	}
	for _, tc := range cases {
		if got := PrefixAddrCount(netip.MustParsePrefix(tc.prefix)); got != tc.want {
			t.Errorf("PrefixAddrCount(%s) = %d, want %d", tc.prefix, got, tc.want)
		}
	}
	if got := PrefixAddrCount(netip.Prefix{}); got != 0 {
		t.Errorf("PrefixAddrCount(invalid) = %d, want 0", got)
	}
	// A large IPv6 prefix must clamp rather than overflow int.
	if got := PrefixAddrCount(netip.MustParsePrefix("2001:db8::/48")); got <= 0 {
		t.Errorf("PrefixAddrCount(v6 /48) = %d, want a large positive (clamped)", got)
	}
}

func TestWithinHostCap(t *testing.T) {
	// Default cap 4096: a /22 (1024) passes, a /16 (65536) is blocked unless -yes.
	if !WithinHostCap(1024, 4096, false) {
		t.Error("/22 (1024) should be within the default 4096 cap")
	}
	if WithinHostCap(65536, 4096, false) {
		t.Error("/16 (65536) should exceed the default cap without -yes")
	}
	if !WithinHostCap(65536, 4096, true) {
		t.Error("-yes should allow exceeding the cap")
	}
	if !WithinHostCap(4096, 4096, false) {
		t.Error("count == max should be allowed (boundary inclusive)")
	}
}

func TestResolveAddrPrefix_RejectsCIDR(t *testing.T) {
	if _, _, err := ResolveAddrPrefix(context.Background(), "1.2.3.0/24", false); err == nil {
		t.Error("expected error: -bgp should reject a CIDR input")
	}
}

func TestResolveAddrPrefix_RejectsIPv6WithoutFlag(t *testing.T) {
	if _, _, err := ResolveAddrPrefix(context.Background(), "2001:db8::1", false); err == nil {
		t.Error("expected error: IPv6 input without -46 should be rejected")
	}
}

func TestResolveAddrPrefix_IP(t *testing.T) {
	addr, cleanup := startCymruStub(t,
		"Bulk mode; whois.cymru.com\n4837 | 104.249.172.234 | 104.249.172.0/22 | US | arin | 2015-01-01 | EXAMPLE, US\n")
	defer cleanup()
	oldAddr := cymruWhoisAddr
	cymruWhoisAddr = addr
	defer func() { cymruWhoisAddr = oldAddr }()

	prefix, count, err := ResolveAddrPrefix(context.Background(), "104.249.172.234", false)
	if err != nil {
		t.Fatal(err)
	}
	if prefix.String() != "104.249.172.0/22" {
		t.Errorf("prefix = %s, want 104.249.172.0/22", prefix)
	}
	if count != 1024 {
		t.Errorf("count = %d, want 1024 (/22)", count)
	}
}
