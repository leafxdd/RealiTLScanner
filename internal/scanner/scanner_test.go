package scanner

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/types"
)

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	return generateTestCertWithSAN(t, "localhost", nil)
}

func generateTestCertWithSAN(t *testing.T, cn string, dnsNames []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: []string{"Test Org"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func startTestTLSServerWithCert(t *testing.T, cert tls.Certificate) (string, func()) {
	t.Helper()
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS13,
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			tlsConn := conn.(*tls.Conn)
			_ = tlsConn.Handshake()
			tlsConn.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func startTestTLSServer(t *testing.T) (string, func()) {
	t.Helper()
	return startTestTLSServerWithCert(t, generateTestCert(t))
}

func TestScanTLS_LocalServer(t *testing.T) {
	addr, cleanup := startTestTLSServer(t)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	cfg := ScanConfig{
		Port:    port,
		Timeout: 5 * time.Second,
	}
	geoReader := &geo.Geo{}

	h := types.Host{
		IP:     net.ParseIP(host),
		Origin: host,
		Type:   types.HostTypeIP,
	}

	result := ScanTLS(context.Background(), h, cfg, geoReader)

	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.TLS == nil {
		t.Fatal("expected TLS info")
	}
	if result.TLS.Version != tls.VersionTLS13 {
		t.Errorf("expected TLS 1.3, got %d", result.TLS.Version)
	}
	if result.TLS.ALPN != "h2" {
		t.Errorf("expected h2 ALPN, got %s", result.TLS.ALPN)
	}
}

func portFromAddr(t *testing.T, addr string) int {
	t.Helper()
	_, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	return port
}

func TestScanTLS_PrefersSANOverCN(t *testing.T) {
	cert := generateTestCertWithSAN(t, "placeholder-cn", []string{"primary.example", "alt.example"})
	addr, cleanup := startTestTLSServerWithCert(t, cert)
	defer cleanup()

	cfg := ScanConfig{Port: portFromAddr(t, addr), Timeout: 5 * time.Second}
	h := types.Host{IP: net.ParseIP("127.0.0.1"), Origin: "127.0.0.1", Type: types.HostTypeIP}

	result := ScanTLS(context.Background(), h, cfg, &geo.Geo{})

	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.TLS == nil {
		t.Fatal("expected TLS info")
	}
	if result.TLS.CertDomain != "primary.example" {
		t.Errorf("CertDomain: got %q, want %q (first SAN)", result.TLS.CertDomain, "primary.example")
	}
}

func TestScanTLS_WildcardSANMatch(t *testing.T) {
	cert := generateTestCertWithSAN(t, "", []string{"*.wild.example"})
	addr, cleanup := startTestTLSServerWithCert(t, cert)
	defer cleanup()

	cfg := ScanConfig{Port: portFromAddr(t, addr), Timeout: 5 * time.Second}
	h := types.Host{
		IP:     net.ParseIP("127.0.0.1"),
		Origin: "api.wild.example",
		Type:   types.HostTypeDomain,
	}

	result := ScanTLS(context.Background(), h, cfg, &geo.Geo{})

	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.CertValid == nil || result.CertValid.SNIMatch == nil || !*result.CertValid.SNIMatch {
		t.Errorf("wildcard SAN should match api.wild.example; CertValid=%+v", result.CertValid)
	}
}

func TestScanTLS_RespectsContextCancel(t *testing.T) {
	// Server that accepts TCP but never sends TLS handshake — forces client to hang.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				<-done
				c.Close()
			}(c)
		}
	}()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}

	cfg := ScanConfig{
		Port:    port,
		Timeout: 30 * time.Second, // long timeout — cancel must win
	}
	h := types.Host{
		IP:     net.ParseIP(host),
		Origin: host,
		Type:   types.HostTypeIP,
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	result := ScanTLS(ctx, h, cfg, &geo.Geo{})
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Errorf("ScanTLS did not return promptly after ctx cancel: %v", elapsed)
	}
	if result.Error != "cancelled" {
		t.Errorf("expected error 'cancelled', got %q", result.Error)
	}
}

func TestValidateDomainName(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"invalid domain", false},
		{"test-site.org", true},
	}
	for _, tt := range tests {
		got := ValidateDomainName(tt.domain)
		if got != tt.valid {
			t.Errorf("ValidateDomainName(%q) = %v, want %v", tt.domain, got, tt.valid)
		}
	}
}

func TestStrictDomainName_Edges(t *testing.T) {
	tests := []struct {
		domain string
		valid  bool
	}{
		{"example.com", true},
		{"sub.example.com", true},
		{"a.b", true},
		{"test-site.org", true},
		{"", false},
		{"a..b", false},
		{"-x.com", false},
		{"x-.com", false},
		{"x.-com", false},
		{".example.com", false},
		{"example.com.", false},
		{"invalid domain", false},
		{"foo,bar", false},
		{"*.example.com", false},
		{strings.Repeat("a", 64) + ".com", false}, // label > 63
		{strings.Repeat("a.", 130) + "a", false},  // total > 253
	}
	for _, tt := range tests {
		got := StrictDomainName(tt.domain)
		if got != tt.valid {
			t.Errorf("StrictDomainName(%q) = %v, want %v", tt.domain, got, tt.valid)
		}
	}
}

func TestReadCSVDomains_HandlesQuotedFields(t *testing.T) {
	// Earlier strings.Split parser would mis-count columns when an upstream
	// field (e.g. CERT_ISSUER "Cloudflare, Inc.") contained a comma, shifting
	// every subsequent column. encoding/csv must keep quoted fields intact.
	csvContent := `IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE
1.2.3.4,foo.example,foo.example,"Cloudflare, Inc.",US
5.6.7.8,bar.example,bar.example,DigiCert,DE
9.9.9.9,baz.example,baz.example,"Let""s Encrypt",JP
`
	dir := t.TempDir()
	path := filepath.Join(dir, "input.csv")
	if err := os.WriteFile(path, []byte(csvContent), 0644); err != nil {
		t.Fatal(err)
	}

	ch, count, err := ReadCSVDomains(path)
	if err != nil {
		t.Fatal(err)
	}

	var got []string
	for h := range ch {
		got = append(got, h.Origin)
	}

	want := []string{"foo.example", "bar.example", "baz.example"}
	if count != len(want) {
		t.Errorf("expected %d domains, got %d", len(want), count)
	}
	if len(got) != len(want) {
		t.Fatalf("expected %d hosts, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("domain[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

func TestIterateAddrInfinite_SingleHostByDefault(t *testing.T) {
	ch := IterateAddrInfinite("127.0.0.1", false, false)

	count := 0
	timeout := time.After(2 * time.Second)
loop:
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				break loop
			}
			count++
		case <-timeout:
			t.Fatalf("channel did not close within 2s; received %d hosts", count)
		}
	}
	if count != 1 {
		t.Errorf("expected 1 host in non-infinite mode, got %d", count)
	}
}

func TestIterateAddrInfinite_InfiniteFlag(t *testing.T) {
	// With infinite=true, the producer keeps emitting neighbour IPs.
	ch := IterateAddrInfinite("10.0.0.5", false, true)

	const want = 5
	got := 0
	deadline := time.After(2 * time.Second)
	for got < want {
		select {
		case _, ok := <-ch:
			if !ok {
				t.Fatalf("channel closed early after %d hosts", got)
			}
			got++
		case <-deadline:
			t.Fatalf("did not get %d hosts within 2s (got %d)", want, got)
		}
	}
}

func TestIterateCtx_CIDRCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := IterateCtx(ctx, strings.NewReader("10.0.0.0/16\n"), false)

	// Read one host to confirm production started.
	select {
	case <-ch:
	case <-time.After(2 * time.Second):
		t.Fatal("expected first host within 2s")
	}

	startGoroutines := runtime.NumGoroutine()
	cancel()

	// Drain — producer should close channel after observing ctx.Done.
	drained := make(chan struct{})
	go func() {
		for range ch {
		}
		close(drained)
	}()

	select {
	case <-drained:
	case <-time.After(3 * time.Second):
		t.Fatal("producer goroutine did not exit within 3s after context cancel")
	}

	// Goroutine count should not have grown (producer exited).
	endGoroutines := runtime.NumGoroutine()
	if endGoroutines > startGoroutines {
		t.Logf("goroutine count: start=%d end=%d", startGoroutines, endGoroutines)
	}
}

func TestNextIP_OverflowIPv4ReturnsNil(t *testing.T) {
	max := net.ParseIP("255.255.255.255").To4()
	if got := NextIP(max, true); got != nil {
		t.Errorf("NextIP(255.255.255.255, +1) = %v, want nil", got)
	}
}

func TestNextIP_UnderflowIPv4ReturnsNil(t *testing.T) {
	min := net.ParseIP("0.0.0.0").To4()
	if got := NextIP(min, false); got != nil {
		t.Errorf("NextIP(0.0.0.0, -1) = %v, want nil", got)
	}
}

func TestNextIP_NormalIncrement(t *testing.T) {
	ip := net.ParseIP("10.0.0.5").To4()
	got := NextIP(ip, true)
	if got == nil {
		t.Fatal("expected non-nil")
	}
	if got.String() != "10.0.0.6" {
		t.Errorf("NextIP(10.0.0.5, +1) = %v, want 10.0.0.6", got)
	}
}

func TestIterateAddrInfinite_StopsAtBoundary(t *testing.T) {
	// Start near IPv4 max; infinite mode alternates low/high.
	// High side will overflow after a few steps and should close the channel.
	ch := IterateAddrInfinite("255.255.255.253", false, true)
	count := 0
	deadline := time.After(3 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				// channel closed cleanly — expected after overflow stops producer
				return
			}
			count++
			if count > 1000 {
				t.Fatalf("producer did not stop after overflow (received %d)", count)
			}
		case <-deadline:
			t.Fatalf("did not observe channel close within 3s (received %d)", count)
		}
	}
}

func TestIterateFileCtx_ClosesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.txt")
	if err := os.WriteFile(path, []byte("1.2.3.4\n5.6.7.8\n"), 0644); err != nil {
		t.Fatal(err)
	}

	ch, err := IterateFileCtx(context.Background(), path, false)
	if err != nil {
		t.Fatal(err)
	}
	for range ch {
	}

	// On Windows an open file cannot be removed; os.Remove succeeding implies
	// the underlying handle was released by the producer goroutine.
	if err := os.Remove(path); err != nil {
		t.Errorf("file not closed after iteration (remove failed): %v", err)
	}
}

func TestIterateFileCtx_OpenError(t *testing.T) {
	_, err := IterateFileCtx(context.Background(), filepath.Join(t.TempDir(), "nope.txt"), false)
	if err == nil {
		t.Error("expected open error for missing file")
	}
}
