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
	"strings"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/types"
)

func generateTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost", Organization: []string{"Test Org"}},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
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

func startTestTLSServer(t *testing.T) (string, func()) {
	t.Helper()
	cert := generateTestCert(t)
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

func TestScanTLS_LocalServer(t *testing.T) {
	addr, cleanup := startTestTLSServer(t)
	defer cleanup()

	host, portStr, _ := net.SplitHostPort(addr)
	port := 0
	for _, c := range portStr {
		port = port*10 + int(c-'0')
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

