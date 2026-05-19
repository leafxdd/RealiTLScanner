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

func TestResultToCSV(t *testing.T) {
	r := &types.ScanResult{
		Host:    types.Host{Origin: "example.com"},
		IP:      net.ParseIP("1.2.3.4"),
		GeoCode: "US",
		TLS: &types.TLSInfo{
			CertDomain: "example.com",
			CertIssuer: "Let's Encrypt",
		},
	}
	csv := ResultToCSV(r)
	expected := "1.2.3.4,example.com,example.com,Let's Encrypt,US\n"
	if csv != expected {
		t.Errorf("expected %q, got %q", expected, csv)
	}
}

func TestResultToCSV_WithComma(t *testing.T) {
	r := &types.ScanResult{
		Host:    types.Host{Origin: "cdn.example.com"},
		IP:      net.ParseIP("1.2.3.4"),
		GeoCode: "US",
		TLS: &types.TLSInfo{
			CertDomain: "Cloudflare, Inc.",
			CertIssuer: "DigiCert, Inc.",
		},
	}
	csv := ResultToCSV(r)
	expected := "1.2.3.4,cdn.example.com,\"Cloudflare, Inc.\",\"DigiCert, Inc.\",US\n"
	if csv != expected {
		t.Errorf("expected %q, got %q", expected, csv)
	}
}

func TestCsvEscape(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"simple", "simple"},
		{"has,comma", "\"has,comma\""},
		{"has\"quote", "\"has\"\"quote\""},
		{"has\nnewline", "\"has\nnewline\""},
	}
	for _, tt := range tests {
		got := CsvEscape(tt.input)
		if got != tt.want {
			t.Errorf("CsvEscape(%q) = %q, want %q", tt.input, got, tt.want)
		}
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

