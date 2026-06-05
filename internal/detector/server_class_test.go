package detector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

func TestClassifyServer(t *testing.T) {
	cases := []struct {
		in   string
		want serverCategory
	}{
		{"", serverNone},
		{"   ", serverNone},
		{"nginx", serverWeb},
		{"nginx/1.25.3", serverWeb},
		{"cloudflare", serverWeb},
		{"Apache/2.4.41 (Ubuntu)", serverWeb},
		{"Caddy", serverWeb},
		{"x-ui", serverProxy},
		{"3x-ui", serverProxy},
		{"sing-box", serverProxy},
		{"some-v2board-panel", serverProxy},
		{"GoFancyServer/9", serverUnknown},
	}
	for _, tc := range cases {
		if got := classifyServer(tc.in); got != tc.want {
			t.Errorf("classifyServer(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestVetoIfProxyServer(t *testing.T) {
	// Proxy server → veto.
	r := &types.ScanResult{Feasible: true, TLS: &types.TLSInfo{CertDomain: "x.example"}}
	vetoIfProxyServer(r, "x-ui")
	if r.Block == nil || !r.Block.Hit || r.Block.Reason != "proxy_server" {
		t.Errorf("expected proxy_server block, got %+v", r.Block)
	}
	if r.Feasible {
		t.Error("expected Feasible flipped to false")
	}

	// Web server → no veto.
	r2 := &types.ScanResult{Feasible: true, TLS: &types.TLSInfo{CertDomain: "x.example"}}
	vetoIfProxyServer(r2, "nginx")
	if r2.Block != nil {
		t.Errorf("web server must not set Block, got %+v", r2.Block)
	}
	if !r2.Feasible {
		t.Error("web server must not flip Feasible")
	}

	// Does not clobber a more specific domain blocklist hit.
	r3 := &types.ScanResult{
		Feasible: false,
		TLS:      &types.TLSInfo{CertDomain: "vless.example"},
		Block:    &types.BlockResult{Hit: true, Reason: "proxy_keyword", Keywords: []string{"vless"}},
	}
	vetoIfProxyServer(r3, "x-ui")
	if r3.Block.Reason != "proxy_keyword" {
		t.Errorf("must not clobber existing block reason, got %q", r3.Block.Reason)
	}
}

func TestRedirectDetector_ServerHeaderProxyVeto(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "x-ui")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	d := NewRedirectDetector(2 * time.Second)
	d.client = server.Client()
	d.testInjected = true
	d.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	result := &types.ScanResult{Feasible: true, TLS: &types.TLSInfo{CertDomain: u.Host}}
	if err := d.Detect(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if result.Redirect == nil || result.Redirect.Server != "x-ui" {
		t.Fatalf("expected Server header recorded as x-ui, got %+v", result.Redirect)
	}
	if result.Block == nil || !result.Block.Hit || result.Block.Reason != "proxy_server" {
		t.Errorf("expected proxy_server veto, got %+v", result.Block)
	}
	if result.Feasible {
		t.Error("expected Feasible=false after proxy-panel server")
	}
}

func TestRedirectDetector_ServerHeaderWebRecorded(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	d := NewRedirectDetector(2 * time.Second)
	d.client = server.Client()
	d.testInjected = true
	d.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	result := &types.ScanResult{Feasible: true, TLS: &types.TLSInfo{CertDomain: u.Host}}
	if err := d.Detect(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if result.Redirect == nil || result.Redirect.Server != "nginx" {
		t.Fatalf("expected Server header recorded as nginx, got %+v", result.Redirect)
	}
	if result.Block != nil {
		t.Errorf("web server must not disqualify, got %+v", result.Block)
	}
	if !result.Feasible {
		t.Error("web server must not flip Feasible")
	}
}
