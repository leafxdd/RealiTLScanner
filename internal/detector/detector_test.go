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

func TestDetectorInterface(t *testing.T) {
	detectors := []Detector{
		NewTLSCheckDetector(),
		NewRedirectDetector(0),
		NewStatusDetector(0),
	}

	for _, d := range detectors {
		if d.Name() == "" {
			t.Error("detector Name() should not be empty")
		}
		if !d.Available() {
			t.Errorf("detector %s should be available", d.Name())
		}
	}
}

func TestCDNDetector_Unavailable(t *testing.T) {
	d := NewCDNDetector("")
	if d.Available() {
		t.Error("CDN detector without keywords should not be available")
	}
}

func TestGFWDetector_Unavailable(t *testing.T) {
	d := NewGFWDetector("")
	if d.Available() {
		t.Error("GFW detector without list should not be available")
	}
}

func TestTLSCheckDetector(t *testing.T) {
	d := NewTLSCheckDetector()
	result := &types.ScanResult{
		Host: types.Host{Origin: "example.com", Type: types.HostTypeDomain},
		TLS: &types.TLSInfo{
			Version:    0x0304, // TLS 1.3
			ALPN:       "h2",
			CertDomain: "example.com",
			CertIssuer: "Let's Encrypt",
		},
	}
	err := d.Detect(context.Background(), result)
	if err != nil {
		t.Fatal(err)
	}
	if result.CertValid == nil {
		t.Fatal("expected CertValid to be set")
	}
	if !result.CertValid.Valid {
		t.Error("expected valid TLS config")
	}
	if result.CertValid.SNIMatch == nil {
		t.Fatal("expected SNIMatch to be set for domain scan")
	}
	if !*result.CertValid.SNIMatch {
		t.Error("expected SNI match")
	}
}

func TestTLSCheckDetector_IPScan_SNIMatchIsNil(t *testing.T) {
	d := NewTLSCheckDetector()
	result := &types.ScanResult{
		Host: types.Host{Origin: "1.2.3.4", Type: types.HostTypeIP},
		TLS: &types.TLSInfo{
			Version:    0x0304,
			ALPN:       "h2",
			CertDomain: "example.com",
			CertIssuer: "Let's Encrypt",
		},
	}
	if err := d.Detect(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if result.CertValid == nil {
		t.Fatal("expected CertValid to be set")
	}
	if result.CertValid.SNIMatch != nil {
		t.Errorf("expected SNIMatch nil for IP scan, got %v", *result.CertValid.SNIMatch)
	}
}

func TestTLSCheckDetector_DomainScan_MismatchingSNI(t *testing.T) {
	d := NewTLSCheckDetector()
	result := &types.ScanResult{
		Host: types.Host{Origin: "example.com", Type: types.HostTypeDomain},
		TLS: &types.TLSInfo{
			Version:    0x0304,
			ALPN:       "h2",
			CertDomain: "other.example.org",
			CertIssuer: "Let's Encrypt",
		},
	}
	if err := d.Detect(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if result.CertValid == nil {
		t.Fatal("expected CertValid to be set")
	}
	if result.CertValid.SNIMatch == nil {
		t.Fatal("expected SNIMatch set (not nil) for domain scan")
	}
	if *result.CertValid.SNIMatch {
		t.Error("expected SNIMatch false when cert domain differs from origin")
	}
}

func TestRunner(t *testing.T) {
	d := NewTLSCheckDetector()
	runner := NewRunner([]Detector{d}, 1)

	in := make(chan *types.ScanResult, 1)
	in <- &types.ScanResult{
		Host: types.Host{Origin: "test.com"},
		TLS: &types.TLSInfo{
			Version:    0x0304,
			ALPN:       "h2",
			CertDomain: "test.com",
			CertIssuer: "Test CA",
		},
	}
	close(in)

	out := runner.Run(context.Background(), in)
	result := <-out
	if result == nil {
		t.Fatal("expected result from runner")
	}
	if result.CertValid == nil {
		t.Fatal("expected CertValid to be set by runner")
	}
}

func TestStatusDetector_PreservesRedirectStatusCode(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	d := NewStatusDetector(2 * time.Second)
	d.client = server.Client()

	result := &types.ScanResult{
		TLS:      &types.TLSInfo{CertDomain: u.Host},
		Redirect: &types.RedirectResult{StatusCode: 301, Target: "https://elsewhere.example", Redirects: true},
	}
	if err := d.Detect(context.Background(), result); err != nil {
		t.Fatal(err)
	}

	if result.Redirect.StatusCode != 301 {
		t.Errorf("expected Redirect.StatusCode preserved as 301, got %d", result.Redirect.StatusCode)
	}
	if result.Redirect.Target != "https://elsewhere.example" {
		t.Errorf("expected Redirect.Target preserved, got %q", result.Redirect.Target)
	}
	if !result.Redirect.Redirects {
		t.Error("expected Redirects flag preserved as true")
	}
}

func TestStatusDetector_WritesWhenRedirectIsNil(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	d := NewStatusDetector(2 * time.Second)
	d.client = server.Client()

	result := &types.ScanResult{
		TLS: &types.TLSInfo{CertDomain: u.Host},
	}
	if err := d.Detect(context.Background(), result); err != nil {
		t.Fatal(err)
	}

	if result.Redirect == nil {
		t.Fatal("expected Redirect to be set")
	}
	if result.Redirect.StatusCode != 200 {
		t.Errorf("expected StatusCode 200, got %d", result.Redirect.StatusCode)
	}
}

func TestRedirectDetector_HonorsInjectedClient(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://elsewhere.example/")
		w.WriteHeader(http.StatusMovedPermanently)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	d := NewRedirectDetector(2 * time.Second)
	d.client = server.Client() // inject — bypasses isSafeForProbe
	d.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	result := &types.ScanResult{
		TLS: &types.TLSInfo{CertDomain: u.Host},
	}
	if err := d.Detect(context.Background(), result); err != nil {
		t.Fatal(err)
	}
	if result.Redirect == nil {
		t.Fatal("expected Redirect set")
	}
	if result.Redirect.StatusCode != http.StatusMovedPermanently {
		t.Errorf("StatusCode: got %d, want 301", result.Redirect.StatusCode)
	}
	if result.Redirect.Target != "https://elsewhere.example/" {
		t.Errorf("Target: got %q, want elsewhere", result.Redirect.Target)
	}
}

func TestRedirectDetector_ReuseTransport(t *testing.T) {
	d := NewRedirectDetector(2 * time.Second)
	if d.client == nil {
		t.Fatal("expected pre-constructed client")
	}
	tr, ok := d.client.Transport.(*http.Transport)
	if !ok {
		t.Fatal("expected *http.Transport on default client")
	}
	if tr.MaxIdleConnsPerHost == 0 {
		t.Error("expected MaxIdleConnsPerHost > 0 (connection pool reuse)")
	}
}

func TestRunner_SetsScore(t *testing.T) {
	d := NewTLSCheckDetector()
	runner := NewRunner([]Detector{d}, 1)

	in := make(chan *types.ScanResult, 1)
	in <- &types.ScanResult{
		Host: types.Host{Origin: "example.com", Type: types.HostTypeDomain},
		TLS: &types.TLSInfo{
			Version:       0x0304,
			ALPN:          "h2",
			CertDomain:    "example.com",
			CertIssuer:    "Test CA",
			HandshakeTime: 100 * time.Millisecond,
			CertExpiry:    time.Now().Add(120 * 24 * time.Hour),
		},
	}
	close(in)

	out := runner.Run(context.Background(), in)
	result := <-out
	if result == nil {
		t.Fatal("expected result from runner")
	}
	if result.Score <= 0 {
		t.Errorf("expected runner to set Score > 0, got %d", result.Score)
	}
}