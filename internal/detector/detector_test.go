package detector

import (
	"context"
	"testing"

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
		Host: types.Host{Origin: "example.com"},
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
	if !result.CertValid.SNIMatch {
		t.Error("expected SNI match")
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
