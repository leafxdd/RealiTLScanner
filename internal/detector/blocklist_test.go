package detector

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

func testBlocklist() *BlocklistDetector {
	return &BlocklistDetector{
		keywords: []string{"vless", "x-ui", "xui", "trojan"},
		suffixes: []blockSuffix{
			{".nip.io", "dynamic_dns"},
			{".duckdns.org", "dynamic_dns"},
			{".quickconnect.to", "nas"},
		},
		tlds: []string{".xyz", ".top"},
	}
}

func blockDetect(d *BlocklistDetector, domain string) *types.ScanResult {
	r := &types.ScanResult{
		Feasible: true,
		TLS:      &types.TLSInfo{CertDomain: domain},
	}
	_ = d.Detect(context.Background(), r)
	return r
}

func TestBlocklistDetector_HardHits(t *testing.T) {
	d := testBlocklist()
	cases := []struct {
		domain string
		reason string
	}{
		{"vless.example.com", "proxy_keyword"},
		{"panel.x-ui.net", "proxy_keyword"},
		{"my.trojan.io", "proxy_keyword"},
		{"home.nip.io", "dynamic_dns"},
		{"foo.bar.duckdns.org", "dynamic_dns"},
		{"nas.quickconnect.to", "nas"},
	}
	for _, tc := range cases {
		r := blockDetect(d, tc.domain)
		if r.Block == nil || !r.Block.Hit {
			t.Errorf("%s: expected hard block hit, got %+v", tc.domain, r.Block)
			continue
		}
		if r.Block.Reason != tc.reason {
			t.Errorf("%s: reason = %q, want %q", tc.domain, r.Block.Reason, tc.reason)
		}
		if r.Feasible {
			t.Errorf("%s: expected Feasible flipped to false on hard hit", tc.domain)
		}
	}
}

func TestBlocklistDetector_CheapTLDIsSoft(t *testing.T) {
	d := testBlocklist()
	r := blockDetect(d, "shop.example.xyz")
	if r.Block == nil {
		t.Fatal("expected Block set for cheap TLD")
	}
	if r.Block.Hit {
		t.Error("cheap TLD must NOT be a hard hit")
	}
	if !r.Block.CheapTLD {
		t.Error("expected CheapTLD true")
	}
	if !r.Feasible {
		t.Error("cheap TLD must not flip Feasible")
	}
}

func TestBlocklistDetector_NoFalsePositiveOnHK(t *testing.T) {
	// Regression: "hk" must NOT be a substring keyword — it would wreck
	// legitimate .com.hk / .gov.hk domains.
	d := testBlocklist()
	for _, dom := range []string{"bank.com.hk", "www.gov.hk", "shop.example.com"} {
		r := blockDetect(d, dom)
		if r.Block != nil {
			t.Errorf("%s: expected no block, got %+v", dom, r.Block)
		}
		if !r.Feasible {
			t.Errorf("%s: expected Feasible unchanged", dom)
		}
	}
}

func TestBlocklistDetector_Unavailable(t *testing.T) {
	if (&BlocklistDetector{}).Available() {
		t.Error("empty blocklist detector should not be available")
	}
	if !testBlocklist().Available() {
		t.Error("populated blocklist detector should be available")
	}
}

func TestBlocklistDetector_NilTLS(t *testing.T) {
	d := testBlocklist()
	r := &types.ScanResult{} // TLS nil
	if err := d.Detect(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if r.Block != nil {
		t.Error("expected no block for nil TLS")
	}
}

func TestNewBlocklistDetector_ParsesTags(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bl.txt")
	content := "# comment\n\nkw:vless\nkw:x-ui\ndyn:.nip.io\nnas:.synology.me\ntld:.xyz\nbogus-line\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	d := NewBlocklistDetector(path)
	if len(d.keywords) != 2 {
		t.Errorf("keywords = %d, want 2", len(d.keywords))
	}
	if len(d.suffixes) != 2 {
		t.Errorf("suffixes = %d, want 2", len(d.suffixes))
	}
	if len(d.tlds) != 1 {
		t.Errorf("tlds = %d, want 1", len(d.tlds))
	}
}

func TestComputeScore_BlocklistVeto(t *testing.T) {
	base := func() *types.ScanResult {
		sni := true
		return &types.ScanResult{
			TLS: &types.TLSInfo{
				Version:       0x0304,
				ALPN:          "h2",
				CertDomain:    "example.com",
				CertIssuer:    "Let's Encrypt",
				HandshakeTime: 100 * time.Millisecond,
				CertExpiry:    time.Now().Add(120 * 24 * time.Hour),
			},
			CertValid: &types.CertValidResult{Valid: true, SNIMatch: &sni},
		}
	}

	clean := ComputeScore(base())
	if clean != 5 {
		t.Fatalf("baseline score = %d, want 5 (test fixture drifted)", clean)
	}

	hard := base()
	hard.Block = &types.BlockResult{Hit: true, Reason: "proxy_keyword"}
	if got := ComputeScore(hard); got != 0 {
		t.Errorf("hard blocklist hit score = %d, want 0", got)
	}

	cheap := base()
	cheap.Block = &types.BlockResult{CheapTLD: true}
	if got := ComputeScore(cheap); got != clean-1 {
		t.Errorf("cheap TLD score = %d, want %d (baseline-1)", got, clean-1)
	}
}

func TestComputeScore_PQCBonus(t *testing.T) {
	sni := true
	r := &types.ScanResult{
		TLS: &types.TLSInfo{
			Version:       0x0304,
			ALPN:          "h2",
			CertDomain:    "example.com",
			CertIssuer:    "Let's Encrypt",
			HandshakeTime: 100 * time.Millisecond,
			CertExpiry:    time.Now().Add(120 * 24 * time.Hour),
		},
		CertValid: &types.CertValidResult{Valid: true, SNIMatch: &sni},
	}

	without := ComputeScore(r) // all 5 classical criteria pass
	r.TLS.PQC = true
	with := ComputeScore(r)

	if with != without+1 {
		t.Errorf("PQC bonus: with=%d, without=%d, want with=without+1", with, without)
	}
	if with != 6 {
		t.Errorf("fully clean dest + PQC = %d stars, want 6", with)
	}
}
