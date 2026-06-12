package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

func testResult() *types.ScanResult {
	return &types.ScanResult{
		Host:    types.Host{Origin: "example.com", Type: types.HostTypeDomain},
		IP:      net.ParseIP("1.2.3.4"),
		GeoCode: "US",
		TLS: &types.TLSInfo{
			Version:    0x0304,
			ALPN:       "h2",
			CertDomain: "example.com",
			CertIssuer: "Let's Encrypt",
		},
		Feasible: true,
	}
}

func TestCSVWriter_FlushesPerRow(t *testing.T) {
	// Buffer that records cumulative byte count seen by the writer — proves
	// each Write hits the underlying io.Writer immediately rather than sitting
	// in encoding/csv's internal buffer.
	var buf bytes.Buffer
	w := NewCSVWriter(&buf, Options{NoHeader: true})

	if err := w.WriteResult(testResult()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("after WriteResult, underlying buffer is empty — encoding/csv did not flush")
	}
	beforeSecond := buf.Len()
	if err := w.WriteResult(testResult()); err != nil {
		t.Fatal(err)
	}
	if buf.Len() <= beforeSecond {
		t.Fatal("second WriteResult did not extend the underlying buffer")
	}
}

func TestCSVWriter_DefaultFormat(t *testing.T) {
	var buf bytes.Buffer
	w := NewCSVWriter(&buf, Options{})
	_ = w.WriteHeader()
	_ = w.WriteResult(testResult())
	_ = w.Close()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines (header + result), got %d", len(lines))
	}
	if lines[0] != "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE" {
		t.Errorf("unexpected header: %s", lines[0])
	}
	if lines[1] != "1.2.3.4,example.com,example.com,Let's Encrypt,US" {
		t.Errorf("unexpected result: %s", lines[1])
	}
}

func TestCSVWriter_Escape(t *testing.T) {
	var buf bytes.Buffer
	w := NewCSVWriter(&buf, Options{NoHeader: true})
	r := testResult()
	r.TLS.CertDomain = "Cloudflare, Inc."
	_ = w.WriteResult(r)
	_ = w.Close()

	line := strings.TrimSpace(buf.String())
	if !strings.Contains(line, "\"Cloudflare, Inc.\"") {
		t.Errorf("expected escaped field, got: %s", line)
	}
}

func TestCSVWriter_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w := NewCSVWriter(&buf, Options{})
	if err := w.WriteHeader(); err != nil {
		t.Fatal(err)
	}

	r := testResult()
	r.TLS.CertDomain = "has,comma.example"
	r.TLS.CertIssuer = `has"quote, Inc.`
	r.GeoCode = "line\nbreak"
	if err := w.WriteResult(r); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	cr := csv.NewReader(&buf)
	rows, err := cr.ReadAll()
	if err != nil {
		t.Fatalf("round-trip parse failed: %s", err)
	}
	if len(rows) != 2 {
		t.Fatalf("expected 2 rows (header + result), got %d", len(rows))
	}

	got := rows[1]
	want := []string{"1.2.3.4", "example.com", "has,comma.example", `has"quote, Inc.`, "line\nbreak"}
	if len(got) != len(want) {
		t.Fatalf("expected %d fields, got %d (%v)", len(want), len(got), got)
	}
	for i, w := range want {
		if got[i] != w {
			t.Errorf("field[%d]: got %q, want %q", i, got[i], w)
		}
	}
}

func TestJSONLWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONLWriter(&buf)
	_ = w.WriteHeader()
	_ = w.WriteResult(testResult())
	_ = w.WriteResult(testResult())
	_ = w.Close()

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d", len(lines))
	}
	for i, line := range lines {
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			t.Errorf("line %d is not valid JSON: %s", i, err)
		}
	}
}

func TestJSONWriter(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf, Options{Pretty: true})
	_ = w.WriteHeader()
	_ = w.WriteResult(testResult())
	_ = w.Close()

	var out map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("output is not valid JSON: %s", err)
	}
	if _, ok := out["metadata"]; !ok {
		t.Error("expected metadata field")
	}
	if _, ok := out["results"]; !ok {
		t.Error("expected results field")
	}
	if _, ok := out["summary"]; !ok {
		t.Error("expected summary field")
	}
}

func TestTableWriter_RendersPreComputedScore(t *testing.T) {
	var buf bytes.Buffer
	tw := NewTableWriter(&buf, nil)
	r := testResult()
	r.Score = 3
	tw.WriteResult(r)
	tw.WriteSummaryWithStats(1, 0, time.Second, SummaryStats{}) // flushes the buffered table

	out := stripANSI(buf.String())
	if !strings.Contains(out, "***") {
		t.Errorf("expected pre-computed score (3 stars) in output, got: %q", out)
	}
}

func TestJSONWriter_SummaryStats_MixedResults(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf, Options{Pretty: false})
	for i := 0; i < 5; i++ {
		r := testResult()
		r.Feasible = i < 3 // 3 feasible, 2 non-feasible
		if err := w.WriteResult(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary.TotalScanned != 5 {
		t.Errorf("TotalScanned: got %d, want 5", out.Summary.TotalScanned)
	}
	if out.Summary.FeasibleCount != 3 {
		t.Errorf("FeasibleCount: got %d, want 3", out.Summary.FeasibleCount)
	}
	if out.Summary.DetectionRate != "60.0%" {
		t.Errorf("DetectionRate: got %q, want %q", out.Summary.DetectionRate, "60.0%")
	}
}

func TestJSONWriter_SummaryStats_EmptyResults(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf, Options{})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary.TotalScanned != 0 {
		t.Errorf("TotalScanned: got %d, want 0", out.Summary.TotalScanned)
	}
	if out.Summary.FeasibleCount != 0 {
		t.Errorf("FeasibleCount: got %d, want 0", out.Summary.FeasibleCount)
	}
	if out.Summary.DetectionRate != "N/A" {
		t.Errorf("DetectionRate: got %q, want %q", out.Summary.DetectionRate, "N/A")
	}
}

func TestJSONWriter_SummaryStats_AllNonFeasible(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf, Options{})
	for i := 0; i < 4; i++ {
		r := testResult()
		r.Feasible = false
		if err := w.WriteResult(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Summary.FeasibleCount != 0 {
		t.Errorf("FeasibleCount: got %d, want 0", out.Summary.FeasibleCount)
	}
	if out.Summary.DetectionRate != "0.0%" {
		t.Errorf("DetectionRate: got %q, want %q", out.Summary.DetectionRate, "0.0%")
	}
}

func TestTableWriter_RedirectStripsANSI(t *testing.T) {
	var buf bytes.Buffer
	tw := NewTableWriter(&buf, nil)
	r := testResult()
	r.Score = 3
	tw.WriteResult(r)
	tw.WriteSummaryWithStats(1, 0, time.Second, SummaryStats{}) // flushes the buffered table

	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Errorf("buffer (non-TTY) writer should have no ANSI escapes, got: %q", out)
	}
}

func TestTableWriter_HandlesNilTLS(t *testing.T) {
	var buf bytes.Buffer
	tw := NewTableWriter(&buf, nil)
	tw.WriteResult(&types.ScanResult{
		Host: types.Host{Origin: "example.com", Type: types.HostTypeDomain},
		IP:   net.ParseIP("1.2.3.4"),
		// TLS intentionally nil
	})
	// Should not panic; output should be empty.
	if buf.Len() != 0 {
		t.Errorf("expected no output for nil TLS, got %q", buf.String())
	}
}

func TestJSONWriter_ExtendedFields_Populated(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf, Options{Pretty: false})
	r := testResult()
	r.TLS.HandshakeTime = 123 * time.Millisecond
	r.TLS.CertExpiry = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	r.HotSite = &types.HotSiteResult{IsHot: true, Category: "cdn"}
	r.Redirect = &types.RedirectResult{Redirects: true, StatusCode: 301, Target: "https://elsewhere.example"}
	sniMatch := true
	r.CertValid = &types.CertValidResult{Valid: true, SNIMatch: &sniMatch}
	r.Error = "none"
	if err := w.WriteResult(r); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(out.Results))
	}
	got := out.Results[0]
	if got.TLS == nil {
		t.Fatal("want TLS")
	}
	if got.TLS.HandshakeMS != 123 {
		t.Errorf("HandshakeMS: got %d, want 123", got.TLS.HandshakeMS)
	}
	if got.TLS.CertExpiry == "" {
		t.Error("CertExpiry empty")
	}
	if got.TLS.VersionName == "" {
		t.Error("VersionName empty")
	}
	if got.HotSite == nil || !got.HotSite.IsHot {
		t.Errorf("HotSite missing/wrong: %+v", got.HotSite)
	}
	if got.Redirect == nil || got.Redirect.StatusCode != 301 {
		t.Errorf("Redirect missing/wrong: %+v", got.Redirect)
	}
	if got.CertValid == nil || !got.CertValid.Valid {
		t.Errorf("CertValid missing/wrong: %+v", got.CertValid)
	}
	if got.Error != "none" {
		t.Errorf("Error: got %q, want %q", got.Error, "none")
	}
}

func TestJSONWriter_BlockAndServer(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf, Options{Pretty: false})
	r := testResult()
	r.Redirect = &types.RedirectResult{StatusCode: 200, Server: "x-ui"}
	r.Block = &types.BlockResult{Hit: true, Reason: "proxy_server", Keywords: []string{"x-ui"}}
	if err := w.WriteResult(r); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	var out jsonOutput
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	got := out.Results[0]
	if got.Block == nil || !got.Block.Hit || got.Block.Reason != "proxy_server" {
		t.Errorf("Block missing/wrong in JSON: %+v", got.Block)
	}
	if got.Redirect == nil || got.Redirect.Server != "x-ui" {
		t.Errorf("Redirect.Server missing/wrong in JSON: %+v", got.Redirect)
	}
}

// stripANSI removes ANSI color escapes for stable assertions.
func stripANSI(s string) string {
	for {
		i := strings.Index(s, "\033[")
		if i < 0 {
			return s
		}
		end := strings.IndexByte(s[i:], 'm')
		if end < 0 {
			return s
		}
		s = s[:i] + s[i+end+1:]
	}
}