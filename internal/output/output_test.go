package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"net"
	"strings"
	"testing"

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
