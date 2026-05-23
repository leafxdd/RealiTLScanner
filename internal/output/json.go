package output

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type jsonOutput struct {
	Metadata jsonMetadata        `json:"metadata"`
	Results  []jsonResult        `json:"results"`
	Summary  jsonSummary         `json:"summary"`
}

type jsonMetadata struct {
	Version   string `json:"version"`
	Timestamp string `json:"timestamp"`
}

type jsonResult struct {
	IP       string          `json:"ip"`
	Origin   string          `json:"origin"`
	TLS      *jsonTLS        `json:"tls,omitempty"`
	GeoCode  string          `json:"geo_code"`
	CDN      *types.CDNResult `json:"cdn,omitempty"`
	GFW      *types.GFWResult `json:"gfw,omitempty"`
	Feasible bool            `json:"feasible"`
	Score    int             `json:"score,omitempty"`
}

type jsonTLS struct {
	Version    string `json:"version"`
	ALPN       string `json:"alpn"`
	CertDomain string `json:"cert_domain"`
	CertIssuer string `json:"cert_issuer"`
}

type jsonSummary struct {
	TotalScanned  int    `json:"total_scanned"`
	FeasibleCount int    `json:"feasible_count"`
	DetectionRate string `json:"detection_rate"`
}

type JSONWriter struct {
	w             io.Writer
	results       []jsonResult
	feasibleCount int
	opts          Options
}

func NewJSONWriter(w io.Writer, opts Options) *JSONWriter {
	return &JSONWriter{w: w, opts: opts}
}

func (j *JSONWriter) WriteHeader() error { return nil }

func (j *JSONWriter) WriteResult(result *types.ScanResult) error {
	r := toJSONResult(result)
	j.results = append(j.results, r)
	if result.Feasible {
		j.feasibleCount++
	}
	return nil
}

func (j *JSONWriter) Flush() error { return nil }

func (j *JSONWriter) Close() error {
	total := len(j.results)
	rate := "N/A"
	if total > 0 {
		rate = fmt.Sprintf("%.1f%%", float64(j.feasibleCount)/float64(total)*100)
	}
	out := jsonOutput{
		Metadata: jsonMetadata{
			Version:   "2.0",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
		},
		Results: j.results,
		Summary: jsonSummary{
			TotalScanned:  total,
			FeasibleCount: j.feasibleCount,
			DetectionRate: rate,
		},
	}
	enc := json.NewEncoder(j.w)
	if j.opts.Pretty {
		enc.SetIndent("", "  ")
	}
	return enc.Encode(out)
}

type JSONLWriter struct {
	w io.Writer
}

func NewJSONLWriter(w io.Writer) *JSONLWriter {
	return &JSONLWriter{w: w}
}

func (j *JSONLWriter) WriteHeader() error { return nil }

func (j *JSONLWriter) WriteResult(result *types.ScanResult) error {
	r := toJSONResult(result)
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(j.w, "%s\n", data)
	return err
}

func (j *JSONLWriter) Flush() error { return nil }
func (j *JSONLWriter) Close() error { return nil }

func toJSONResult(result *types.ScanResult) jsonResult {
	r := jsonResult{
		IP:       result.IP.String(),
		Origin:   result.Host.Origin,
		GeoCode:  result.GeoCode,
		CDN:      result.CDN,
		GFW:      result.GFW,
		Feasible: result.Feasible,
		Score:    result.Score,
	}
	if result.TLS != nil {
		r.TLS = &jsonTLS{
			Version:    fmt.Sprintf("0x%04x", result.TLS.Version),
			ALPN:       result.TLS.ALPN,
			CertDomain: result.TLS.CertDomain,
			CertIssuer: result.TLS.CertIssuer,
		}
	}
	return r
}
