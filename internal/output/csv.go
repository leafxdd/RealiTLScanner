package output

import (
	"encoding/csv"
	"fmt"
	"io"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type CSVWriter struct {
	w    *csv.Writer
	opts Options
}

func NewCSVWriter(w io.Writer, opts Options) *CSVWriter {
	return &CSVWriter{w: csv.NewWriter(w), opts: opts}
}

func (c *CSVWriter) WriteHeader() error {
	if c.opts.NoHeader {
		return nil
	}
	header := []string{"IP", "ORIGIN", "CERT_DOMAIN", "CERT_ISSUER", "GEO_CODE"}
	if c.opts.Extended {
		header = append(header, "CDN_LEVEL", "GFW_BLOCKED", "SCORE")
	}
	if err := c.w.Write(header); err != nil {
		return err
	}
	c.w.Flush()
	return c.w.Error()
}

func (c *CSVWriter) WriteResult(result *types.ScanResult) error {
	if result.TLS == nil {
		return nil
	}
	fields := []string{
		result.IP.String(),
		result.Host.Origin,
		result.TLS.CertDomain,
		result.TLS.CertIssuer,
		result.GeoCode,
	}
	if c.opts.Extended {
		cdnLevel := ""
		if result.CDN != nil {
			cdnLevel = result.CDN.Level
		}
		gfwBlocked := "false"
		if result.GFW != nil && result.GFW.Blocked {
			gfwBlocked = "true"
		}
		fields = append(fields, cdnLevel, gfwBlocked, fmt.Sprintf("%d", result.Score))
	}
	if err := c.w.Write(fields); err != nil {
		return err
	}
	// Flush per row so partial scans survive Ctrl+C — encoding/csv buffers
	// internally; previous fmt.Fprintln-based implementation hit disk per call
	// and callers relied on that for crash/abort recovery.
	c.w.Flush()
	return c.w.Error()
}

func (c *CSVWriter) Flush() error {
	c.w.Flush()
	return c.w.Error()
}

func (c *CSVWriter) Close() error {
	c.w.Flush()
	return c.w.Error()
}
