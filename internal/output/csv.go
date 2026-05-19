package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/scanner"
	"github.com/xtls/RealiTLScanner/internal/types"
)

type CSVWriter struct {
	w    io.Writer
	opts Options
}

func NewCSVWriter(w io.Writer, opts Options) *CSVWriter {
	return &CSVWriter{w: w, opts: opts}
}

func (c *CSVWriter) WriteHeader() error {
	if c.opts.NoHeader {
		return nil
	}
	header := "IP,ORIGIN,CERT_DOMAIN,CERT_ISSUER,GEO_CODE"
	if c.opts.Extended {
		header += ",CDN_LEVEL,GFW_BLOCKED,SCORE"
	}
	_, err := fmt.Fprintln(c.w, header)
	return err
}

func (c *CSVWriter) WriteResult(result *types.ScanResult) error {
	if result.TLS == nil {
		return nil
	}
	fields := []string{
		result.IP.String(),
		result.Host.Origin,
		scanner.CsvEscape(result.TLS.CertDomain),
		scanner.CsvEscape(result.TLS.CertIssuer),
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
	_, err := fmt.Fprintln(c.w, strings.Join(fields, ","))
	return err
}

func (c *CSVWriter) Flush() error { return nil }
func (c *CSVWriter) Close() error { return nil }
