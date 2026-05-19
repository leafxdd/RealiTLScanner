package detector

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type CDNDetector struct {
	keywords []string
}

func NewCDNDetector(keywordsPath string) *CDNDetector {
	d := &CDNDetector{}
	if keywordsPath == "" {
		return d
	}
	f, err := os.Open(keywordsPath)
	if err != nil {
		slog.Warn("CDN keywords file not found, detector disabled", "path", keywordsPath, "err", err)
		return d
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d.keywords = append(d.keywords, strings.ToLower(line))
	}
	slog.Info("CDN detector loaded", "keywords", len(d.keywords))
	return d
}

func (d *CDNDetector) Name() string { return "cdn" }

func (d *CDNDetector) Available() bool { return len(d.keywords) > 0 }

func (d *CDNDetector) Detect(_ context.Context, result *types.ScanResult) error {
	if result.TLS == nil {
		return nil
	}
	domain := strings.ToLower(result.TLS.CertDomain)
	issuer := strings.ToLower(result.TLS.CertIssuer)
	combined := domain + " " + issuer

	var matched []string
	for _, kw := range d.keywords {
		if strings.Contains(combined, kw) {
			matched = append(matched, kw)
		}
	}

	level := "none"
	confidence := 0.0
	switch {
	case len(matched) >= 3:
		level = "high"
		confidence = 0.95
	case len(matched) == 2:
		level = "medium"
		confidence = 0.7
	case len(matched) == 1:
		level = "low"
		confidence = 0.4
	}

	result.CDN = &types.CDNResult{
		Level:      level,
		Confidence: confidence,
		Keywords:   matched,
	}
	return nil
}
