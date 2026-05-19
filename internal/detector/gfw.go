package detector

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type GFWDetector struct {
	domains map[string]bool
}

func NewGFWDetector(listPath string) *GFWDetector {
	d := &GFWDetector{domains: make(map[string]bool)}
	if listPath == "" {
		return d
	}
	f, err := os.Open(listPath)
	if err != nil {
		slog.Warn("GFW list not found, detector disabled", "path", listPath, "err", err)
		return d
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		d.domains[strings.ToLower(line)] = true
	}
	slog.Info("GFW detector loaded", "domains", len(d.domains))
	return d
}

func (d *GFWDetector) Name() string { return "gfw" }

func (d *GFWDetector) Available() bool { return len(d.domains) > 0 }

func (d *GFWDetector) Detect(_ context.Context, result *types.ScanResult) error {
	if result.TLS == nil || result.TLS.CertDomain == "" {
		return nil
	}
	domain := strings.ToLower(result.TLS.CertDomain)
	blocked := d.domains[domain]
	if !blocked {
		parts := strings.Split(domain, ".")
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			if d.domains[parent] {
				blocked = true
				break
			}
		}
	}
	result.GFW = &types.GFWResult{
		Blocked: blocked,
		Source:  "gfwlist",
	}
	return nil
}
