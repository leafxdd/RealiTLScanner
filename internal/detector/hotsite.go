package detector

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type HotSiteDetector struct {
	sites map[string]string
}

func NewHotSiteDetector(listPath string) *HotSiteDetector {
	d := &HotSiteDetector{sites: make(map[string]string)}
	if listPath == "" {
		return d
	}
	f, err := os.Open(listPath)
	if err != nil {
		slog.Warn("Hot websites list not found, detector disabled", "path", listPath, "err", err)
		return d
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ",", 2)
		domain := strings.ToLower(strings.TrimSpace(parts[0]))
		category := "general"
		if len(parts) > 1 {
			category = strings.TrimSpace(parts[1])
		}
		d.sites[domain] = category
	}
	slog.Info("HotSite detector loaded", "sites", len(d.sites))
	return d
}

func (d *HotSiteDetector) Name() string { return "hot_website" }

func (d *HotSiteDetector) Available() bool { return len(d.sites) > 0 }

func (d *HotSiteDetector) Detect(_ context.Context, result *types.ScanResult) error {
	if result.TLS == nil || result.TLS.CertDomain == "" {
		return nil
	}
	domain := strings.ToLower(result.TLS.CertDomain)
	if cat, ok := d.sites[domain]; ok {
		result.HotSite = &types.HotSiteResult{IsHot: true, Category: cat}
		return nil
	}
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if cat, ok := d.sites[parent]; ok {
			result.HotSite = &types.HotSiteResult{IsHot: true, Category: cat}
			return nil
		}
	}
	result.HotSite = &types.HotSiteResult{IsHot: false}
	return nil
}
