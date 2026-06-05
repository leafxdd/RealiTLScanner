package detector

import (
	"bufio"
	"context"
	"log/slog"
	"os"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

// BlocklistDetector flags cert domains that are unsuitable as Reality dest
// targets: other people's proxy panels (x-ui/vless/...), dynamic-DNS and NAS
// hostnames, and — as a soft signal — cheap throwaway TLDs. A hard hit
// disqualifies the candidate (Feasible=false, score 0); a cheap TLD only costs
// one star.
type BlocklistDetector struct {
	keywords []string      // substring match on domain (proxy/panel signatures)
	suffixes []blockSuffix // exact domain-suffix match (dynamic DNS / NAS)
	tlds     []string      // TLD suffix match, soft signal only
}

type blockSuffix struct {
	suffix string
	reason string // dynamic_dns | nas
}

func NewBlocklistDetector(listPath string) *BlocklistDetector {
	d := &BlocklistDetector{}
	if listPath == "" {
		return d
	}
	f, err := os.Open(listPath)
	if err != nil {
		slog.Warn("Blocklist file not found, detector disabled", "path", listPath, "err", err)
		return d
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		switch {
		case strings.HasPrefix(line, "kw:"):
			if v := strings.ToLower(strings.TrimSpace(line[3:])); v != "" {
				d.keywords = append(d.keywords, v)
			}
		case strings.HasPrefix(line, "dyn:"):
			if v := strings.ToLower(strings.TrimSpace(line[4:])); v != "" {
				d.suffixes = append(d.suffixes, blockSuffix{v, "dynamic_dns"})
			}
		case strings.HasPrefix(line, "nas:"):
			if v := strings.ToLower(strings.TrimSpace(line[4:])); v != "" {
				d.suffixes = append(d.suffixes, blockSuffix{v, "nas"})
			}
		case strings.HasPrefix(line, "tld:"):
			if v := strings.ToLower(strings.TrimSpace(line[4:])); v != "" {
				d.tlds = append(d.tlds, v)
			}
		}
	}
	slog.Info("Blocklist detector loaded",
		"keywords", len(d.keywords), "suffixes", len(d.suffixes), "tlds", len(d.tlds))
	return d
}

func (d *BlocklistDetector) Name() string { return "blocklist" }

func (d *BlocklistDetector) Available() bool {
	return len(d.keywords) > 0 || len(d.suffixes) > 0 || len(d.tlds) > 0
}

func (d *BlocklistDetector) Detect(_ context.Context, result *types.ScanResult) error {
	if result.TLS == nil || result.TLS.CertDomain == "" {
		return nil
	}
	domain := strings.ToLower(result.TLS.CertDomain)
	block := &types.BlockResult{}

	// Dangerous suffixes (dynamic DNS / NAS) — checked first; most specific.
	for _, s := range d.suffixes {
		if strings.HasSuffix(domain, s.suffix) {
			block.Hit = true
			block.Reason = s.reason
			block.Keywords = []string{s.suffix}
			break
		}
	}

	// Proxy / panel keywords — substring match, only if not already disqualified.
	if !block.Hit {
		for _, kw := range d.keywords {
			if strings.Contains(domain, kw) {
				block.Hit = true
				block.Reason = "proxy_keyword"
				block.Keywords = []string{kw}
				break
			}
		}
	}

	// Cheap TLD — soft signal, never disqualifies on its own.
	for _, tld := range d.tlds {
		if strings.HasSuffix(domain, tld) {
			block.CheapTLD = true
			break
		}
	}

	if block.Hit {
		// A proxy panel / dynamic-DNS / NAS host is not a usable Reality dest,
		// regardless of a clean TLS handshake.
		result.Feasible = false
	}
	if block.Hit || block.CheapTLD {
		result.Block = block
	}
	return nil
}
