package detector

import (
	"context"
	"net"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type ResolverDetector struct {
	timeout time.Duration
}

func NewResolverDetector(timeout time.Duration) *ResolverDetector {
	return &ResolverDetector{timeout: timeout}
}

func (d *ResolverDetector) Name() string { return "resolver" }

func (d *ResolverDetector) Available() bool { return true }

func (d *ResolverDetector) Detect(ctx context.Context, result *types.ScanResult) error {
	if result.TLS == nil || result.TLS.CertDomain == "" {
		return nil
	}
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{Timeout: d.timeout}
			return dialer.DialContext(ctx, network, address)
		},
	}
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()

	ips, err := resolver.LookupIPAddr(ctx, result.TLS.CertDomain)
	if err != nil {
		return nil
	}

	for _, ip := range ips {
		if ip.IP.Equal(result.IP) {
			return nil
		}
	}
	return nil
}
