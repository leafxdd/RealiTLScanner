package detector

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type StatusDetector struct {
	timeout time.Duration
	client  *http.Client
	// testInjected: see RedirectDetector.testInjected.
	testInjected bool
}

func NewStatusDetector(timeout time.Duration) *StatusDetector {
	return &StatusDetector{
		timeout: timeout,
		client: &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   2,
				IdleConnTimeout:       30 * time.Second,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
			},
		},
	}
}

func (d *StatusDetector) Name() string { return "status" }

func (d *StatusDetector) Available() bool { return true }

func (d *StatusDetector) Detect(ctx context.Context, result *types.ScanResult) error {
	if result.TLS == nil || result.TLS.CertDomain == "" {
		return nil
	}
	if result.Redirect != nil {
		return nil
	}
	if !d.injected() && !isSafeForProbe(result.TLS.CertDomain) {
		return nil
	}
	url := fmt.Sprintf("https://%s", result.TLS.CertDomain)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	server := resp.Header.Get("Server")
	result.Redirect = &types.RedirectResult{StatusCode: resp.StatusCode, Server: server}
	vetoIfProxyServer(result, server)
	return nil
}

func (d *StatusDetector) injected() bool {
	return d.testInjected
}
