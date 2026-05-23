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
}

func NewStatusDetector(timeout time.Duration) *StatusDetector {
	return &StatusDetector{timeout: timeout}
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
	if d.client == nil && !isSafeForProbe(result.TLS.CertDomain) {
		return nil
	}
	url := fmt.Sprintf("https://%s", result.TLS.CertDomain)

	client := d.client
	if client == nil {
		client = &http.Client{
			Timeout: d.timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: d.timeout}).DialContext,
			},
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	result.Redirect = &types.RedirectResult{StatusCode: resp.StatusCode}
	return nil
}
