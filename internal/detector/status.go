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
	url := fmt.Sprintf("https://%s", result.TLS.CertDomain)

	client := &http.Client{
		Timeout: d.timeout,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: d.timeout}).DialContext,
		},
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

	if result.Redirect == nil {
		result.Redirect = &types.RedirectResult{}
	}
	result.Redirect.StatusCode = resp.StatusCode
	return nil
}
