package detector

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type RedirectDetector struct {
	timeout time.Duration
}

func NewRedirectDetector(timeout time.Duration) *RedirectDetector {
	return &RedirectDetector{timeout: timeout}
}

func (d *RedirectDetector) Name() string { return "redirect" }

func (d *RedirectDetector) Available() bool { return true }

func (d *RedirectDetector) Detect(ctx context.Context, result *types.ScanResult) error {
	if result.TLS == nil || result.TLS.CertDomain == "" {
		return nil
	}
	domain := result.TLS.CertDomain
	url := fmt.Sprintf("https://%s", domain)

	client := &http.Client{
		Timeout: d.timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
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
		result.Redirect = &types.RedirectResult{Redirects: false}
		return nil
	}
	defer resp.Body.Close()

	redirects := resp.StatusCode >= 300 && resp.StatusCode < 400
	target := ""
	if redirects {
		target = resp.Header.Get("Location")
	}

	result.Redirect = &types.RedirectResult{
		Redirects:  redirects,
		Target:     target,
		StatusCode: resp.StatusCode,
	}
	return nil
}
