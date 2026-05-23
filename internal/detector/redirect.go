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
	client  *http.Client
}

func NewRedirectDetector(timeout time.Duration) *RedirectDetector {
	return &RedirectDetector{
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

func (d *RedirectDetector) Name() string { return "redirect" }

func (d *RedirectDetector) Available() bool { return true }

func (d *RedirectDetector) Detect(ctx context.Context, result *types.ScanResult) error {
	if result.TLS == nil || result.TLS.CertDomain == "" {
		return nil
	}
	domain := result.TLS.CertDomain
	// When d.client was overridden (test injection), trust the caller's setup
	// and bypass the safe-target check.
	if !d.injected() && !isSafeForProbe(domain) {
		return nil
	}
	url := fmt.Sprintf("https://%s", domain)

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, url, nil)
	if err != nil {
		return err
	}

	resp, err := d.client.Do(req)
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

// injected tells whether d.client has been replaced by a test fixture (which
// uses a custom Transport, e.g. httptest.Server). The default client wired in
// NewRedirectDetector has a *http.Transport with a DialContext set; we treat
// any Transport with no DialContext (typical for httptest) as injected.
func (d *RedirectDetector) injected() bool {
	tr, ok := d.client.Transport.(*http.Transport)
	if !ok {
		return true
	}
	return tr.DialContext == nil
}
