package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/xtls/RealiTLScanner/internal/scanner"
)

const (
	urlFetchTimeout = 30 * time.Second
	urlMaxBytes     = int64(10 << 20)
)

var urlDomainRegex = regexp.MustCompile(`(http|https)://(.*?)[/"<>\s]+`)

func fetchURLDomains(ctx context.Context, rawURL string, timeout time.Duration, maxBytes int64) ([]string, error) {
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("User-Agent", "RealiTLScanner/"+version)
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxBytes)
	}
	matches := urlDomainRegex.FindAllStringSubmatch(string(body), -1)
	var domains []string
	for _, m := range matches {
		domains = append(domains, m[2])
	}
	return scanner.RemoveDuplicateStr(domains), nil
}
