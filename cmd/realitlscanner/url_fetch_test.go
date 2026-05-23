package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchURLDomains_HappyPath(t *testing.T) {
	body := `<html>
<a href="https://example.com/foo">A</a>
<a href="https://other.example.org/bar">B</a>
<a href="https://example.com/dup">A again</a>
</html>`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, body)
	}))
	defer srv.Close()

	domains, err := fetchURLDomains(context.Background(), srv.URL, 5*time.Second, 1<<20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 unique domains, got %d: %v", len(domains), domains)
	}
	got := map[string]bool{domains[0]: true, domains[1]: true}
	if !got["example.com"] || !got["other.example.org"] {
		t.Errorf("missing expected domains, got: %v", domains)
	}
}

func TestFetchURLDomains_RespectsSizeLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(strings.Repeat("a", 5000)))
	}))
	defer srv.Close()

	_, err := fetchURLDomains(context.Background(), srv.URL, 5*time.Second, 1024)
	if err == nil {
		t.Fatal("expected size-limit error, got nil")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("expected 'exceeds' in error, got: %v", err)
	}
}

func TestFetchURLDomains_RespectsTimeout(t *testing.T) {
	gate := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-gate
	}))
	defer srv.Close()
	defer close(gate)

	start := time.Now()
	_, err := fetchURLDomains(context.Background(), srv.URL, 200*time.Millisecond, 1<<20)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
	if elapsed > 2*time.Second {
		t.Errorf("timeout took too long: %v", elapsed)
	}
}

func TestFetchURLDomains_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := fetchURLDomains(context.Background(), srv.URL, 5*time.Second, 1<<20)
	if err == nil {
		t.Fatal("expected http error, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("expected 404 in error, got: %v", err)
	}
}
