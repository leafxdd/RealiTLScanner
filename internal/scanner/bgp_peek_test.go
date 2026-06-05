package scanner

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
)

// synthHeatmap builds a 16×16 RGBA PNG with the first activeCells pixels
// (row-major) coloured bgp.tools-blue on a black background — a stand-in for a
// /24 heatmap where that many addresses have been "seen".
func synthHeatmap(t *testing.T, activeCells int) []byte {
	return synthHeatmapSize(t, 16, activeCells)
}

// synthHeatmapSize is synthHeatmap for an arbitrary square canvas side, used to
// stand in for the padded images bgp.tools renders for larger prefixes.
func synthHeatmapSize(t *testing.T, side, activeCells int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, side, side))
	bg := color.RGBA{R: 0, G: 0, B: 0, A: 255}     // black = no data
	used := color.RGBA{R: 0, G: 3, B: 255, A: 255} // blue = seen
	painted := 0
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			if painted < activeCells {
				img.Set(x, y, used)
				painted++
			} else {
				img.Set(x, y, bg)
			}
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPeekPrefixUsage_DownloadDecodeAndCache(t *testing.T) {
	const activeCells = 37
	body := synthHeatmap(t, activeCells)

	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Honest UA: must identify the tool + repo, must NOT spoof a browser.
		ua := r.Header.Get("User-Agent")
		if ua != bgpUserAgent {
			t.Errorf("User-Agent = %q, want honest %q", ua, bgpUserAgent)
		}
		if strings.Contains(ua, "Mozilla") || strings.Contains(ua, "Chrome") {
			t.Errorf("User-Agent must not spoof a browser: %q", ua)
		}
		// The /24 CIDR is carried literally in the path.
		if !strings.Contains(r.URL.Path, "1.2.3.0/24") {
			t.Errorf("path = %q, want it to contain 1.2.3.0/24", r.URL.Path)
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	oldBase, oldDir := pfximgBaseURL, pfximgCacheDir
	pfximgBaseURL = srv.URL
	pfximgCacheDir = t.TempDir()
	defer func() { pfximgBaseURL, pfximgCacheDir = oldBase, oldDir }()

	res, err := peekPrefix(context.Background(), netip.MustParsePrefix("1.2.3.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if res.CIDR != "1.2.3.0/24" {
		t.Errorf("CIDR = %q, want 1.2.3.0/24", res.CIDR)
	}
	if res.Active != activeCells {
		t.Errorf("Active = %d, want %d", res.Active, activeCells)
	}
	if res.Total != 256 {
		t.Errorf("Total = %d, want 256", res.Total)
	}
	if res.Cached {
		t.Error("first call should not be served from cache")
	}

	// Second call must hit the local cache, not the network.
	res2, err := peekPrefix(context.Background(), netip.MustParsePrefix("1.2.3.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if !res2.Cached {
		t.Error("second call should be served from cache")
	}
	if res2.Active != activeCells {
		t.Errorf("cached Active = %d, want %d", res2.Active, activeCells)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server was hit %d times, want exactly 1 (cache should absorb the rest)", got)
	}
}

func TestPeekPrefixUsage_IPv6Rejected(t *testing.T) {
	if _, err := PeekPrefixUsage(context.Background(), netip.MustParseAddr("2001:db8::1")); err == nil {
		t.Error("expected pfximg peek to reject IPv6 (it is a /24 heatmap)")
	}
}

func TestIsActiveCell(t *testing.T) {
	cases := []struct {
		name string
		c    color.Color
		want bool
	}{
		{"black background is no-data", color.RGBA{R: 0, G: 0, B: 0, A: 255}, false},
		{"near-black is no-data", color.RGBA{R: 10, G: 10, B: 10, A: 255}, false},
		{"bgp.tools blue is seen", color.RGBA{R: 0, G: 3, B: 255, A: 255}, true},
		{"dense red is seen", color.RGBA{R: 255, G: 0, B: 0, A: 255}, true},
		{"transparent is no-data", color.RGBA{R: 0, G: 3, B: 255, A: 0}, false},
	}
	for _, tc := range cases {
		if got := isActiveCell(tc.c); got != tc.want {
			t.Errorf("%s: isActiveCell = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestCountSeen(t *testing.T) {
	// Black background with a known number of blue pixels → countSeen returns
	// exactly that many (one pixel per address, padding is black). Uses a 32×32
	// canvas like a /23's padded image.
	img := image.NewRGBA(image.Rect(0, 0, 32, 32))
	bg := color.RGBA{R: 0, G: 0, B: 0, A: 255}     // black = no data
	used := color.RGBA{R: 0, G: 3, B: 255, A: 255} // blue = seen
	for y := 0; y < 32; y++ {
		for x := 0; x < 32; x++ {
			img.Set(x, y, bg)
		}
	}
	const want = 137
	painted := 0
	for y := 0; y < 32 && painted < want; y++ {
		for x := 0; x < 32 && painted < want; x++ {
			img.Set(x, y, used)
			painted++
		}
	}
	if got := countSeen(img); got != want {
		t.Errorf("countSeen = %d, want %d", got, want)
	}

	// All-black image → 0 seen (matches an all-black /24 like the user's VPS).
	black := image.NewRGBA(image.Rect(0, 0, 16, 16))
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			black.Set(x, y, bg)
		}
	}
	if got := countSeen(black); got != 0 {
		t.Errorf("countSeen(all black) = %d, want 0", got)
	}
}

func TestPeekPrefix_TotalFromPrefixNotPixels(t *testing.T) {
	// A /23 is rendered on a padded 32×32 (1024px) canvas but spans only 512
	// addresses — Total must come from the prefix, not the pixel count.
	body := synthHeatmapSize(t, 32, 90) // 32×32, 90 blue pixels
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	oldBase, oldDir := pfximgBaseURL, pfximgCacheDir
	pfximgBaseURL = srv.URL
	pfximgCacheDir = t.TempDir()
	defer func() { pfximgBaseURL, pfximgCacheDir = oldBase, oldDir }()

	res, err := peekPrefix(context.Background(), netip.MustParsePrefix("45.136.12.0/23"))
	if err != nil {
		t.Fatal(err)
	}
	if res.Active != 90 {
		t.Errorf("Active = %d, want 90 (non-black pixels)", res.Active)
	}
	if res.Total != 512 {
		t.Errorf("Total = %d, want 512 (/23 address count, not 1024 pixels)", res.Total)
	}
}

func TestPeekPrefix_RejectsHugePrefix(t *testing.T) {
	// /8 is far past the peek cap — must refuse before any network call.
	if _, err := peekPrefix(context.Background(), netip.MustParsePrefix("10.0.0.0/8")); err == nil {
		t.Error("expected peekPrefix to refuse an oversized prefix")
	}
}

func TestPeekPrefixUsage_UsesResolvedPrefix(t *testing.T) {
	// End-to-end: ResolvePrefix (Cymru stub) yields the announced /22, and the
	// peek must target that prefix — not a hardcoded /24 — with Total=1024.
	addr, cleanup := startCymruStub(t,
		"Bulk mode; whois.cymru.com\n12345 | 203.0.113.50 | 203.0.113.0/22 | US | arin | 2020-01-01 | EXAMPLE, US\n")
	defer cleanup()
	oldCymru := cymruWhoisAddr
	cymruWhoisAddr = addr
	defer func() { cymruWhoisAddr = oldCymru }()

	body := synthHeatmapSize(t, 32, 500) // /22 → padded 32×32, 500 blue
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	oldBase, oldDir := pfximgBaseURL, pfximgCacheDir
	pfximgBaseURL = srv.URL
	pfximgCacheDir = t.TempDir()
	defer func() { pfximgBaseURL, pfximgCacheDir = oldBase, oldDir }()

	res, err := PeekPrefixUsage(context.Background(), netip.MustParseAddr("203.0.113.50"))
	if err != nil {
		t.Fatal(err)
	}
	if res.CIDR != "203.0.113.0/22" {
		t.Errorf("CIDR = %q, want the resolved 203.0.113.0/22", res.CIDR)
	}
	if res.Total != 1024 {
		t.Errorf("Total = %d, want 1024 (/22)", res.Total)
	}
	if res.Active != 500 {
		t.Errorf("Active = %d, want 500", res.Active)
	}
	if !strings.Contains(gotPath, "203.0.113.0/22") {
		t.Errorf("pfximg path = %q, want it to target the /22", gotPath)
	}
}
