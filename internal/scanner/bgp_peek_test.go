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
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 16, 16))
	bg := color.RGBA{R: 0, G: 0, B: 0, A: 255}      // black = no data
	used := color.RGBA{R: 0, G: 3, B: 255, A: 255}  // blue = seen
	for y := 0; y < 16; y++ {
		for x := 0; x < 16; x++ {
			if y*16+x < activeCells {
				img.Set(x, y, used)
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

	res, err := PeekPrefixUsage(context.Background(), netip.MustParseAddr("1.2.3.4"))
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
	res2, err := PeekPrefixUsage(context.Background(), netip.MustParseAddr("1.2.3.99"))
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

func TestCountActiveGrid_ScaleInvariant(t *testing.T) {
	// A 160×160 image (10px per cell) on a black background with the top-left
	// 4×4 cells filled blue must count as 16 seen cells under a 16×16 grid.
	img := image.NewRGBA(image.Rect(0, 0, 160, 160))
	bg := color.RGBA{R: 0, G: 0, B: 0, A: 255}     // black = no data
	used := color.RGBA{R: 0, G: 3, B: 255, A: 255} // blue = seen
	for y := 0; y < 160; y++ {
		for x := 0; x < 160; x++ {
			img.Set(x, y, bg)
		}
	}
	for cy := 0; cy < 4; cy++ {
		for cx := 0; cx < 4; cx++ {
			for y := cy * 10; y < cy*10+10; y++ {
				for x := cx * 10; x < cx*10+10; x++ {
					img.Set(x, y, used)
				}
			}
		}
	}
	if got := countActiveGrid(img, 16); got != 16 {
		t.Errorf("countActiveGrid = %d, want 16", got)
	}
	if got := countActiveGrid(img, 0); got != 0 {
		t.Errorf("countActiveGrid(gridN=0) = %d, want 0", got)
	}
}
