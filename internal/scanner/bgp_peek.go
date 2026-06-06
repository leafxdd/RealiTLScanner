package scanner

import (
	"context"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// --- bgp.tools /pfximg heatmap peek ----------------------------------------
//
// After -bgp picks a prefix, it counts how many addresses bgp.tools has "seen"
// in that prefix by downloading bgp.tools' heatmap PNG and counting the
// non-black pixels. It's an up-front size readout and the abort gate — a hint,
// NOT a substitute for a real probe: pfximg reflects bgp.tools' ICMP-ping view,
// so an all-black prefix can still host pingable-but-firewalled servers and a
// busy one says nothing about TLS. The probe-first TCP phase is the ground truth.
//
// Good-citizen guardrails (deliberate, do not remove):
//   - HONEST User-Agent (reuses bgpUserAgent; never spoofs a browser)
//   - local cache with a TTL so we don't hammer bgp.tools
//   - pure-Go image/png decode (no ImageMagick / external binary dependency)

// Overridable for tests; the slash in a CIDR is kept literal in the path.
var (
	pfximgBaseURL  = "https://bgp.tools/pfximg"
	pfximgClient   = &http.Client{Timeout: 20 * time.Second}
	pfximgCacheTTL = 6 * time.Hour
	pfximgCacheDir = "" // empty → <os.TempDir()>/realitls-pfximg
)

// PeekResult summarises a prefix heatmap peek.
type PeekResult struct {
	CIDR   string // the prefix that was peeked, e.g. "43.159.32.0/19"
	Active int    // addresses bgp.tools has seen in use (non-black pixels)
	Total  int    // addresses in the prefix
	Cached bool   // served from the local cache rather than the network
}

// peekMaxAddrs caps how large a prefix we will peek. bgp.tools renders one
// pixel per address (padding odd-host-bit prefixes with black), so a /16 is a
// 256×256 image — fine. Anything bigger isn't useful for neighbour discovery
// and risks bgp.tools switching to an aggregated /24-per-pixel rendering, where
// the per-address count no longer holds.
const peekMaxAddrs = 1 << 16 // /16

// peekPrefix fetches and counts a single prefix's heatmap. bgp.tools paints one
// pixel per address — coloured (blue→red) if it has seen the address, black if
// not — and pads odd-host-bit prefixes (e.g. /23, /19) with extra black to a
// square canvas. Since padding is black, counting every non-black pixel yields
// the exact "seen" count regardless of prefix size; Total is the prefix's
// address count (not the padded pixel count).
func peekPrefix(ctx context.Context, prefix netip.Prefix) (PeekResult, error) {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return PeekResult{}, fmt.Errorf("pfximg peek needs an IPv4 prefix, got %q", prefix)
	}
	total := PrefixAddrCount(prefix)
	if total > peekMaxAddrs {
		return PeekResult{}, fmt.Errorf("prefix %s too large to peek (%d > %d addresses)", prefix, total, peekMaxAddrs)
	}
	cidr := prefix.String()
	data, cached, err := fetchPfximg(ctx, cidr)
	if err != nil {
		return PeekResult{}, err
	}
	img, err := png.Decode(strings.NewReader(string(data)))
	if err != nil {
		return PeekResult{}, fmt.Errorf("decode pfximg PNG: %w", err)
	}
	return PeekResult{
		CIDR:   cidr,
		Active: countSeen(img),
		Total:  total,
		Cached: cached,
	}, nil
}

// PeekPrefix counts how many addresses bgp.tools has seen in prefix (its
// non-black heatmap pixels) — the -bgp active-neighbour estimate, IPv4 only. It
// peeks exactly the prefix given (the one smart selection chose).
func PeekPrefix(ctx context.Context, prefix netip.Prefix) (PeekResult, error) {
	return peekPrefix(ctx, prefix)
}

// fetchPfximg returns the heatmap PNG bytes for cidr, serving a fresh-enough
// cached copy when present and otherwise downloading (and caching) it. The
// cache write is best-effort: a failure there never fails the peek.
func fetchPfximg(ctx context.Context, cidr string) (data []byte, cached bool, err error) {
	path := pfximgCachePath(cidr)
	if info, statErr := os.Stat(path); statErr == nil && time.Since(info.ModTime()) < pfximgCacheTTL {
		if b, readErr := os.ReadFile(path); readErr == nil {
			return b, true, nil
		}
	}

	url := pfximgBaseURL + "/" + cidr
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	// Honest UA — identify ourselves so bgp.tools can rate-limit/identify us
	// fairly. NEVER spoof a browser here.
	req.Header.Set("User-Agent", bgpUserAgent)
	resp, err := pfximgClient.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, fmt.Errorf("pfximg HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, false, err
	}

	// Best-effort cache write.
	dir := pfximgCacheDirResolved()
	if mkErr := os.MkdirAll(dir, 0o755); mkErr == nil {
		_ = os.WriteFile(path, body, 0o644)
	}
	return body, false, nil
}

func pfximgCacheDirResolved() string {
	if pfximgCacheDir != "" {
		return pfximgCacheDir
	}
	return filepath.Join(os.TempDir(), "realitls-pfximg")
}

func pfximgCachePath(cidr string) string {
	name := strings.ReplaceAll(cidr, "/", "_") + ".png"
	return filepath.Join(pfximgCacheDirResolved(), name)
}

// countSeen counts every non-black pixel in the heatmap. bgp.tools paints one
// pixel per address (black = no data, coloured = seen) and pads odd-host-bit
// prefixes with black, so a full-image non-black count equals the number of
// addresses bgp.tools has seen — no grid assumption, works at any prefix size.
func countSeen(img image.Image) int {
	b := img.Bounds()
	seen := 0
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if isActiveCell(img.At(x, y)) {
				seen++
			}
		}
	}
	return seen
}

// isActiveCell classifies a bgp.tools heatmap pixel. The heatmap's empty
// background is black (rgba 0,0,0) — bgp.tools' internet-wide ping scan saw no
// host there — while any address it has seen is coloured (blue for sparse
// through to red for dense). So an opaque, non-black cell is a seen neighbour;
// black or transparent means no data. Verified against real /24 images: an
// all-black /24 → 0 seen, a 234-blue /24 → 234 seen.
func isActiveCell(c color.Color) bool {
	r, g, bl, a := c.RGBA() // each 0..0xFFFF
	if a < 0x8000 {
		return false // transparent → no data
	}
	// Black background → no data. Any colour (even a dim blue) clears this
	// floor; pure/near black stays under it.
	const darkFloor = 0x2000 // ~12.5%
	return r > darkFloor || g > darkFloor || bl > darkFloor
}
