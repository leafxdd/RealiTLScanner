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

// --- Hidden easter egg: bgp.tools /pfximg heatmap peek ---------------------
//
// NOT documented in the README — only visible to people reading the source.
// `-bgp-peek` is default-OFF and opt-in. It downloads the bgp.tools heatmap PNG
// for the /24 covering a target IP and counts the cells bgp.tools has "seen" in
// use, as a cheap "is this /24 worth scanning" preview. It is a hint, NOT a
// substitute for a real TLS probe.
//
// Legitimacy guardrails (all deliberate, do not remove):
//   - default OFF + explicit opt-in (the user turning it on accepts the behaviour)
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

// PeekResult summarises a /24 heatmap peek.
type PeekResult struct {
	CIDR   string // the /24 that was peeked, e.g. "1.2.3.0/24"
	Active int    // cells bgp.tools shows as in use
	Total  int    // cells in the grid (256 for a /24)
	Cached bool   // served from the local cache rather than the network
}

// PeekPrefixUsage downloads the bgp.tools pfximg heatmap for the /24 covering
// ip and estimates how many of its 256 addresses bgp.tools has seen in use.
// IPv4 only — pfximg is a /24 heatmap. Best-effort preview hint.
func PeekPrefixUsage(ctx context.Context, ip netip.Addr) (PeekResult, error) {
	if !ip.IsValid() || !ip.Is4() {
		return PeekResult{}, fmt.Errorf("pfximg peek needs an IPv4 address, got %q", ip)
	}
	slash24 := netip.PrefixFrom(ip, 24).Masked()
	cidr := slash24.String()

	data, cached, err := fetchPfximg(ctx, cidr)
	if err != nil {
		return PeekResult{}, err
	}
	img, err := png.Decode(strings.NewReader(string(data)))
	if err != nil {
		return PeekResult{}, fmt.Errorf("decode pfximg PNG: %w", err)
	}
	const gridN = 16 // 16×16 = 256 addresses in a /24
	return PeekResult{
		CIDR:   cidr,
		Active: countActiveGrid(img, gridN),
		Total:  gridN * gridN,
		Cached: cached,
	}, nil
}

// PeekPrefixUsageForAddr resolves addr (a literal IP, or a domain via DNS) to
// an IPv4 address and peeks its /24. Thin entry point for the CLI hook so the
// command layer needn't import net/netip.
func PeekPrefixUsageForAddr(ctx context.Context, addr string, enableIPv6 bool) (PeekResult, error) {
	ip, err := netip.ParseAddr(addr)
	if err != nil {
		netIP, lerr := LookupIP(addr, enableIPv6)
		if lerr != nil {
			return PeekResult{}, lerr
		}
		ip, err = netip.ParseAddr(netIP.String())
		if err != nil {
			return PeekResult{}, err
		}
	}
	return PeekPrefixUsage(ctx, ip)
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

// countActiveGrid samples the centre of each of gridN×gridN cells and counts
// those that look "in use" (distinguishable from the empty background). It
// samples cell centres rather than every pixel, so it is robust to the heatmap
// being rendered at any pixel scale (1px/cell or many px/cell).
func countActiveGrid(img image.Image, gridN int) int {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w == 0 || h == 0 || gridN <= 0 {
		return 0
	}
	active := 0
	for gy := 0; gy < gridN; gy++ {
		for gx := 0; gx < gridN; gx++ {
			px := b.Min.X + (gx*w)/gridN + w/(2*gridN)
			py := b.Min.Y + (gy*h)/gridN + h/(2*gridN)
			if isActiveCell(img.At(px, py)) {
				active++
			}
		}
	}
	return active
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
