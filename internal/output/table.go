package output

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/xtls/RealiTLScanner/internal/types"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
)

var colorEnabled = true

func init() {
	if os.Getenv("NO_COLOR") != "" {
		colorEnabled = false
	}
	enableVirtualTerminal()
}

type TableWriter struct {
	termW        io.Writer
	fileW        io.Writer
	mu           sync.Mutex
	count        int
	total        int
	colorEnabled bool
}

func NewTableWriter(term io.Writer, file io.Writer) *TableWriter {
	return &TableWriter{
		termW:        term,
		fileW:        file,
		colorEnabled: colorEnabled && isTTY(term),
	}
}

// isTTY reports whether w is a character device — terminals are; pipes,
// redirected files, and bytes.Buffer are not.
func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

func (tw *TableWriter) SetTotal(n int) {
	tw.total = n
}

// Column visual widths (terminal cells, CJK = 2). These match the natural
// rendering of the CJK header labels under the previous %-Ns layout, so the
// visual look is preserved while data rows are padded by cell width instead
// of byte count. Padding by bytes (the old approach) over-counted ANSI escape
// sequences, so cells without colour (e.g. hot="-") overshot their column
// width and pushed subsequent columns out of alignment.
const (
	colDomainW = 34
	colBasicW  = 12
	colHsW     = 14
	colCertW   = 14
	colCDNW    = 8
	colHotW    = 8
	colRecW    = 8
	colStatusW = 12
	// 备注 stacks every applicable flag (e.g. 代理/廉价/PQC); sized to the widest
	// possible note 动态DNS/廉价/PQC (7+1+4+1+3 = 16 cells) so the fixed,
	// stream-rendered frame never overflows. TestFormatNote_PQC guards the bound.
	colNoteW = 16
)

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// stringVisualWidth returns the terminal cell width of s, counting CJK and
// fullwidth characters as 2 cells. Sufficient for our header — we don't pull
// in go-runewidth for 8 fixed labels.
func stringVisualWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case (r >= 0x1100 && r <= 0x115F), // Hangul Jamo
			(r >= 0x2E80 && r <= 0x9FFF),  // CJK Radicals .. Unified Ideographs
			(r >= 0xA000 && r <= 0xA4CF),  // Yi
			(r >= 0xAC00 && r <= 0xD7A3),  // Hangul Syllables
			(r >= 0xF900 && r <= 0xFAFF),  // CJK Compatibility Ideographs
			(r >= 0xFE30 && r <= 0xFE4F),  // CJK Compatibility Forms
			(r >= 0xFF00 && r <= 0xFF60),  // Fullwidth forms
			(r >= 0xFFE0 && r <= 0xFFE6):  // Fullwidth signs
			w += 2
		default:
			w++
		}
	}
	return w
}

// padVisualRight pads s with trailing spaces until its visual cell width
// (excluding ANSI SGR escapes) reaches width. Returns s unchanged when
// already at or above width.
func padVisualRight(s string, width int) string {
	visible := ansiRE.ReplaceAllString(s, "")
	have := stringVisualWidth(visible)
	if have >= width {
		return s
	}
	return s + strings.Repeat(" ", width-have)
}

// renderRow joins nine pre-built cells with single-space delimiters,
// padding each to its column's visual cell width. ANSI escapes inside
// cells are preserved but ignored for width.
func renderRow(domain, basic, hs, cert, cdn, hot, rec, status, note string) string {
	return padVisualRight(domain, colDomainW) + " " +
		padVisualRight(basic, colBasicW) + " " +
		padVisualRight(hs, colHsW) + " " +
		padVisualRight(cert, colCertW) + " " +
		padVisualRight(cdn, colCDNW) + " " +
		padVisualRight(hot, colHotW) + " " +
		padVisualRight(rec, colRecW) + " " +
		padVisualRight(status, colStatusW) + " " +
		padVisualRight(note, colNoteW)
}

// tableHeader is the single source of truth for column layout. The dash
// separator below is sized by its actual terminal cell width — Chinese
// labels take 2 cells per glyph, so a naive rune count under-sizes the
// separator and lets the last two columns leak past it.
var (
	tableHeader = renderRow(
		"最终域名", "基础条件", "握手时间", "证书时间",
		"CDN", "热门", "推荐", "页面状态", "备注")
	tableSepLen = stringVisualWidth(tableHeader)
)

// writeTerm writes s to the terminal stream, stripping ANSI colour escapes
// when the destination is not a TTY.
func (tw *TableWriter) writeTerm(s string) {
	if !tw.colorEnabled {
		s = ansiRE.ReplaceAllString(s, "")
	}
	fmt.Fprint(tw.termW, s)
}

func (tw *TableWriter) WriteHeader() {
	sep := strings.Repeat("-", tableSepLen)

	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.writeTerm(sep + "\n")
	tw.writeTerm(tableHeader + "\n")
	tw.writeTerm(sep + "\n")

	if tw.fileW != nil {
		fmt.Fprintln(tw.fileW, sep)
		fmt.Fprintln(tw.fileW, tableHeader)
		fmt.Fprintln(tw.fileW, sep)
	}
}

func (tw *TableWriter) WriteResult(result *types.ScanResult) {
	if result.TLS == nil {
		// No TLS info → nothing meaningful to render. The pipeline filters
		// non-feasible scans out by default; this is only reachable in
		// PassAll mode or when a downstream detector ran first.
		return
	}
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.count++

	domain := truncateByRune(result.TLS.CertDomain, 28)

	baseOk := result.Feasible
	baseStr := colorize("✓", colorGreen, baseOk)
	basePlain := "✓"
	if !baseOk {
		baseStr = colorize("✗", colorRed, true)
		basePlain = "✗"
	}

	hsTime := result.TLS.HandshakeTime
	hsStr := formatHandshakeTime(hsTime)
	hsPlain := fmt.Sprintf("%dms", hsTime.Milliseconds())

	daysLeft := 0
	if !result.TLS.CertExpiry.IsZero() {
		daysLeft = int(time.Until(result.TLS.CertExpiry).Hours() / 24)
	}
	certStr := formatCertDays(daysLeft)
	certPlain := fmt.Sprintf("%d天", daysLeft)

	cdnLevel := "无"
	if result.CDN != nil && result.CDN.Level != "" && result.CDN.Level != "none" {
		cdnLevel = result.CDN.Level
	}
	cdnStr := formatCDN(cdnLevel)
	cdnPlain := cdnLevel

	hotStr := "-"
	hotPlain := "-"
	if result.HotSite != nil && result.HotSite.IsHot {
		hotStr = colorize("✓", colorRed, true)
		hotPlain = "✓"
	}

	score := result.Score
	stars := strings.Repeat("*", score)
	starsStr := colorize(stars, colorYellow, true)

	statusCode := 0
	if result.Redirect != nil {
		statusCode = result.Redirect.StatusCode
	}
	statusStr := formatStatus(statusCode)
	statusPlain := fmt.Sprintf("%d", statusCode)
	if statusCode == 0 {
		statusStr = "-"
		statusPlain = "-"
	}

	notePlain, noteStr := formatNote(result)

	termLine := renderRow(domain, baseStr, hsStr, certStr, cdnStr, hotStr, starsStr, statusStr, noteStr)
	tw.writeTerm(termLine + "\n")

	if tw.fileW != nil {
		fileLine := renderRow(domain, basePlain, hsPlain, certPlain, cdnPlain, hotPlain, stars, statusPlain, notePlain)
		fmt.Fprintln(tw.fileW, fileLine)
	}
}

// SummaryStats are optional counters surfaced in WriteSummary; pass zero
// values if not applicable.
type SummaryStats struct {
	Attempted int64
	TLSFailed int64
	Dropped   int64
}

func (tw *TableWriter) WriteSummary(suitable, unsuitable int, elapsed time.Duration) {
	tw.WriteSummaryWithStats(suitable, unsuitable, elapsed, SummaryStats{})
}

func (tw *TableWriter) WriteSummaryWithStats(suitable, unsuitable int, elapsed time.Duration, stats SummaryStats) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	sep := strings.Repeat("-", tableSepLen)
	total := suitable + unsuitable
	pct := float64(0)
	if total > 0 {
		pct = float64(suitable) / float64(total) * 100
	}

	summary := fmt.Sprintf("\n%s\n检测完成: %d 个域名, %d 个适合 (%.1f%%), 耗时 %.1fs\n",
		sep, total, suitable, pct, elapsed.Seconds())
	if stats.Attempted > 0 {
		summary += fmt.Sprintf("扫描统计: attempted=%d  tls_failed=%d  dropped=%d\n",
			stats.Attempted, stats.TLSFailed, stats.Dropped)
	}

	tw.writeTerm(summary)
	if tw.fileW != nil {
		fmt.Fprint(tw.fileW, summary)
	}
}

// truncateByRune cuts s to at most max runes, appending ".." when truncated.
// Byte-slicing a multi-byte string mid-rune would produce mojibake.
func truncateByRune(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	runes := []rune(s)
	return string(runes[:max]) + ".."
}

func colorize(s, color string, apply bool) string {
	if !apply || !colorEnabled {
		return s
	}
	return color + s + colorReset
}

func formatHandshakeTime(d time.Duration) string {
	ms := d.Milliseconds()
	s := fmt.Sprintf("%dms", ms)
	if ms <= 200 {
		return colorize(s, colorGreen, true)
	} else if ms <= 500 {
		return colorize(s, colorYellow, true)
	}
	return colorize(s, colorRed, true)
}

func formatCertDays(days int) string {
	s := fmt.Sprintf("%d天", days)
	if days >= 60 {
		return colorize(s, colorGreen, true)
	} else if days >= 30 {
		return colorize(s, colorYellow, true)
	}
	return colorize(s, colorRed, true)
}

func formatCDN(level string) string {
	if level == "无" || level == "" {
		return colorize("无", colorGreen, true)
	}
	return colorize(level, colorRed, true)
}

func formatStatus(code int) string {
	s := fmt.Sprintf("%d", code)
	if code == 200 {
		return colorize(s, colorGreen, true)
	} else if code >= 300 && code < 400 {
		return colorize(s, colorYellow, true)
	} else if code == 404 {
		return colorize(s, colorBlue, true)
	}
	return colorize(s, colorRed, true)
}

// formatNote renders the 备注 column: every applicable flag for a Reality dest
// candidate, stacked and joined by "/". Order is negatives-then-perk — the hard
// blocklist veto (代理/面板/动态DNS/NAS, red), then a cheap TLD (廉价, yellow),
// then a post-quantum key exchange (PQC, green) — e.g. "面板/廉价/PQC", or just
// "PQC". Each segment keeps its own colour. The widest possible stack
// (动态DNS/廉价/PQC) is colNoteW cells, so the fixed frame always encloses it.
// Returns (plain, colored) so file output stays ANSI-free.
func formatNote(result *types.ScanResult) (plain, colored string) {
	var plains, coloreds []string
	if result.Block != nil && result.Block.Hit {
		var label string
		switch result.Block.Reason {
		case "proxy_keyword":
			label = "代理"
		case "proxy_server":
			label = "面板"
		case "dynamic_dns":
			label = "动态DNS"
		case "nas":
			label = "NAS"
		default:
			label = "屏蔽"
		}
		plains = append(plains, label)
		coloreds = append(coloreds, colorize(label, colorRed, true))
	}
	if result.Block != nil && result.Block.CheapTLD {
		plains = append(plains, "廉价")
		coloreds = append(coloreds, colorize("廉价", colorYellow, true))
	}
	if result.TLS != nil && result.TLS.PQC {
		plains = append(plains, "PQC")
		coloreds = append(coloreds, colorize("PQC", colorGreen, true))
	}
	return strings.Join(plains, "/"), strings.Join(coloreds, "/")
}
