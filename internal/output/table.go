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

// tableHeader is the single source of truth for column layout. The dash
// separator below is sized by its actual terminal cell width — Chinese
// labels take 2 cells per glyph, so a naive rune count under-sizes the
// separator and lets the last two columns leak past it.
var (
	tableHeader = fmt.Sprintf("%-30s %-8s %-10s %-10s %-8s %-6s %-6s %-8s",
		"最终域名", "基础条件", "握手时间", "证书时间", "CDN", "热门", "推荐", "页面状态")
	tableSepLen = stringVisualWidth(tableHeader)
)

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

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

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

	termLine := fmt.Sprintf("%-30s %-18s %-20s %-20s %-18s %-16s %-16s %-18s",
		domain, baseStr, hsStr, certStr, cdnStr, hotStr, starsStr, statusStr)
	tw.writeTerm(termLine + "\n")

	if tw.fileW != nil {
		fileLine := fmt.Sprintf("%-30s %-8s %-10s %-10s %-8s %-6s %-6s %-8s",
			domain, basePlain, hsPlain, certPlain, cdnPlain, hotPlain, stars, statusPlain)
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
