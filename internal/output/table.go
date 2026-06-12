package output

import (
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

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
	progress     bool       // termW is a TTY → draw a transient "检测中" line while buffering
	rows         []tableRow // buffered until flush so the domain column can auto-fit
	sepLen       int        // visual width of the rendered frame; set at flush, reused by the summary
	flushed      bool
}

// tableRow holds one result's pre-built cells in both variants: coloured for the
// terminal, plain for file output. Cells are stored unpadded — the domain column
// width isn't known until every row is in, so padding happens at flush time.
type tableRow struct {
	term [9]string
	file [9]string
}

func NewTableWriter(term io.Writer, file io.Writer) *TableWriter {
	return &TableWriter{
		termW:        term,
		fileW:        file,
		colorEnabled: colorEnabled && isTTY(term),
		progress:     isTTY(term),
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

// Fixed column visual widths (terminal cells, CJK = 2). The 最终域名 column is
// the exception — it auto-fits the widest domain in the result set (see flush),
// so a long cert domain like streamingaudio-ssl.itunes.apple.com is never
// truncated. Padding is by cell width, not byte count, so ANSI escapes in a
// coloured cell don't inflate its measured width.
const (
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

// domainHeaderLabel is the 最终域名 column header and the floor for the auto-fit
// domain width — the column never shrinks below its own label.
const domainHeaderLabel = "最终域名"

var ansiRE = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// stringVisualWidth returns the terminal cell width of s, counting CJK and
// fullwidth characters as 2 cells. Sufficient for our header — we don't pull
// in go-runewidth for 8 fixed labels.
func stringVisualWidth(s string) int {
	w := 0
	for _, r := range s {
		switch {
		case (r >= 0x1100 && r <= 0x115F), // Hangul Jamo
			(r >= 0x2E80 && r <= 0x9FFF), // CJK Radicals .. Unified Ideographs
			(r >= 0xA000 && r <= 0xA4CF), // Yi
			(r >= 0xAC00 && r <= 0xD7A3), // Hangul Syllables
			(r >= 0xF900 && r <= 0xFAFF), // CJK Compatibility Ideographs
			(r >= 0xFE30 && r <= 0xFE4F), // CJK Compatibility Forms
			(r >= 0xFF00 && r <= 0xFF60), // Fullwidth forms
			(r >= 0xFFE0 && r <= 0xFFE6): // Fullwidth signs
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

// renderRow joins nine pre-built cells with single-space delimiters, padding
// each to its column's visual cell width. The domain column width is passed in
// because it is computed dynamically (auto-fit). ANSI escapes inside cells are
// preserved but ignored for width.
func renderRow(domainW int, domain, basic, hs, cert, cdn, hot, rec, status, note string) string {
	return padVisualRight(domain, domainW) + " " +
		padVisualRight(basic, colBasicW) + " " +
		padVisualRight(hs, colHsW) + " " +
		padVisualRight(cert, colCertW) + " " +
		padVisualRight(cdn, colCDNW) + " " +
		padVisualRight(hot, colHotW) + " " +
		padVisualRight(rec, colRecW) + " " +
		padVisualRight(status, colStatusW) + " " +
		padVisualRight(note, colNoteW)
}

// headerRow renders the column header for a given domain-column width. The dash
// separator (see flush) is sized by this row's terminal cell width — CJK labels
// take 2 cells per glyph, so a naive rune count under-sizes it and lets the last
// columns leak past it.
func headerRow(domainW int) string {
	return renderRow(domainW,
		domainHeaderLabel, "基础条件", "握手时间", "证书时间",
		"CDN", "热门", "推荐", "页面状态", "备注")
}

// sepLen is the visual width of the frame (header / separator) for a given
// domain-column width.
func sepLen(domainW int) int { return stringVisualWidth(headerRow(domainW)) }

// writeTerm writes s to the terminal stream, stripping ANSI colour escapes
// when the destination is not a TTY.
func (tw *TableWriter) writeTerm(s string) {
	if !tw.colorEnabled {
		s = ansiRE.ReplaceAllString(s, "")
	}
	fmt.Fprint(tw.termW, s)
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

	domain := result.TLS.CertDomain

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

	tw.rows = append(tw.rows, tableRow{
		term: [9]string{domain, baseStr, hsStr, certStr, cdnStr, hotStr, starsStr, statusStr, noteStr},
		file: [9]string{domain, basePlain, hsPlain, certPlain, cdnPlain, hotPlain, stars, statusPlain, notePlain},
	})
	tw.drawProgress()
}

// flush computes the auto-fit domain-column width across every buffered row,
// then emits the separator, header, and all rows in one pass. Buffering is what
// lets the first column size itself to the longest domain without truncation —
// at the cost of per-row streaming, a trade made deliberately. Caller must hold
// tw.mu. Idempotent.
func (tw *TableWriter) flush() {
	if tw.flushed {
		return
	}
	tw.flushed = true
	tw.clearProgress()

	domainW := stringVisualWidth(domainHeaderLabel)
	for i := range tw.rows {
		if w := stringVisualWidth(tw.rows[i].file[0]); w > domainW {
			domainW = w
		}
	}
	header := headerRow(domainW)
	tw.sepLen = stringVisualWidth(header)
	sep := strings.Repeat("-", tw.sepLen)

	tw.writeTerm(sep + "\n")
	tw.writeTerm(header + "\n")
	tw.writeTerm(sep + "\n")
	for i := range tw.rows {
		c := tw.rows[i].term
		tw.writeTerm(renderRow(domainW, c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8]) + "\n")
	}

	if tw.fileW != nil {
		fmt.Fprintln(tw.fileW, sep)
		fmt.Fprintln(tw.fileW, header)
		fmt.Fprintln(tw.fileW, sep)
		for i := range tw.rows {
			c := tw.rows[i].file
			fmt.Fprintln(tw.fileW, renderRow(domainW, c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8]))
		}
	}
}

// drawProgress paints a single transient "检测中 N/M" line on the terminal so a
// long detection phase doesn't look frozen while rows are buffered. TTY only —
// the cursor-control escapes would corrupt piped/redirected output. Caller must
// hold tw.mu.
func (tw *TableWriter) drawProgress() {
	if !tw.progress {
		return
	}
	msg := fmt.Sprintf("检测中 %d", tw.count)
	if tw.total > 0 {
		msg = fmt.Sprintf("检测中 %d/%d", tw.count, tw.total)
	}
	fmt.Fprintf(tw.termW, "\r\x1b[2K%s", msg)
}

// clearProgress erases the transient progress line so the table frame starts at
// column 0 of a clean line. No-op on non-TTY.
func (tw *TableWriter) clearProgress() {
	if !tw.progress {
		return
	}
	fmt.Fprint(tw.termW, "\r\x1b[2K")
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
	tw.flush() // emit the buffered table first; this also sets tw.sepLen

	sep := strings.Repeat("-", tw.sepLen)
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
