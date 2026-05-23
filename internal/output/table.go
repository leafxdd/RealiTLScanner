package output

import (
	"fmt"
	"io"
	"os"
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
	termW io.Writer
	fileW io.Writer
	mu    sync.Mutex
	count int
	total int
}

func NewTableWriter(term io.Writer, file io.Writer) *TableWriter {
	return &TableWriter{termW: term, fileW: file}
}

func (tw *TableWriter) SetTotal(n int) {
	tw.total = n
}

func (tw *TableWriter) WriteHeader() {
	header := fmt.Sprintf("%-30s %-8s %-10s %-10s %-8s %-6s %-6s %-8s",
		"最终域名", "基础条件", "握手时间", "证书时间", "CDN", "热门", "推荐", "页面状态")
	sep := strings.Repeat("-", 96)

	tw.mu.Lock()
	defer tw.mu.Unlock()
	fmt.Fprintln(tw.termW, sep)
	fmt.Fprintln(tw.termW, header)
	fmt.Fprintln(tw.termW, sep)

	if tw.fileW != nil {
		fmt.Fprintln(tw.fileW, sep)
		fmt.Fprintln(tw.fileW, header)
		fmt.Fprintln(tw.fileW, sep)
	}
}

func (tw *TableWriter) WriteResult(result *types.ScanResult) {
	tw.mu.Lock()
	defer tw.mu.Unlock()
	tw.count++

	domain := result.TLS.CertDomain
	if len(domain) > 28 {
		domain = domain[:28] + ".."
	}

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
	fmt.Fprintln(tw.termW, termLine)

	if tw.fileW != nil {
		fileLine := fmt.Sprintf("%-30s %-8s %-10s %-10s %-8s %-6s %-6s %-8s",
			domain, basePlain, hsPlain, certPlain, cdnPlain, hotPlain, stars, statusPlain)
		fmt.Fprintln(tw.fileW, fileLine)
	}
}

func (tw *TableWriter) WriteSummary(suitable, unsuitable int, elapsed time.Duration) {
	tw.mu.Lock()
	defer tw.mu.Unlock()

	sep := strings.Repeat("-", 96)
	total := suitable + unsuitable
	pct := float64(0)
	if total > 0 {
		pct = float64(suitable) / float64(total) * 100
	}

	summary := fmt.Sprintf("\n%s\n检测完成: %d 个域名, %d 个适合 (%.1f%%), 耗时 %.1fs\n",
		sep, total, suitable, pct, elapsed.Seconds())

	fmt.Fprint(tw.termW, summary)
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
