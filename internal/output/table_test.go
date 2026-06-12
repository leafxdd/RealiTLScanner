package output

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

func TestStringVisualWidth(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"abc", 3},
		{"最终域名", 8},
		{"CDN", 3},
		{"热门", 4},
		{"页面状态", 8},
		{"101天", 5},
		{"a✓b", 3}, // U+2713 is East-Asian Narrow → 1 cell
	}
	for _, tc := range cases {
		if got := stringVisualWidth(tc.in); got != tc.want {
			t.Errorf("stringVisualWidth(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestTableHeaderSeparatorEnclosesHeader(t *testing.T) {
	// The 最终域名 column auto-fits, so the frame width is a function of the
	// widest domain. At the floor (no domain wider than the 最终域名 label) the
	// width is fully determined by the fixed columns — pin it so a column
	// layout change forces a re-check.
	minW := stringVisualWidth(domainHeaderLabel)
	header := headerRow(minW)
	if sepLen(minW) != stringVisualWidth(header) {
		t.Fatalf("sepLen(%d) %d does not equal visual width of header %d",
			minW, sepLen(minW), stringVisualWidth(header))
	}
	// Sanity: header has CJK, so the separator must be wider than rune length.
	runes := len([]rune(header))
	if sepLen(minW) <= runes {
		t.Errorf("expected sepLen (%d) to exceed header rune count (%d) due to CJK width",
			sepLen(minW), runes)
	}
	if got := sepLen(minW); got != 108 {
		t.Errorf("floor sepLen = %d, want 108 (regression: column layout changed without test update)", got)
	}
	// Auto-fit: a wider domain widens the frame by exactly the extra cells.
	wideW := minW + 20
	if got := sepLen(wideW); got != 108+20 {
		t.Errorf("sepLen(%d) = %d, want %d (frame must grow with the domain column)", wideW, got, 108+20)
	}
}

func TestRenderRow_AlignsRegardlessOfANSI(t *testing.T) {
	// Both rows share the same domain-column width, so colour mix must not
	// change their visual width. The previous byte-based padding happened to
	// look right because each coloured cell carried ~9 bytes of ANSI escapes
	// that consumed the "extra" padding.
	domainW := stringVisualWidth("example.com")
	colored := renderRow(
		domainW,
		"example.com",
		"\x1b[31m✗\x1b[0m",   // baseStr (red ✗)
		"\x1b[32m8ms\x1b[0m", // hsStr
		"\x1b[33m101天\x1b[0m",
		"\x1b[32m无\x1b[0m",
		"\x1b[31m✓\x1b[0m", // hot=true
		"\x1b[33m***\x1b[0m",
		"\x1b[32m200\x1b[0m",  // status colored
		"\x1b[31m代理\x1b[0m", // note colored
	)
	// Plain row: hot, status and note are bare (no ANSI). The old code
	// over-padded these cells by ~9 cells, pushing later columns right.
	plain := renderRow(domainW, "example.com", "✗", "8ms", "101天", "无", "-", "***", "-", "")

	visibleColored := stringVisualWidth(ansiRE.ReplaceAllString(colored, ""))
	visiblePlain := stringVisualWidth(plain)
	if visibleColored != visiblePlain {
		t.Errorf("rows misaligned: colored visible width %d, plain %d\n  colored=%q\n  plain  =%q",
			visibleColored, visiblePlain, colored, plain)
	}
	// Both rows must match the header / separator width for this domain width —
	// no over- or under-shoot regardless of colour mix.
	if visiblePlain != sepLen(domainW) {
		t.Errorf("plain row visual width %d != sepLen(%d) %d (row=%q)",
			visiblePlain, domainW, sepLen(domainW), plain)
	}
}

func TestTableAutoFitsLongestDomain(t *testing.T) {
	// The reported bug: a long cert domain was truncated. Auto-fit must size the
	// 最终域名 column to the widest domain in the buffered set and align every
	// frame line (separators, header, rows, summary rule) to one width.
	var buf bytes.Buffer
	tw := NewTableWriter(&buf, nil) // bytes.Buffer is non-TTY → no colour, no progress line
	long := "streamingaudio-ssl.itunes.apple.com"
	tw.WriteResult(&types.ScanResult{Feasible: true, TLS: &types.TLSInfo{CertDomain: long}})
	tw.WriteResult(&types.ScanResult{Feasible: true, TLS: &types.TLSInfo{CertDomain: "a.com"}})
	tw.WriteSummaryWithStats(2, 0, time.Second, SummaryStats{})

	out := buf.String()
	if !strings.Contains(out, long) {
		t.Fatalf("long domain truncated or missing from output:\n%s", out)
	}

	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	frameW := stringVisualWidth(lines[0]) // top separator
	if frameW < stringVisualWidth(long) {
		t.Errorf("frame width %d narrower than longest domain %d — would truncate",
			frameW, stringVisualWidth(long))
	}
	for i, ln := range lines {
		if ln == "" || strings.HasPrefix(ln, "检测完成") {
			continue // blank line / summary text aren't frame-width lines
		}
		if w := stringVisualWidth(ln); w != frameW {
			t.Errorf("line %d width %d != frame width %d: %q", i, w, frameW, ln)
		}
	}
}

func TestFormatNote_PQC(t *testing.T) {
	// Clean dest that negotiated a PQC hybrid → green "PQC".
	clean := &types.ScanResult{TLS: &types.TLSInfo{PQC: true}}
	if plain, colored := formatNote(clean); plain != "PQC" || !strings.Contains(colored, "PQC") {
		t.Errorf("clean PQC dest: plain=%q colored=%q, want \"PQC\"", plain, colored)
	}

	// Cheap TLD + PQC stack as "廉价/PQC", each segment keeping its colour.
	cheapPQC := &types.ScanResult{
		TLS:   &types.TLSInfo{PQC: true},
		Block: &types.BlockResult{CheapTLD: true},
	}
	if plain, colored := formatNote(cheapPQC); plain != "廉价/PQC" {
		t.Errorf("cheap+PQC dest: plain=%q, want \"廉价/PQC\"", plain)
	} else if !strings.Contains(colored, "廉价") || !strings.Contains(colored, "PQC") {
		t.Errorf("cheap+PQC colored=%q should carry both segments", colored)
	}

	// Cheap TLD without PQC → just 廉价.
	cheap := &types.ScanResult{TLS: &types.TLSInfo{}, Block: &types.BlockResult{CheapTLD: true}}
	if plain, _ := formatNote(cheap); plain != "廉价" {
		t.Errorf("cheap-only dest: note=%q, want \"廉价\"", plain)
	}

	// Everything stacks — a proxy panel that is also a cheap TLD and speaks PQC
	// shows all three: "面板/廉价/PQC".
	all := &types.ScanResult{
		TLS:   &types.TLSInfo{PQC: true},
		Block: &types.BlockResult{Hit: true, Reason: "proxy_server", CheapTLD: true},
	}
	if plain, _ := formatNote(all); plain != "面板/廉价/PQC" {
		t.Errorf("panel+cheap+PQC dest: note=%q, want \"面板/廉价/PQC\"", plain)
	}

	// Unflagged non-PQC dest → no note.
	if plain, _ := formatNote(&types.ScanResult{TLS: &types.TLSInfo{}}); plain != "" {
		t.Errorf("clean non-PQC dest: note=%q, want empty", plain)
	}

	// The widest possible stack must fit colNoteW so the fixed, stream-rendered
	// frame never overflows. This is the bound colNoteW is sized against.
	worst := &types.ScanResult{
		TLS:   &types.TLSInfo{PQC: true},
		Block: &types.BlockResult{Hit: true, Reason: "dynamic_dns", CheapTLD: true},
	}
	plain, _ := formatNote(worst)
	if plain != "动态DNS/廉价/PQC" {
		t.Errorf("worst-case note=%q, want \"动态DNS/廉价/PQC\"", plain)
	}
	if w := stringVisualWidth(plain); w > colNoteW {
		t.Errorf("worst-case note width %d exceeds colNoteW %d — frame would overflow", w, colNoteW)
	}
}
