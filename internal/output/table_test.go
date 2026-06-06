package output

import (
	"bytes"
	"strings"
	"testing"

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
	if tableSepLen != stringVisualWidth(tableHeader) {
		t.Fatalf("tableSepLen %d does not equal visual width of tableHeader %d",
			tableSepLen, stringVisualWidth(tableHeader))
	}
	// Sanity: header has CJK, so sep must be wider than rune length.
	runes := len([]rune(tableHeader))
	if tableSepLen <= runes {
		t.Errorf("expected tableSepLen (%d) to exceed header rune count (%d) due to CJK width",
			tableSepLen, runes)
	}
	// 9 column labels with CJK widths → header visual width is well-defined;
	// pin it so future column changes force a re-check.
	if got := tableSepLen; got != 134 {
		t.Errorf("tableSepLen = %d, want 134 (regression: column layout changed without test update)", got)
	}
}

func TestRenderRow_AlignsRegardlessOfANSI(t *testing.T) {
	// Mixed row: every cell coloured. The previous byte-based padding
	// happened to look right here because each cell carried ~9 bytes of
	// ANSI escapes that consumed the "extra" padding.
	colored := renderRow(
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
	plain := renderRow("example.com", "✗", "8ms", "101天", "无", "-", "***", "-", "")

	visibleColored := stringVisualWidth(ansiRE.ReplaceAllString(colored, ""))
	visiblePlain := stringVisualWidth(plain)
	if visibleColored != visiblePlain {
		t.Errorf("rows misaligned: colored visible width %d, plain %d\n  colored=%q\n  plain  =%q",
			visibleColored, visiblePlain, colored, plain)
	}
	// Both rows must match the header / separator width — no over- or
	// under-shoot regardless of colour mix.
	if visiblePlain != tableSepLen {
		t.Errorf("plain row visual width %d != tableSepLen %d (row=%q)",
			visiblePlain, tableSepLen, plain)
	}
}

func TestWriteHeader_SeparatorMatchesHeaderWidth(t *testing.T) {
	var term bytes.Buffer
	tw := &TableWriter{termW: &term, colorEnabled: false}
	tw.WriteHeader()
	lines := strings.Split(strings.TrimRight(term.String(), "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (sep/header/sep), got %d: %q", len(lines), lines)
	}
	if lines[0] != lines[2] {
		t.Errorf("top and bottom separators differ:\ntop=%q\nbot=%q", lines[0], lines[2])
	}
	if stringVisualWidth(lines[1]) != stringVisualWidth(lines[0]) {
		t.Errorf("header visual width %d != separator width %d\nheader=%q\nsep=%q",
			stringVisualWidth(lines[1]), stringVisualWidth(lines[0]), lines[1], lines[0])
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
