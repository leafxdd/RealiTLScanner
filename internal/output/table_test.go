package output

import (
	"bytes"
	"strings"
	"testing"
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
	if got := tableSepLen; got != 126 {
		t.Errorf("tableSepLen = %d, want 126 (regression: column layout changed without test update)", got)
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
