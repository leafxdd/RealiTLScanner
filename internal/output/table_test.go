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
	// 8 column labels (4 CJK each ×4) + (4 CJK each ×3) + (2 CJK each ×2) +
	// pure ASCII "CDN" → header visual width is well-defined; pin it so
	// future column changes force a re-check.
	if got := tableSepLen; got != 117 {
		t.Errorf("tableSepLen = %d, want 117 (regression: column layout changed without test update)", got)
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
