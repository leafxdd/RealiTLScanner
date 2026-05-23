package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestLiveLog_NonTTYIsNoop(t *testing.T) {
	// bytes.Buffer is not a TTY → LiveLog disables itself and writes nothing.
	var buf bytes.Buffer
	l := NewLiveLog(&buf, 7)
	if l.Enabled() {
		t.Fatal("expected Enabled()=false for bytes.Buffer")
	}
	for i := 0; i < 20; i++ {
		l.Push("event line")
	}
	l.Refresh()
	l.Close()
	if buf.Len() != 0 {
		t.Errorf("non-TTY LiveLog must not write; got %d bytes: %q", buf.Len(), buf.String())
	}
}

func TestTruncOneLine(t *testing.T) {
	cases := []struct {
		in, want string
		max      int
	}{
		{"short", "short", 20},
		{"a\nb\nc", "a b c", 20},
		{"with\rcr", "withcr", 20},
		{strings.Repeat("x", 30), strings.Repeat("x", 9) + "…", 10},
	}
	for _, tc := range cases {
		got := truncOneLine(tc.in, tc.max)
		if got != tc.want {
			t.Errorf("truncOneLine(%q,%d) = %q, want %q", tc.in, tc.max, got, tc.want)
		}
	}
}
