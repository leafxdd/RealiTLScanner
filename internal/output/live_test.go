package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestLiveLog_RenderReservesAndRedrawsInPlace(t *testing.T) {
	// Force enabled=true to test the TTY render path against a buffer.
	var buf bytes.Buffer
	l := &LiveLog{
		lines:     make([]string, 0, 3),
		max:       3,
		out:       &buf,
		enabled:   true,
		minRedraw: 0,
	}

	// First render: pushes "a", reserves N rows + cursor-up, then draws.
	l.Push("a")
	first := buf.String()
	buf.Reset()

	// First render must reserve 3 rows by emitting 3 \n then cursor-up.
	if !strings.Contains(first, "\n\n\n") {
		t.Errorf("first render must reserve N=3 rows with \\n*3; got %q", first)
	}
	if !strings.Contains(first, "\x1b[3A") {
		t.Errorf("first render must cursor-up by N before drawing; got %q", first)
	}

	// Subsequent render: must NOT contain the reservation sequence, must
	// end with cursor-return-to-top.
	l.Push("b")
	subsequent := buf.String()
	if strings.Contains(subsequent, "\n\n\n") {
		t.Errorf("subsequent render must not re-reserve rows; got %q", subsequent)
	}
	if !strings.HasSuffix(subsequent, "\r\x1b[2A") {
		t.Errorf("subsequent render must end with \\r + cursor-up(N-1); got %q", subsequent)
	}
	// Exactly N-1 = 2 newlines between region rows.
	if got := strings.Count(subsequent, "\n"); got != 2 {
		t.Errorf("subsequent render: expected 2 newlines, got %d in %q", got, subsequent)
	}

	// Push past capacity: oldest is evicted.
	buf.Reset()
	l.Push("c")
	l.Push("d") // evicts "a"
	rotated := buf.String()
	if !strings.Contains(rotated, "d") {
		t.Errorf("rotated frame missing latest 'd': %q", rotated)
	}
	// "a" should NOT be drawn in the last frame (last 3 lines = b,c,d).
	// Crude check: the final render block (after the last \x1b[2A) holds the
	// current 3 lines.
	idx := strings.LastIndex(rotated, "\x1b[2A")
	if idx < 0 {
		t.Fatalf("no cursor-up found in rotated output: %q", rotated)
	}
	// Step back to the start of that final frame's draw.
	finalFrame := rotated[idx:]
	if strings.Contains(finalFrame, "a") {
		t.Errorf("final frame still contains evicted line 'a': %q", finalFrame)
	}
}

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
