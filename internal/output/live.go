package output

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

// LiveLog maintains a fixed-height rolling buffer rendered in-place on a TTY.
// On non-TTY writers it degrades to plain per-line writes so logs still go
// somewhere visible.
//
// Concurrency: Push/Refresh/Close are safe for concurrent use. The renderer
// throttles redraws so a flood of Push calls does not saturate the terminal.
type LiveLog struct {
	mu        sync.Mutex
	lines     []string
	max       int
	out       io.Writer
	enabled   bool
	drawn     bool
	lastDraw  time.Time
	minRedraw time.Duration
	closed    bool
}

func NewLiveLog(out io.Writer, height int) *LiveLog {
	if height < 1 {
		height = 7
	}
	return &LiveLog{
		lines:     make([]string, 0, height),
		max:       height,
		out:       out,
		enabled:   isTTY(out),
		minRedraw: 80 * time.Millisecond,
	}
}

// Enabled reports whether the writer is a TTY and in-place rendering is in use.
func (l *LiveLog) Enabled() bool { return l.enabled }

// Push appends a line to the rolling window. No-op when the writer is not a
// TTY (non-interactive callers should rely on the slog-based progress logged
// by the orchestrator instead).
func (l *LiveLog) Push(line string) {
	if !l.enabled {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	line = truncOneLine(line, 120)
	if len(l.lines) >= l.max {
		l.lines = l.lines[1:]
	}
	l.lines = append(l.lines, line)
	if time.Since(l.lastDraw) < l.minRedraw && len(l.lines) == l.max {
		return
	}
	l.render()
}

// Refresh forces a redraw without changing the buffer — used by callers that
// want to flush rate-limited updates (e.g. on scan completion).
func (l *LiveLog) Refresh() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed || !l.enabled {
		return
	}
	l.render()
}

// Close finalises the live region: one last render, then the cursor is parked
// on the line after the window so any subsequent writer appends normally.
func (l *LiveLog) Close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return
	}
	l.closed = true
	if !l.enabled || !l.drawn {
		return
	}
	l.render()
	// Park the cursor below the window. After render, cursor is at the top
	// of the region (col 0). Move down N rows so subsequent writes append.
	fmt.Fprintf(l.out, "\x1b[%dB\r", l.max)
}

// render draws the buffer in a fixed N-line region anchored at the row where
// the LiveLog was first drawn.
//
// Invariant: on entry, the cursor sits at column 0 of the region's top row.
// On exit, it sits at the same position so the next render can overwrite
// in place without scrolling the terminal.
//
// First-time setup writes N blank lines to reserve space (the terminal may
// scroll naturally), then moves cursor back up N. From then on, each render
// writes (N-1) lines terminated by \n plus a final line WITHOUT \n, then
// returns the cursor to the region top via \r + cursor-up.
//
// The previous implementation appended \n after every line, which caused a
// scroll on every render when the region happened to anchor at the bottom of
// the viewport: each scroll evicted the topmost rendered row into scrollback,
// inflating the apparent window size after many redraws.
func (l *LiveLog) render() {
	if !l.drawn {
		// Reserve N rows. \n at the last visible row triggers a one-time
		// scroll if needed; after that the region is stable.
		for i := 0; i < l.max; i++ {
			fmt.Fprintln(l.out)
		}
		fmt.Fprintf(l.out, "\x1b[%dA", l.max)
		l.drawn = true
	}
	for i := 0; i < l.max; i++ {
		text := ""
		if i < len(l.lines) {
			text = l.lines[i]
		}
		fmt.Fprintf(l.out, "\x1b[2K%s", text) // clear + content (no \n yet)
		if i < l.max-1 {
			fmt.Fprint(l.out, "\n") // newline between lines, NOT after last
		}
	}
	// Cursor is at end of the last region line. \r → col 0;
	// cursor-up (N-1) → top of region. Next render overwrites in place.
	if l.max > 1 {
		fmt.Fprintf(l.out, "\r\x1b[%dA", l.max-1)
	} else {
		fmt.Fprint(l.out, "\r")
	}
	l.lastDraw = time.Now()
}

func truncOneLine(s string, max int) string {
	// Replace embedded newlines so a stray \n doesn't corrupt the layout.
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", "")
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-1]) + "…"
}
