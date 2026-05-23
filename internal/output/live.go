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
}

func (l *LiveLog) render() {
	if l.drawn {
		fmt.Fprintf(l.out, "\x1b[%dA", l.max) // cursor up N
	} else {
		l.drawn = true
	}
	for i := 0; i < l.max; i++ {
		text := ""
		if i < len(l.lines) {
			text = l.lines[i]
		}
		fmt.Fprintf(l.out, "\x1b[2K%s\n", text) // clear line + content + newline
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
