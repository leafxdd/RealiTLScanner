package output

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

type Progress struct {
	scanned   atomic.Int64
	feasible  atomic.Int64
	startTime time.Time
	ticker    *time.Ticker
	done      chan struct{}
	w         io.Writer
	mu        sync.Mutex
}

func NewProgress(w io.Writer) *Progress {
	p := &Progress{
		startTime: time.Now(),
		w:         w,
		done:      make(chan struct{}),
	}
	p.ticker = time.NewTicker(time.Second)
	go p.run()
	return p
}

func (p *Progress) IncScanned() {
	p.scanned.Add(1)
}

func (p *Progress) IncFeasible() {
	p.feasible.Add(1)
}

func (p *Progress) Scanned() int64 {
	return p.scanned.Load()
}

func (p *Progress) Feasible() int64 {
	return p.feasible.Load()
}

func (p *Progress) Stop() {
	p.ticker.Stop()
	close(p.done)
	p.print()
	fmt.Fprintln(p.w)
}

func (p *Progress) run() {
	for {
		select {
		case <-p.ticker.C:
			p.print()
		case <-p.done:
			return
		}
	}
}

func (p *Progress) print() {
	p.mu.Lock()
	defer p.mu.Unlock()
	scanned := p.scanned.Load()
	feasible := p.feasible.Load()
	elapsed := time.Since(p.startTime).Seconds()
	speed := float64(0)
	if elapsed > 0 {
		speed = float64(scanned) / elapsed
	}
	pct := float64(0)
	if scanned > 0 {
		pct = float64(feasible) / float64(scanned) * 100
	}
	now := time.Now().Format("15:04:05")
	fmt.Fprintf(p.w, "\r[%s] Scanned: %d | Feasible: %d (%.1f%%) | Speed: %.0f/s",
		now, scanned, feasible, pct, speed)
}
