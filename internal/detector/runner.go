package detector

import (
	"context"
	"log/slog"
	"sync"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type Runner struct {
	detectors []Detector
	workers   int
}

func NewRunner(detectors []Detector, workers int) *Runner {
	if workers <= 0 {
		workers = 1
	}
	return &Runner{detectors: detectors, workers: workers}
}

func (r *Runner) Run(ctx context.Context, in <-chan *types.ScanResult) <-chan *types.ScanResult {
	out := make(chan *types.ScanResult, 64)
	var wg sync.WaitGroup
	wg.Add(r.workers)
	for i := 0; i < r.workers; i++ {
		go func() {
			defer wg.Done()
			for result := range in {
				select {
				case <-ctx.Done():
					return
				default:
				}
				r.processOne(ctx, result)
				out <- result
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

func (r *Runner) ProcessOne(ctx context.Context, result *types.ScanResult) {
	r.processOne(ctx, result)
}

func (r *Runner) processOne(ctx context.Context, result *types.ScanResult) {
	for _, d := range r.detectors {
		if !d.Available() {
			continue
		}
		if err := d.Detect(ctx, result); err != nil {
			slog.Debug("Detector failed", "detector", d.Name(), "ip", result.IP, "err", err)
		}
	}
}

func (r *Runner) AvailableDetectors() []string {
	var names []string
	for _, d := range r.detectors {
		if d.Available() {
			names = append(names, d.Name())
		}
	}
	return names
}
