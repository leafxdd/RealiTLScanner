package pipeline

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"

	"github.com/xtls/RealiTLScanner/internal/detector"
	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/scanner"
	"github.com/xtls/RealiTLScanner/internal/types"
)

type Mode int

const (
	ModeStream Mode = iota
	ModeBatch
)

type Config struct {
	ScanWorkers   int
	DetectWorkers int
	Mode          Mode
	ScanConfig    scanner.ScanConfig
	OnScan        func()
	PassAll       bool // send all TLS-connected results, not just feasible
}

type Stats struct {
	Attempted int64
	TLSFailed int64
	Dropped   int64
}

type Pipeline struct {
	cfg       Config
	geo       *geo.Geo
	runner    *detector.Runner
	attempted atomic.Int64
	tlsFailed atomic.Int64
	dropped   atomic.Int64
}

func New(cfg Config, g *geo.Geo, runner *detector.Runner) *Pipeline {
	if cfg.ScanWorkers <= 0 {
		cfg.ScanWorkers = 2
	}
	if cfg.DetectWorkers <= 0 {
		cfg.DetectWorkers = 2
	}
	return &Pipeline{cfg: cfg, geo: g, runner: runner}
}

// Stats returns counters snapshotted at call time; safe to call any time.
func (p *Pipeline) Stats() Stats {
	return Stats{
		Attempted: p.attempted.Load(),
		TLSFailed: p.tlsFailed.Load(),
		Dropped:   p.dropped.Load(),
	}
}

func (p *Pipeline) Run(ctx context.Context, hosts <-chan types.Host) (<-chan *types.ScanResult, error) {
	scanResultCh := make(chan *types.ScanResult, 128)

	var scanWg sync.WaitGroup
	scanWg.Add(p.cfg.ScanWorkers)
	for i := 0; i < p.cfg.ScanWorkers; i++ {
		go func() {
			defer scanWg.Done()
			for host := range hosts {
				select {
				case <-ctx.Done():
					return
				default:
				}
				p.attempted.Add(1)
				result := scanner.ScanTLS(ctx, host, p.cfg.ScanConfig, p.geo)
				if p.cfg.OnScan != nil {
					p.cfg.OnScan()
				}
				if result.TLS == nil {
					p.tlsFailed.Add(1)
				}
				if result.Feasible || (p.cfg.PassAll && result.TLS != nil) {
					select {
					case scanResultCh <- result:
					case <-ctx.Done():
						return
					}
				} else {
					p.dropped.Add(1)
				}
			}
		}()
	}
	go func() {
		scanWg.Wait()
		close(scanResultCh)
	}()

	var outputCh <-chan *types.ScanResult
	if p.runner != nil && p.cfg.Mode == ModeStream {
		outputCh = p.runner.Run(ctx, scanResultCh)
	} else if p.runner != nil && p.cfg.Mode == ModeBatch {
		outputCh = p.runBatch(ctx, scanResultCh)
	} else {
		outputCh = scanResultCh
	}

	return outputCh, nil
}

func (p *Pipeline) runBatch(ctx context.Context, in <-chan *types.ScanResult) <-chan *types.ScanResult {
	out := make(chan *types.ScanResult, 64)
	go func() {
		defer close(out)
		var batch []*types.ScanResult
		for r := range in {
			batch = append(batch, r)
		}
		slog.Info("Batch mode: scan complete, starting detection", "count", len(batch))
		batchCh := make(chan *types.ScanResult, len(batch))
		for _, r := range batch {
			batchCh <- r
		}
		close(batchCh)
		detected := p.runner.Run(ctx, batchCh)
		for r := range detected {
			select {
			case out <- r:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out
}
