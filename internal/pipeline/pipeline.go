package pipeline

import (
	"context"
	"log/slog"
	"sync"

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
	OnScan        func() // called for every scan attempt
}

type Pipeline struct {
	cfg       Config
	geo       *geo.Geo
	runner    *detector.Runner
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

func (p *Pipeline) Run(ctx context.Context, hosts <-chan types.Host) (<-chan *types.ScanResult, error) {
	ctx, cancel := context.WithCancel(ctx)

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
				result := scanner.ScanTLS(ctx, host, p.cfg.ScanConfig, p.geo)
				if p.cfg.OnScan != nil {
					p.cfg.OnScan()
				}
				if result.Feasible {
					scanResultCh <- result
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

	go func() {
		<-ctx.Done()
		cancel()
	}()
	_ = cancel

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
			out <- r
		}
	}()
	return out
}
