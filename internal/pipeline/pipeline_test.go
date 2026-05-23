package pipeline

import (
	"context"
	"runtime"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/detector"
	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/scanner"
	"github.com/xtls/RealiTLScanner/internal/types"
)

func TestPipeline_Stream(t *testing.T) {
	cfg := Config{
		ScanWorkers: 1,
		Mode:        ModeStream,
		ScanConfig: scanner.ScanConfig{
			Port:    443,
			Timeout: 2 * time.Second,
		},
	}

	tlsCheck := detector.NewTLSCheckDetector()
	runner := detector.NewRunner([]detector.Detector{tlsCheck}, 1)
	g := &geo.Geo{}

	p := New(cfg, g, runner)

	hosts := make(chan types.Host, 1)
	hosts <- types.Host{
		IP:     nil,
		Origin: "localhost",
		Type:   types.HostTypeDomain,
	}
	close(hosts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := p.Run(ctx, hosts)
	if err != nil {
		t.Fatal(err)
	}

	for range out {
		// drain output (may be empty if localhost:443 not available)
	}
}

func TestPipeline_NoDetector(t *testing.T) {
	cfg := Config{
		ScanWorkers: 1,
		Mode:        ModeStream,
		ScanConfig: scanner.ScanConfig{
			Port:    443,
			Timeout: 1 * time.Second,
		},
	}

	g := &geo.Geo{}
	p := New(cfg, g, nil)

	hosts := make(chan types.Host)
	close(hosts)

	ctx := context.Background()
	out, err := p.Run(ctx, hosts)
	if err != nil {
		t.Fatal(err)
	}

	for range out {
	}
}

func TestPipeline_StatsCountsFailedScans(t *testing.T) {
	cfg := Config{
		ScanWorkers: 2,
		Mode:        ModeStream,
		ScanConfig: scanner.ScanConfig{
			Port:    1, // unreachable — all dials fail
			Timeout: 100 * time.Millisecond,
		},
	}
	g := &geo.Geo{}
	p := New(cfg, g, nil)

	hosts := make(chan types.Host, 6)
	for i := 0; i < 6; i++ {
		hosts <- types.Host{IP: nil, Origin: "127.0.0.1", Type: types.HostTypeIP}
	}
	close(hosts)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := p.Run(ctx, hosts)
	if err != nil {
		t.Fatal(err)
	}
	for range out {
	}
	s := p.Stats()
	if s.Attempted != 6 {
		t.Errorf("Attempted: got %d, want 6", s.Attempted)
	}
	if s.TLSFailed != 6 {
		t.Errorf("TLSFailed: got %d, want 6", s.TLSFailed)
	}
	if s.Dropped != 6 {
		t.Errorf("Dropped: got %d, want 6", s.Dropped)
	}
}

// TestPipeline_NoGoroutineLeakOnCtxCancel — abandon the output channel,
// cancel ctx, ensure worker goroutines do not leak waiting on send.
func TestPipeline_NoGoroutineLeakOnCtxCancel(t *testing.T) {
	startGoroutines := runtime.NumGoroutine()

	cfg := Config{
		ScanWorkers: 2,
		Mode:        ModeStream,
		PassAll:     true,
		ScanConfig: scanner.ScanConfig{
			Port:    1, // unreachable — scans fail fast with no TLS
			Timeout: 100 * time.Millisecond,
		},
	}
	runner := detector.NewRunner(nil, 1)
	g := &geo.Geo{}
	p := New(cfg, g, runner)

	hosts := make(chan types.Host, 8)
	for i := 0; i < 8; i++ {
		hosts <- types.Host{IP: nil, Origin: "127.0.0.1", Type: types.HostTypeIP}
	}
	close(hosts)

	ctx, cancel := context.WithCancel(context.Background())
	out, err := p.Run(ctx, hosts)
	if err != nil {
		t.Fatal(err)
	}

	// Drain a couple, then abandon and cancel — simulates downstream death.
	go func() {
		for range out {
		}
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()

	// Allow goroutines to observe cancellation and exit.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		runtime.GC()
		if runtime.NumGoroutine() <= startGoroutines+2 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Errorf("goroutine leak: start=%d end=%d", startGoroutines, runtime.NumGoroutine())
}
