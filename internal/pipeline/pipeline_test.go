package pipeline

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/detector"
	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/scanner"
	"github.com/xtls/RealiTLScanner/internal/types"
)

func TestPipeline_Stream(t *testing.T) {
	cfg := Config{
		ScanWorkers:   1,
		DetectWorkers: 1,
		Mode:          ModeStream,
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
