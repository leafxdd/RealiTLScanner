package scanner

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

// listenLoopback opens a TCP listener on 127.0.0.1 and returns its port plus a
// cleanup func. The backlog completes handshakes without an Accept loop, so a
// plain TCP connect probe succeeds.
func listenLoopback(t *testing.T) (port int, cleanup func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return ln.Addr().(*net.TCPAddr).Port, func() { ln.Close() }
}

func TestProbeLive_LiveListener(t *testing.T) {
	port, cleanup := listenLoopback(t)
	defer cleanup()
	if !ProbeLive(context.Background(), net.ParseIP("127.0.0.1"), port, time.Second) {
		t.Error("expected live for a bound loopback port")
	}
}

func TestProbeLive_RefusedPort(t *testing.T) {
	// Open then close → that port has nothing listening → connect is refused
	// immediately on loopback (RST, not a timeout wait).
	port, cleanup := listenLoopback(t)
	cleanup()
	if ProbeLive(context.Background(), net.ParseIP("127.0.0.1"), port, time.Second) {
		t.Error("expected not-live for a closed loopback port")
	}
}

func TestProbeLive_NilIP(t *testing.T) {
	if ProbeLive(context.Background(), nil, 443, time.Second) {
		t.Error("nil IP must not be live")
	}
}

func TestProbeLive_ContextCancelled(t *testing.T) {
	port, cleanup := listenLoopback(t)
	defer cleanup()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if ProbeLive(ctx, net.ParseIP("127.0.0.1"), port, time.Second) {
		t.Error("cancelled context must short-circuit to not-live")
	}
}

func TestFilterLive_EmitsOnlyLive(t *testing.T) {
	port, cleanup := listenLoopback(t)
	defer cleanup()

	in := make(chan types.Host, 5)
	// 3 live (bound loopback), 2 dead (loopback IP with nothing listening → refused).
	for i := 0; i < 3; i++ {
		in <- types.Host{IP: net.ParseIP("127.0.0.1"), Origin: "live", Type: types.HostTypeIP}
	}
	for i := 0; i < 2; i++ {
		in <- types.Host{IP: net.ParseIP("127.9.9.9"), Origin: "dead", Type: types.HostTypeIP}
	}
	close(in)

	var counts CountLiveProgress
	cfg := ProbeConfig{
		Port:        port,
		Timeout:     time.Second,
		Concurrency: 4,
		OnProbe:     func(_ types.Host, alive bool) { counts.Record(alive) },
	}

	var got []types.Host
	for h := range FilterLive(context.Background(), in, cfg) {
		got = append(got, h)
	}
	if len(got) != 3 {
		t.Errorf("emitted %d live hosts, want 3", len(got))
	}
	for _, h := range got {
		if h.Origin != "live" {
			t.Errorf("emitted a non-live host: %+v", h)
		}
	}
	probed, live := counts.Totals()
	if probed != 5 || live != 3 {
		t.Errorf("counts: probed=%d live=%d, want 5/3", probed, live)
	}
}

func TestFilterLive_AllDeadClosesCleanly(t *testing.T) {
	in := make(chan types.Host, 2)
	in <- types.Host{IP: net.ParseIP("127.9.9.9"), Type: types.HostTypeIP}
	in <- types.Host{IP: net.ParseIP("127.9.9.10"), Type: types.HostTypeIP}
	close(in)

	cfg := ProbeConfig{Port: 1, Timeout: time.Second, Concurrency: 2}
	n := 0
	for range FilterLive(context.Background(), in, cfg) {
		n++
	}
	if n != 0 {
		t.Errorf("expected no live hosts, got %d", n)
	}
}

func TestCountLiveProgress(t *testing.T) {
	var c CountLiveProgress
	if p, l := c.Record(true); p != 1 || l != 1 {
		t.Errorf("after first live: probed=%d live=%d, want 1/1", p, l)
	}
	if p, l := c.Record(false); p != 2 || l != 1 {
		t.Errorf("after a dead: probed=%d live=%d, want 2/1", p, l)
	}
	if p, l := c.Record(true); p != 3 || l != 2 {
		t.Errorf("after second live: probed=%d live=%d, want 3/2", p, l)
	}
	if p, l := c.Totals(); p != 3 || l != 2 {
		t.Errorf("Totals: probed=%d live=%d, want 3/2", p, l)
	}
}
