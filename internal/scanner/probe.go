package scanner

import (
	"context"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

// Stage-1 liveness probe defaults. Tuned for sweeping a freshly-expanded BGP
// prefix: weed out dead / firewalled IPs with a cheap TCP connect before the
// expensive full TLS scan, which would otherwise burn the full -timeout on
// every silent host. High concurrency + short timeout keep the pre-pass fast.
const (
	defaultProbeConcurrency = 256
	defaultProbeTimeout     = 2 * time.Second
)

// ProbeConfig configures the concurrent liveness filter. Zero fields fall back
// to the stage-1 defaults; Port falls back to 443.
type ProbeConfig struct {
	Port        int
	Timeout     time.Duration
	Concurrency int
	EnableIPv6  bool
	// OnProbe fires once per host after its probe resolves. It is called
	// concurrently from many workers, so it must be threadsafe (LiveLog.Push
	// and atomics qualify).
	OnProbe func(host types.Host, alive bool)
}

// ProbeLive reports whether ip:port accepts a TCP connection within timeout. It
// performs no TLS handshake — this is the cheap stage-1 check that only proves
// something is listening. A successful connection is closed immediately.
func ProbeLive(ctx context.Context, ip net.IP, port int, timeout time.Duration) bool {
	if ip == nil {
		return false
	}
	if timeout <= 0 {
		timeout = defaultProbeTimeout
	}
	hostPort := net.JoinHostPort(ip.String(), strconv.Itoa(port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

// FilterLive consumes hosts, TCP-probes each on cfg.Port concurrently, and
// emits only those that answer. Domain hosts (no pre-resolved IP) are resolved
// via DNS first. The output channel closes when the input drains or ctx is
// cancelled; on cancellation, in-flight hosts are simply dropped.
func FilterLive(ctx context.Context, in <-chan types.Host, cfg ProbeConfig) <-chan types.Host {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = defaultProbeConcurrency
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultProbeTimeout
	}
	if cfg.Port <= 0 {
		cfg.Port = 443
	}

	out := make(chan types.Host, cfg.Concurrency)
	var wg sync.WaitGroup
	wg.Add(cfg.Concurrency)
	for i := 0; i < cfg.Concurrency; i++ {
		go func() {
			defer wg.Done()
			for host := range in {
				select {
				case <-ctx.Done():
					return
				default:
				}
				ip := host.IP
				if ip == nil {
					if resolved, err := LookupIP(host.Origin, cfg.EnableIPv6); err == nil {
						ip = resolved
					}
				}
				alive := ProbeLive(ctx, ip, cfg.Port, cfg.Timeout)
				if cfg.OnProbe != nil {
					cfg.OnProbe(host, alive)
				}
				if alive {
					// Carry the resolved IP forward so stage 2 need not re-resolve.
					host.IP = ip
					select {
					case out <- host:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		wg.Wait()
		close(out)
	}()
	return out
}

// CountLiveProgress is a small threadsafe helper for callers that want running
// (probed, live) totals to render a "N/M live" progress line from within a
// concurrent OnProbe callback.
type CountLiveProgress struct {
	probed atomic.Int64
	live   atomic.Int64
}

// Record updates the counters for one probe outcome and returns the running
// (probed, live) totals. Safe for concurrent use.
func (c *CountLiveProgress) Record(alive bool) (probed, live int64) {
	probed = c.probed.Add(1)
	if alive {
		live = c.live.Add(1)
	} else {
		live = c.live.Load()
	}
	return probed, live
}

// Totals returns the final (probed, live) counts; call after probing finishes.
func (c *CountLiveProgress) Totals() (probed, live int64) {
	return c.probed.Load(), c.live.Load()
}
