package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"time"

	"github.com/xtls/RealiTLScanner/internal/data"
	"github.com/xtls/RealiTLScanner/internal/detector"
	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/output"
	"github.com/xtls/RealiTLScanner/internal/pipeline"
	"github.com/xtls/RealiTLScanner/internal/scanner"
	"github.com/xtls/RealiTLScanner/internal/types"
)

var version = "2.0.0-dev"

func main() {
	if len(os.Args) > 1 && !strings.HasPrefix(os.Args[1], "-") {
		os.Exit(routeSubcommand(os.Args[1], os.Args[2:]))
	}
	runLegacy(os.Args[1:])
}

func routeSubcommand(cmd string, args []string) int {
	switch cmd {
	case "scan":
		runScan(args)
		return 0
	case "check":
		return runCheck(args)
	case "version":
		printVersion()
		return 0
	default:
		runLegacy(os.Args[1:])
		return 0
	}
}

func runLegacy(args []string) {
	args, bgpPeek := extractHiddenFlag(args, "-bgp-peek")
	fs := flag.NewFlagSet("realitlscanner", flag.ExitOnError)
	var (
		addr         string
		in           string
		port         int
		thread       int
		out          string
		timeout      int
		verbose      bool
		enableIPv6   bool
		url          string
		skipDownload bool
		infinite     bool
		bgp          bool
		maxHosts     int
		yes          bool
		probeFirst   bool
	)

	fs.StringVar(&addr, "addr", "", "Specify an IP, IP CIDR or domain to scan")
	fs.StringVar(&in, "in", "", "Specify a file with IPs/CIDRs/domains")
	fs.IntVar(&port, "port", 443, "HTTPS port to check")
	fs.IntVar(&thread, "thread", 2, "Concurrent tasks")
	fs.StringVar(&out, "out", "out.csv", "Output file")
	fs.IntVar(&timeout, "timeout", 10, "Timeout per check (seconds)")
	fs.BoolVar(&verbose, "v", false, "Verbose output")
	fs.BoolVar(&enableIPv6, "46", false, "Enable IPv6")
	fs.StringVar(&url, "url", "", "Crawl domain list from URL")
	fs.BoolVar(&skipDownload, "skip-download", false, "Continue even if data file download fails")
	fs.BoolVar(&infinite, "infinite", false, "When -addr is a single IP/domain, continuously scan neighbour IPs (default: single host)")
	fs.BoolVar(&bgp, "bgp", false, "Expand -addr <ip> to its best covering BGP prefix (smart /20-/24 selection) and scan it")
	fs.IntVar(&maxHosts, "max-hosts", 4096, "For an over-broad (< /19) BGP prefix, refuse if bgp.tools shows more than N active neighbours (override with -yes)")
	fs.BoolVar(&yes, "yes", false, "Force scanning past the -bgp broad-prefix active-neighbour cap")
	fs.BoolVar(&probeFirst, "probe-first", false, "Two-phase scan: cheap TCP liveness pre-filter before the full TLS scan (auto-on with -bgp)")
	_ = fs.Parse(args)

	setupLogging(verbose)
	clearProxy()

	if bgp {
		probeFirst = true // a fresh BGP prefix is mostly dead space — pre-filter pays off
	}

	if !scanner.ExistOnlyOne([]string{addr, in, url}) {
		slog.Error("Specify exactly one of: -addr, -in, -url")
		fs.PrintDefaults()
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	maybeBGPPeek(ctx, addr, bgpPeek, enableIPv6)

	hostChan := resolveHosts(ctx, addr, in, url, enableIPv6, infinite, bgp, maxHosts, yes)
	if hostChan == nil {
		return
	}
	if probeFirst {
		liveHosts := liveFilterBarrier(ctx, hostChan, port, enableIPv6)
		if len(liveHosts) == 0 {
			slog.Info("No live hosts after liveness pre-filter")
			return
		}
		hostChan = hostsToChannel(liveHosts)
	}

	dm := data.NewDataManager(".")
	dlCtx := context.Background()
	if err := dm.EnsureReady(dlCtx, "geoip"); err != nil {
		if skipDownload {
			slog.Warn("GeoIP download failed, geo lookup disabled", "err", err)
		} else {
			slog.Error("GeoIP download failed (use -skip-download to continue anyway)", "err", err)
			return
		}
	}

	outWriter, outCloser, err := openOutput(out)
	if err != nil {
		slog.Error("Cannot open output file", "path", out, "err", err)
		return
	}
	if outCloser != nil {
		defer func() {
			if cerr := outCloser.Close(); cerr != nil {
				slog.Error("Error closing output file", "path", out, "err", cerr)
			}
		}()
	}

	w := output.NewCSVWriter(outWriter, output.Options{})
	if err := w.WriteHeader(); err != nil {
		slog.Error("Error writing header", "err", err)
		return
	}

	geoPath, _ := dm.GetPath("geoip")
	geoReader := geo.NewGeo(geoPath)
	defer geoReader.Close()

	cfg := scanner.ScanConfig{
		Port:       port,
		Timeout:    time.Duration(timeout) * time.Second,
		EnableIPv6: enableIPv6,
	}

	var (
		scanCount atomic.Int64
		startedAt = time.Now()
		live      = output.NewLiveLog(os.Stderr, 7)
	)
	defer live.Close()

	pipeCfg := pipeline.Config{
		ScanWorkers: thread,
		Mode:        pipeline.ModeStream,
		ScanConfig:  cfg,
		OnScan: func() {
			n := scanCount.Add(1)
			// Non-TTY fallback: log scan progress periodically so log redirection
			// still sees something happen during long sweeps. On a TTY the LiveLog
			// already renders activity, so the periodic line would be noise.
			if !live.Enabled() && n%50 == 0 {
				slog.Info("Scanning progress",
					"scanned", n,
					"elapsed", time.Since(startedAt).Round(time.Second).String())
			}
		},
		OnResult: func(r *types.ScanResult) {
			live.Push(formatScanLine(r, scanCount.Load(), startedAt))
		},
	}

	p := pipeline.New(pipeCfg, geoReader, nil)

	outCh, err := p.Run(ctx, hostChan)
	if err != nil {
		slog.Error("Pipeline failed", "err", err)
		return
	}

	slog.Info("Started scanning")
	for result := range outCh {
		if err := w.WriteResult(result); err != nil {
			slog.Error("Error writing result", "err", err)
		}
	}
	if err := w.Close(); err != nil {
		slog.Error("Error closing writer", "err", err)
	}
	live.Close()
	stats := p.Stats()
	slog.Info("Completed",
		"elapsed", time.Since(startedAt).Round(time.Second).String(),
		"attempted", stats.Attempted,
		"tls_failed", stats.TLSFailed,
		"dropped", stats.Dropped)
}

// formatScanLine renders a single per-scan event for the rolling LiveLog.
func formatScanLine(r *types.ScanResult, total int64, startedAt time.Time) string {
	target := r.Host.Origin
	if r.IP != nil {
		target = r.IP.String()
	}
	elapsed := time.Since(startedAt).Round(time.Second)
	if r.TLS != nil {
		alpn := r.TLS.ALPN
		if alpn == "" {
			alpn = "-"
		}
		mark := "✓"
		if !r.Feasible {
			mark = "·"
		}
		return fmt.Sprintf("[%6d %s] %s %s  %s  TLS=0x%04x ALPN=%s  cert=%s",
			total, elapsed, mark, target,
			r.TLS.HandshakeTime.Round(time.Millisecond),
			r.TLS.Version, alpn, r.TLS.CertDomain)
	}
	reason := r.Error
	if reason == "" {
		reason = "unknown"
	}
	return fmt.Sprintf("[%6d %s] ✗ %s  %s", total, elapsed, target, reason)
}

func runScan(args []string) {
	args, bgpPeek := extractHiddenFlag(args, "-bgp-peek")
	// Pre-sort: move non-flag arguments (domains) to the end so flag.Parse works correctly
	args = reorderArgs(args)

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var (
		addr         string
		in           string
		csvFile      string
		port         int
		thread       int
		out          string
		timeout      int
		verbose      bool
		enableIPv6   bool
		url          string
		skipDownload bool
		infinite     bool
		bgp          bool
		maxHosts     int
		yes          bool
		probeFirst   bool
	)

	fs.StringVar(&addr, "addr", "", "IP, CIDR or domain to scan")
	fs.StringVar(&in, "in", "", "File with IPs/CIDRs/domains")
	fs.StringVar(&csvFile, "csv", "", "CSV file from previous scan (reads CERT_DOMAIN column)")
	fs.IntVar(&port, "port", 443, "HTTPS port")
	fs.IntVar(&thread, "thread", 2, "Concurrent tasks")
	fs.StringVar(&out, "out", "", "Also output to file")
	fs.IntVar(&timeout, "timeout", 10, "Timeout (seconds)")
	fs.BoolVar(&verbose, "v", false, "Verbose output")
	fs.BoolVar(&enableIPv6, "46", false, "Enable IPv6")
	fs.StringVar(&url, "url", "", "Crawl domain list from URL")
	fs.BoolVar(&skipDownload, "skip-download", false, "Continue even if data file download fails")
	fs.BoolVar(&infinite, "infinite", false, "When -addr is a single IP/domain, continuously scan neighbour IPs (default: single host)")
	fs.BoolVar(&bgp, "bgp", false, "Expand -addr <ip> to its best covering BGP prefix (smart /20-/24 selection) and scan it")
	fs.IntVar(&maxHosts, "max-hosts", 4096, "For an over-broad (< /19) BGP prefix, refuse if bgp.tools shows more than N active neighbours (override with -yes)")
	fs.BoolVar(&yes, "yes", false, "Force scanning past the -bgp broad-prefix active-neighbour cap")
	fs.BoolVar(&probeFirst, "probe-first", false, "Two-phase scan: cheap TCP liveness pre-filter before the full TLS scan (auto-on with -bgp)")
	_ = fs.Parse(args)

	setupLogging(verbose)
	clearProxy()

	if bgp {
		probeFirst = true // a fresh BGP prefix is mostly dead space — pre-filter pays off
	}

	// Determine input source: -csv, -addr/-in/-url, or positional domain args
	directDomains := fs.Args()
	hasAddrInput := addr != "" || in != "" || url != ""

	if csvFile == "" && !hasAddrInput && len(directDomains) == 0 {
		slog.Error("Specify input: -csv <file>, -addr/-in/-url, or domain names")
		fs.PrintDefaults()
		return
	}

	// Download data files before initializing detectors
	dm := data.NewDataManager(".")
	ctx := context.Background()
	if err := dm.EnsureReady(ctx, "gfwlist", "geoip"); err != nil {
		if skipDownload {
			slog.Warn("Data file download failed, continuing with limited detection", "err", err)
		} else {
			slog.Error("Data file download failed (use -skip-download to continue anyway)", "err", err)
			return
		}
	}

	geoPath, _ := dm.GetPath("geoip")
	geoReader := geo.NewGeo(geoPath)
	defer geoReader.Close()

	dets := buildDetectors(dm, geoReader, "all")
	runner := detector.NewRunner(dets, thread)
	slog.Info("Detectors enabled", "available", runner.AvailableDetectors())

	// Setup table output
	var fileW io.Writer
	if out != "" {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
		if err != nil {
			slog.Error("Cannot open output file", "path", out, "err", err)
		} else {
			defer f.Close()
			fileW = f
		}
	}
	table := output.NewTableWriter(os.Stdout, fileW)

	cfg := scanner.ScanConfig{
		Port:       port,
		Timeout:    time.Duration(timeout) * time.Second,
		EnableIPv6: enableIPv6,
	}

	var hostChan <-chan types.Host
	var domainCount int

	switch {
	case csvFile != "":
		ch, count, err := scanner.ReadCSVDomains(csvFile)
		if err != nil {
			slog.Error("Cannot read CSV file", "path", csvFile, "err", err)
			return
		}
		hostChan = ch
		domainCount = count
		fmt.Fprintf(os.Stderr, "[%s] 从CSV文件提取到 %d 个域名\n", time.Now().Format("15:04:05"), count)

	case len(directDomains) > 0:
		ch, count := scanner.DomainsToChannel(directDomains)
		hostChan = ch
		domainCount = count
		fmt.Fprintf(os.Stderr, "[%s] 直接指定 %d 个域名\n", time.Now().Format("15:04:05"), count)

	default:
		// -addr/-in/-url: scan IP range, then detect on results directly
		if !scanner.ExistOnlyOne([]string{addr, in, url}) {
			slog.Error("Specify exactly one of: -addr, -in, -url")
			fs.PrintDefaults()
			return
		}
		maybeBGPPeek(ctx, addr, bgpPeek, enableIPv6)
		rawHosts := resolveHosts(ctx, addr, in, url, enableIPv6, infinite, bgp, maxHosts, yes)
		if rawHosts == nil {
			return
		}
		if probeFirst {
			// Stage 1: cheap TCP liveness pre-filter under its own signal
			// context so a Ctrl+C here stops probing and proceeds to scan the
			// hosts found so far, without cancelling the later scan phase.
			probeCtx, probeCancel := signal.NotifyContext(ctx, os.Interrupt)
			liveHosts := liveFilterBarrier(probeCtx, rawHosts, port, enableIPv6)
			probeCancel()
			if len(liveHosts) == 0 {
				fmt.Fprintf(os.Stderr, "[%s] 探活后无存活主机\n", time.Now().Format("15:04:05"))
				return
			}
			rawHosts = hostsToChannel(liveHosts)
		}
		fmt.Fprintf(os.Stderr, "[%s] 开始扫描IP段... (Ctrl+C 中断扫描并开始检测)\n", time.Now().Format("15:04:05"))

		// Scan phase uses its own context so Ctrl+C stops scanning but allows detection to proceed
		scanCtx, scanCancel := signal.NotifyContext(ctx, os.Interrupt)

		var (
			scanCount atomic.Int64
			scanStart = time.Now()
			live      = output.NewLiveLog(os.Stderr, 7)
		)
		defer live.Close()

		scanPipeCfg := pipeline.Config{
			ScanWorkers: thread,
			Mode:        pipeline.ModeStream,
			ScanConfig:  cfg,
			PassAll:     true,
			OnScan: func() {
				n := scanCount.Add(1)
				if !live.Enabled() && n%50 == 0 {
					slog.Info("Scanning progress",
						"scanned", n,
						"elapsed", time.Since(scanStart).Round(time.Second).String())
				}
			},
			OnResult: func(r *types.ScanResult) {
				live.Push(formatScanLine(r, scanCount.Load(), scanStart))
			},
		}
		sp := pipeline.New(scanPipeCfg, geoReader, nil)
		scanCh, err := sp.Run(scanCtx, rawHosts)
		if err != nil {
			scanCancel()
			slog.Error("Scan pipeline failed", "err", err)
			return
		}
		var scanResults []*types.ScanResult
		seen := make(map[string]bool)
		interrupted := false
	scanLoop:
		for {
			select {
			case <-scanCtx.Done():
				interrupted = true
				break scanLoop
			case result, ok := <-scanCh:
				if !ok {
					break scanLoop
				}
				if result.TLS != nil && result.TLS.CertDomain != "" {
					d := result.TLS.CertDomain
					if !seen[d] && scanner.IsValidDomain(d) {
						seen[d] = true
						scanResults = append(scanResults, result)
					}
				}
			}
		}
		scanCancel()
		// Park the LiveLog cursor below the rolling window before any further
		// stderr writes (扫描中断 / 开始检测 / table.WriteHeader) so they don't
		// land inside the region and corrupt the rendered frame.
		live.Close()

		if len(scanResults) == 0 {
			fmt.Fprintf(os.Stderr, "[%s] 未发现可用域名\n", time.Now().Format("15:04:05"))
			return
		}
		if interrupted {
			fmt.Fprintf(os.Stderr, "\n[%s] 扫描中断, 使用已收集的 %d 个域名继续检测...\n", time.Now().Format("15:04:05"), len(scanResults))
		} else {
			fmt.Fprintf(os.Stderr, "[%s] 扫描完成, 发现 %d 个域名, 开始检测...\n", time.Now().Format("15:04:05"), len(scanResults))
		}

		// Detection phase: fresh context so second Ctrl+C aborts detection
		detectCtx, detectCancel := signal.NotifyContext(context.Background(), os.Interrupt)
		defer detectCancel()

		table.SetTotal(len(scanResults))
		fmt.Fprintf(os.Stderr, "[%s] 开始检测...\n", time.Now().Format("15:04:05"))
		table.WriteHeader()

		resultCh := make(chan *types.ScanResult, len(scanResults))
		for _, r := range scanResults {
			resultCh <- r
		}
		close(resultCh)

		t := time.Now()
		detectedCh := runner.Run(detectCtx, resultCh)
		suitable := 0
		unsuitable := 0
		for result := range detectedCh {
			table.WriteResult(result)
			if result.Feasible {
				suitable++
			} else {
				unsuitable++
			}
		}
		sps := sp.Stats()
		table.WriteSummaryWithStats(suitable, unsuitable, time.Since(t), output.SummaryStats{
			Attempted: sps.Attempted,
			TLSFailed: sps.TLSFailed,
			Dropped:   sps.Dropped,
		})
		return
	}

	// Detection phase
	table.SetTotal(domainCount)
	fmt.Fprintf(os.Stderr, "[%s] 开始检测...\n", time.Now().Format("15:04:05"))

	pipeCtx, pipeCancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer pipeCancel()

	pipeCfg := pipeline.Config{
		ScanWorkers: thread,
		Mode:        pipeline.ModeStream,
		ScanConfig:  cfg,
		PassAll:     true,
	}
	p := pipeline.New(pipeCfg, geoReader, runner)
	outCh, err := p.Run(pipeCtx, hostChan)
	if err != nil {
		slog.Error("Detection pipeline failed", "err", err)
		return
	}

	t := time.Now()
	table.WriteHeader()
	suitable := 0
	unsuitable := 0
	for result := range outCh {
		table.WriteResult(result)
		if result.Feasible {
			suitable++
		} else {
			unsuitable++
		}
	}
	pStats := p.Stats()
	table.WriteSummaryWithStats(suitable, unsuitable, time.Since(t), output.SummaryStats{
		Attempted: pStats.Attempted,
		TLSFailed: pStats.TLSFailed,
		Dropped:   pStats.Dropped,
	})
}

func buildDetectors(dm *data.DataManager, geoReader *geo.Geo, filter string) []detector.Detector {
	cdnPath, _ := dm.GetPath("cdn_keywords")
	hotPath, _ := dm.GetPath("hot_websites")
	gfwPath, _ := dm.GetPath("gfwlist")
	blockPath, _ := dm.GetPath("blocklist")

	dets := []detector.Detector{
		detector.NewTLSCheckDetector(),
		detector.NewCDNDetector(cdnPath),
		detector.NewGFWDetector(gfwPath),
		detector.NewHotSiteDetector(hotPath),
		detector.NewBlocklistDetector(blockPath),
		detector.NewLocationDetector(geoReader),
		detector.NewRedirectDetector(5 * time.Second),
		detector.NewStatusDetector(5 * time.Second),
	}

	if filter == "all" {
		return dets
	}

	enabled := make(map[string]bool)
	for _, name := range strings.Split(filter, ",") {
		enabled[strings.TrimSpace(name)] = true
	}

	var filtered []detector.Detector
	for _, d := range dets {
		if enabled[d.Name()] {
			filtered = append(filtered, d)
		}
	}
	return filtered
}

func resolveHosts(ctx context.Context, addr, in, url string, enableIPv6, infinite, bgp bool, maxHosts int, yes bool) <-chan types.Host {
	if bgp && addr == "" {
		slog.Warn("-bgp only applies to -addr; ignoring")
	}
	if addr != "" {
		if bgp {
			prefix, ok := resolveBGPPrefix(ctx, addr, enableIPv6, maxHosts, yes)
			if !ok {
				return nil
			}
			return scanner.IterateCtx(ctx, strings.NewReader(prefix.String()), enableIPv6)
		}
		return scanner.IterateAddrInfiniteCtx(ctx, addr, enableIPv6, infinite)
	}
	if in != "" {
		ch, err := scanner.IterateFileCtx(ctx, in, enableIPv6)
		if err != nil {
			slog.Error("Error reading file", "path", in, "err", err)
			return nil
		}
		return ch
	}
	if url != "" {
		slog.Info("Fetching url...")
		domains, err := fetchURLDomains(ctx, url, urlFetchTimeout, urlMaxBytes)
		if err != nil {
			slog.Error("Error fetching url", "err", err)
			return nil
		}
		slog.Info("Parsed domains", "count", len(domains))
		return scanner.IterateCtx(ctx, strings.NewReader(strings.Join(domains, "\n")), enableIPv6)
	}
	return nil
}

// resolveBGPPrefix runs smart prefix selection for -bgp: it picks the best
// covering prefix for addr, logs the candidate set, and applies the broad-
// prefix safety gate. When the chosen prefix is broader than /19 — only reached
// if the IP announces nothing tighter — it peeks bgp.tools for the active-
// neighbour count and refuses if it exceeds maxHosts, unless -yes forces it
// through. Returns the prefix to scan and whether scanning may proceed.
func resolveBGPPrefix(ctx context.Context, addr string, enableIPv6 bool, maxHosts int, yes bool) (netip.Prefix, bool) {
	prefix, candidates, err := scanner.SelectAddrPrefix(ctx, addr, enableIPv6)
	if err != nil {
		slog.Error("BGP prefix selection failed", "addr", addr, "err", err)
		return netip.Prefix{}, false
	}
	slog.Info("Selected BGP prefix",
		"ip", addr, "prefix", prefix.String(), "hosts", scanner.PrefixAddrCount(prefix),
		"candidates", formatCandidates(candidates))

	if scanner.PrefixTooBroad(prefix) {
		res, perr := scanner.PeekPrefix(ctx, prefix)
		switch {
		case perr != nil && yes:
			slog.Warn("Broad BGP prefix (< /19): active-count check failed, forcing due to -yes",
				"prefix", prefix.String(), "err", perr)
		case perr != nil:
			slog.Error("Broad BGP prefix (< /19) and its active-neighbour count could not be verified; re-run with -yes to scan anyway",
				"prefix", prefix.String(), "err", perr)
			return netip.Prefix{}, false
		case !scanner.WithinHostCap(res.Active, maxHosts, yes):
			slog.Error("Broad BGP prefix has too many active neighbours; re-run with -yes to scan anyway",
				"prefix", prefix.String(), "active", res.Active, "max-hosts", maxHosts)
			return netip.Prefix{}, false
		default:
			slog.Info("Broad BGP prefix within active-neighbour cap",
				"prefix", prefix.String(), "active", res.Active, "max-hosts", maxHosts)
		}
	}
	return prefix, true
}

// formatCandidates renders the smart-selection candidate set for logging,
// tagging each prefix with the RIPEstat visibility that informed the ranking.
func formatCandidates(cands []scanner.PrefixCandidate) string {
	parts := make([]string, len(cands))
	for i, c := range cands {
		if c.PeersTotal > 0 {
			parts[i] = fmt.Sprintf("%s(vis=%d%%)", c.Prefix, int(c.Visibility*100+0.5))
		} else {
			parts[i] = c.Prefix.String()
		}
	}
	return strings.Join(parts, " ")
}

// liveFilterBarrier runs the stage-1 TCP liveness probe over in, rendering a
// rolling "探活 N/M" progress window, and returns the live hosts. It is a
// barrier: it fully drains the probe before returning, so the stage-1 LiveLog
// is closed before stage 2 writes to stderr (two live regions writing at once
// would corrupt each other's frames).
func liveFilterBarrier(ctx context.Context, in <-chan types.Host, port int, enableIPv6 bool) []types.Host {
	probeLog := output.NewLiveLog(os.Stderr, 7)
	var counts scanner.CountLiveProgress

	cfg := scanner.ProbeConfig{
		Port:       port,
		EnableIPv6: enableIPv6,
		OnProbe: func(host types.Host, alive bool) {
			probed, live := counts.Record(alive)
			mark := "·"
			if alive {
				mark = "✓"
			}
			target := host.Origin
			if host.IP != nil {
				target = host.IP.String()
			}
			probeLog.Push(fmt.Sprintf("[探活 %d/%d] %s %s", live, probed, mark, target))
		},
	}

	liveCh := scanner.FilterLive(ctx, in, cfg)
	var hosts []types.Host
	for h := range liveCh {
		hosts = append(hosts, h)
	}
	probeLog.Close()

	probed, live := counts.Totals()
	fmt.Fprintf(os.Stderr, "[%s] 探活完成: %d/%d 存活\n", time.Now().Format("15:04:05"), live, probed)
	return hosts
}

// hostsToChannel replays a fixed host slice as a closed channel so it can feed
// the scan pipeline like any other host source.
func hostsToChannel(hosts []types.Host) <-chan types.Host {
	ch := make(chan types.Host, len(hosts))
	for _, h := range hosts {
		ch <- h
	}
	close(ch)
	return ch
}

// extractHiddenFlag removes a bare boolean flag token from args, returning the
// remaining args and whether it was present. Used for source-only flags that
// are deliberately kept out of the FlagSet (and thus out of -h usage).
func extractHiddenFlag(args []string, name string) (remaining []string, present bool) {
	for _, a := range args {
		if a == name {
			present = true
			continue
		}
		remaining = append(remaining, a)
	}
	return remaining, present
}

// maybeBGPPeek is the hidden `-bgp-peek` easter egg: log a one-line preview of
// how many neighbours bgp.tools has seen in the target's /24. Purely
// informational — it never gates scanning. Undocumented on purpose.
func maybeBGPPeek(ctx context.Context, addr string, enabled, enableIPv6 bool) {
	if !enabled || addr == "" {
		return
	}
	res, err := scanner.PeekPrefixUsageForAddr(ctx, addr, enableIPv6)
	if err != nil {
		slog.Warn("bgp-peek failed", "addr", addr, "err", err)
		return
	}
	src := "network"
	if res.Cached {
		src = "cache"
	}
	fmt.Fprintf(os.Stderr, "[%s] 🥚 pfximg: %s 约 %d/%d 邻居在用 (%s, 预览, 不代表可握手)\n",
		time.Now().Format("15:04:05"), res.CIDR, res.Active, res.Total, src)
}

func openOutput(path string) (io.Writer, io.Closer, error) {
	if path == "" || path == "-" {
		return os.Stdout, nil, nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return nil, nil, err
	}
	return f, f, nil
}

func setupLogging(verbose bool) {
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
}

func clearProxy() {
	for _, name := range []string{
		"ALL_PROXY", "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
		"all_proxy", "http_proxy", "https_proxy", "no_proxy",
	} {
		_ = os.Unsetenv(name)
	}
}

// reorderArgs moves positional arguments (domains) after all flags
// so that Go's flag.Parse works correctly.
func reorderArgs(args []string) []string {
	var flags []string
	var positional []string

	knownFlags := map[string]bool{
		"-addr": true, "-in": true, "-csv": true, "-port": true,
		"-thread": true, "-out": true, "-timeout": true, "-url": true,
		"-max-hosts": true,
	}

	for i := 0; i < len(args); i++ {
		arg := args[i]
		if strings.HasPrefix(arg, "-") {
			flags = append(flags, arg)
			if knownFlags[arg] && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		} else {
			positional = append(positional, arg)
		}
	}
	return append(flags, positional...)
}
