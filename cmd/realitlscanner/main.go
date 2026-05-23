package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
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
		routeSubcommand(os.Args[1], os.Args[2:])
		return
	}
	runLegacy(os.Args[1:])
}

func routeSubcommand(cmd string, args []string) {
	switch cmd {
	case "scan":
		runScan(args)
	case "check":
		runCheck(args)
	case "version":
		printVersion()
	default:
		runLegacy(os.Args[1:])
	}
}

func runLegacy(args []string) {
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
	_ = fs.Parse(args)

	setupLogging(verbose)
	clearProxy()

	if !scanner.ExistOnlyOne([]string{addr, in, url}) {
		slog.Error("Specify exactly one of: -addr, -in, -url")
		fs.PrintDefaults()
		return
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	hostChan := resolveHosts(ctx, addr, in, url, enableIPv6, infinite)
	if hostChan == nil {
		return
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

	pipeCfg := pipeline.Config{
		ScanWorkers:   thread,
		DetectWorkers: thread,
		Mode:          pipeline.ModeStream,
		ScanConfig:    cfg,
	}

	p := pipeline.New(pipeCfg, geoReader, nil)

	outCh, err := p.Run(ctx, hostChan)
	if err != nil {
		slog.Error("Pipeline failed", "err", err)
		return
	}

	t := time.Now()
	slog.Info("Started scanning")
	for result := range outCh {
		if err := w.WriteResult(result); err != nil {
			slog.Error("Error writing result", "err", err)
		}
	}
	if err := w.Close(); err != nil {
		slog.Error("Error closing writer", "err", err)
	}
	slog.Info("Completed", "elapsed", time.Since(t).String())
}

func runScan(args []string) {
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
	_ = fs.Parse(args)

	setupLogging(verbose)
	clearProxy()

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
		rawHosts := resolveHosts(ctx, addr, in, url, enableIPv6, infinite)
		if rawHosts == nil {
			return
		}
		fmt.Fprintf(os.Stderr, "[%s] 开始扫描IP段... (Ctrl+C 中断扫描并开始检测)\n", time.Now().Format("15:04:05"))

		// Scan phase uses its own context so Ctrl+C stops scanning but allows detection to proceed
		scanCtx, scanCancel := signal.NotifyContext(ctx, os.Interrupt)

		scanPipeCfg := pipeline.Config{
			ScanWorkers:   thread,
			DetectWorkers: thread,
			Mode:          pipeline.ModeStream,
			ScanConfig:    cfg,
			PassAll:       true,
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
		ScanWorkers:   thread,
		DetectWorkers: thread,
		Mode:          pipeline.ModeStream,
		ScanConfig:    cfg,
		PassAll:       true,
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
	cdnData, _ := dm.Get("cdn_keywords")
	hotData, _ := dm.Get("hot_websites")

	cdnPath := writeTempFile(cdnData, "cdn_keywords.txt")
	hotPath := writeTempFile(hotData, "hot_websites.txt")

	gfwPath, _ := dm.GetPath("gfwlist")

	dets := []detector.Detector{
		detector.NewTLSCheckDetector(),
		detector.NewCDNDetector(cdnPath),
		detector.NewGFWDetector(gfwPath),
		detector.NewHotSiteDetector(hotPath),
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

func writeTempFile(content []byte, name string) string {
	if len(content) == 0 {
		return ""
	}
	f, err := os.CreateTemp("", name)
	if err != nil {
		return ""
	}
	_, _ = f.Write(content)
	f.Close()
	return f.Name()
}

func resolveHosts(ctx context.Context, addr, in, url string, enableIPv6, infinite bool) <-chan types.Host {
	if addr != "" {
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
	_ = os.Unsetenv("ALL_PROXY")
	_ = os.Unsetenv("HTTP_PROXY")
	_ = os.Unsetenv("HTTPS_PROXY")
	_ = os.Unsetenv("NO_PROXY")
}

// reorderArgs moves positional arguments (domains) after all flags
// so that Go's flag.Parse works correctly.
func reorderArgs(args []string) []string {
	var flags []string
	var positional []string

	knownFlags := map[string]bool{
		"-addr": true, "-in": true, "-csv": true, "-port": true,
		"-thread": true, "-out": true, "-timeout": true, "-url": true,
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
