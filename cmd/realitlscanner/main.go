package main

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"regexp"
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
		addr       string
		in         string
		port       int
		thread     int
		out        string
		timeout    int
		verbose    bool
		enableIPv6 bool
		url        string
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
	_ = fs.Parse(args)

	setupLogging(verbose)
	clearProxy()

	if !scanner.ExistOnlyOne([]string{addr, in, url}) {
		slog.Error("Specify exactly one of: -addr, -in, -url")
		fs.PrintDefaults()
		return
	}

	hostChan := resolveHosts(addr, in, url, enableIPv6)
	if hostChan == nil {
		return
	}

	outWriter := openOutput(out)
	if f, ok := outWriter.(*os.File); ok && f != os.Stdout {
		defer f.Close()
	}

	w := output.NewCSVWriter(outWriter, output.Options{})
	_ = w.WriteHeader()

	geoReader := geo.NewGeo()
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
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	outCh, err := p.Run(ctx, hostChan)
	if err != nil {
		slog.Error("Pipeline failed", "err", err)
		return
	}

	t := time.Now()
	slog.Info("Started scanning")
	for result := range outCh {
		_ = w.WriteResult(result)
	}
	_ = w.Close()
	slog.Info("Completed", "elapsed", time.Since(t).String())
}

func runScan(args []string) {
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	var (
		addr       string
		in         string
		port       int
		thread     int
		out        string
		timeout    int
		verbose    bool
		enableIPv6 bool
		url        string
		detect     bool
		detectors  string
		format     string
		dataDir    string
		batch      bool
	)

	fs.StringVar(&addr, "addr", "", "IP, CIDR or domain to scan")
	fs.StringVar(&in, "in", "", "File with IPs/CIDRs/domains")
	fs.IntVar(&port, "port", 443, "HTTPS port")
	fs.IntVar(&thread, "thread", 2, "Concurrent tasks")
	fs.StringVar(&out, "out", "out.csv", "Output file")
	fs.IntVar(&timeout, "timeout", 10, "Timeout (seconds)")
	fs.BoolVar(&verbose, "v", false, "Verbose output")
	fs.BoolVar(&enableIPv6, "46", false, "Enable IPv6")
	fs.StringVar(&url, "url", "", "Crawl domain list from URL")
	fs.BoolVar(&detect, "detect", false, "Enable detectors after scan")
	fs.StringVar(&detectors, "detectors", "all", "Detectors to enable (comma-separated)")
	fs.StringVar(&format, "format", "csv", "Output format: csv/json/jsonl/csv-extended")
	fs.StringVar(&dataDir, "data-dir", ".", "Data files directory")
	fs.BoolVar(&batch, "batch", false, "Batch mode (scan all, then detect)")
	_ = fs.Parse(args)

	setupLogging(verbose)
	clearProxy()

	if !scanner.ExistOnlyOne([]string{addr, in, url}) {
		slog.Error("Specify exactly one of: -addr, -in, -url")
		fs.PrintDefaults()
		return
	}

	hostChan := resolveHosts(addr, in, url, enableIPv6)
	if hostChan == nil {
		return
	}

	outWriter := openOutput(out)
	if f, ok := outWriter.(*os.File); ok && f != os.Stdout {
		defer f.Close()
	}

	opts := output.Options{Extended: detect}
	w := output.NewWriter(format, outWriter, opts)
	_ = w.WriteHeader()

	geoReader := geo.NewGeo()
	defer geoReader.Close()

	var runner *detector.Runner
	if detect {
		dm := data.NewDataManager(dataDir)
		ctx := context.Background()
		_ = dm.EnsureReady(ctx, "cdn_keywords", "hot_websites", "gfwlist")

		dets := buildDetectors(dm, geoReader, detectors)
		runner = detector.NewRunner(dets, thread)
		slog.Info("Detectors enabled", "available", runner.AvailableDetectors())
	}

	cfg := scanner.ScanConfig{
		Port:       port,
		Timeout:    time.Duration(timeout) * time.Second,
		EnableIPv6: enableIPv6,
	}

	mode := pipeline.ModeStream
	if batch {
		mode = pipeline.ModeBatch
	}

	pipeCfg := pipeline.Config{
		ScanWorkers:   thread,
		DetectWorkers: thread,
		Mode:          mode,
		ScanConfig:    cfg,
	}

	p := pipeline.New(pipeCfg, geoReader, runner)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	progress := output.NewProgress(os.Stderr)

	outCh, err := p.Run(ctx, hostChan)
	if err != nil {
		slog.Error("Pipeline failed", "err", err)
		return
	}

	t := time.Now()
	slog.Info("Started scanning")
	for result := range outCh {
		_ = w.WriteResult(result)
		progress.IncFeasible()
	}
	progress.Stop()
	_ = w.Close()
	slog.Info("Completed", "elapsed", time.Since(t).String())
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
		detector.NewResolverDetector(5 * time.Second),
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

func resolveHosts(addr, in, url string, enableIPv6 bool) <-chan types.Host {
	if addr != "" {
		return scanner.IterateAddr(addr, enableIPv6)
	}
	if in != "" {
		f, err := os.Open(in)
		if err != nil {
			slog.Error("Error reading file", "path", in)
			return nil
		}
		return scanner.Iterate(f, enableIPv6)
	}
	if url != "" {
		slog.Info("Fetching url...")
		resp, err := http.Get(url)
		if err != nil {
			slog.Error("Error fetching url", "err", err)
			return nil
		}
		defer resp.Body.Close()
		v, err := io.ReadAll(resp.Body)
		if err != nil {
			slog.Error("Error reading body", "err", err)
			return nil
		}
		arr := regexp.MustCompile(`(http|https)://(.*?)[/"<>\s]+`).FindAllStringSubmatch(string(v), -1)
		var domains []string
		for _, m := range arr {
			domains = append(domains, m[2])
		}
		domains = scanner.RemoveDuplicateStr(domains)
		slog.Info("Parsed domains", "count", len(domains))
		return scanner.Iterate(strings.NewReader(strings.Join(domains, "\n")), enableIPv6)
	}
	return nil
}

func openOutput(path string) io.Writer {
	if path == "" || path == "-" {
		return os.Stdout
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		slog.Error("Error opening output file", "path", path)
		return os.Stdout
	}
	return f
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
