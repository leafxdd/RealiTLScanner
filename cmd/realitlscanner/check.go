package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"time"

	"github.com/xtls/RealiTLScanner/internal/data"
	"github.com/xtls/RealiTLScanner/internal/detector"
	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/scanner"
	"github.com/xtls/RealiTLScanner/internal/types"
)

func runCheck(args []string) {
	fs := flag.NewFlagSet("check", flag.ExitOnError)
	var (
		port         int
		timeout      int
		dataDir      string
		verbose      bool
		skipDownload bool
	)
	fs.IntVar(&port, "port", 443, "HTTPS port")
	fs.IntVar(&timeout, "timeout", 10, "Timeout (seconds)")
	fs.StringVar(&dataDir, "data-dir", ".", "Data files directory")
	fs.BoolVar(&verbose, "v", false, "Verbose output")
	fs.BoolVar(&skipDownload, "skip-download", false, "Continue even if data file download fails")
	_ = fs.Parse(args)

	setupLogging(verbose)

	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: realitlscanner check <domain> [flags]")
		return
	}
	domain := fs.Arg(0)

	ip, err := scanner.LookupIP(domain, false)
	if err != nil {
		slog.Error("Failed to resolve domain", "domain", domain, "err", err)
		return
	}

	host := types.Host{
		IP:     ip,
		Origin: domain,
		Type:   types.HostTypeDomain,
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	dm := data.NewDataManager(dataDir)
	if err := dm.EnsureReady(ctx, "cdn_keywords", "hot_websites", "gfwlist", "geoip"); err != nil {
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

	cfg := scanner.ScanConfig{
		Port:    port,
		Timeout: time.Duration(timeout) * time.Second,
	}

	result := scanner.ScanTLS(ctx, host, cfg, geoReader)
	if result.Error != "" {
		fmt.Printf("Error: %s\n", result.Error)
		return
	}

	fmt.Printf("=== Check: %s (%s:%d) ===\n", domain, ip.String(), port)
	if result.TLS != nil {
		fmt.Printf("TLS Version:  %s\n", tlsVersionName(result.TLS.Version))
		fmt.Printf("ALPN:         %s\n", result.TLS.ALPN)
		fmt.Printf("Cert Domain:  %s\n", result.TLS.CertDomain)
		fmt.Printf("Cert Issuer:  %s\n", result.TLS.CertIssuer)
	}
	fmt.Printf("GeoCode:      %s\n", result.GeoCode)
	fmt.Printf("Feasible:     %v\n", result.Feasible)

	dets := buildDetectors(dm, geoReader, "all")
	runner := detector.NewRunner(dets, 1)
	runner.ProcessOne(ctx, result)

	fmt.Println("\n--- Detection Results ---")
	if result.CDN != nil {
		fmt.Printf("CDN:          %s (confidence: %.0f%%)\n", result.CDN.Level, result.CDN.Confidence*100)
	}
	if result.GFW != nil {
		fmt.Printf("GFW Blocked:  %v\n", result.GFW.Blocked)
	}
	if result.HotSite != nil {
		fmt.Printf("Hot Website:  %v", result.HotSite.IsHot)
		if result.HotSite.IsHot {
			fmt.Printf(" (%s)", result.HotSite.Category)
		}
		fmt.Println()
	}
	if result.CertValid != nil {
		sniDisplay := "N/A"
		if result.CertValid.SNIMatch != nil {
			sniDisplay = fmt.Sprintf("%v", *result.CertValid.SNIMatch)
		}
		fmt.Printf("Cert Valid:   %v (SNI match: %s)\n", result.CertValid.Valid, sniDisplay)
	}
	if result.Redirect != nil {
		fmt.Printf("Redirect:     %v", result.Redirect.Redirects)
		if result.Redirect.Redirects {
			fmt.Printf(" → %s", result.Redirect.Target)
		}
		fmt.Println()
	}
}

func tlsVersionName(v uint16) string {
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	default:
		return "0x" + strconv.FormatUint(uint64(v), 16)
	}
}

