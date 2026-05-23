package scanner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/types"
)

type ScanConfig struct {
	Port       int
	Timeout    time.Duration
	EnableIPv6 bool
}

func ScanTLS(ctx context.Context, host types.Host, cfg ScanConfig, geoReader *geo.Geo) *types.ScanResult {
	result := &types.ScanResult{
		Host:      host,
		Port:      cfg.Port,
		Timestamp: time.Now(),
	}

	if host.IP == nil {
		ip, err := LookupIP(host.Origin, cfg.EnableIPv6)
		if err != nil {
			slog.Debug("Failed to get IP from the origin", "origin", host.Origin, "err", err)
			result.Error = err.Error()
			return result
		}
		host.IP = ip
	}
	result.IP = host.IP

	hostPort := net.JoinHostPort(host.IP.String(), strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", hostPort)
	if err != nil {
		if ctx.Err() != nil {
			result.Error = "cancelled"
		} else {
			result.Error = "dial failed"
		}
		slog.Debug("Cannot dial", "target", hostPort, "err", err)
		return result
	}
	defer conn.Close()

	err = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	if err != nil {
		slog.Error("Error setting deadline", "err", err)
		result.Error = "deadline failed"
		return result
	}

	tlsCfg := &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}
	if host.Type == types.HostTypeDomain {
		tlsCfg.ServerName = host.Origin
	}

	c := tls.Client(conn, tlsCfg)
	hsStart := time.Now()
	err = c.HandshakeContext(ctx)
	hsTime := time.Since(hsStart)
	if err != nil {
		if ctx.Err() != nil {
			result.Error = "cancelled"
		} else {
			result.Error = "handshake failed"
		}
		slog.Debug("TLS handshake failed", "target", hostPort, "err", err)
		return result
	}

	state := c.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		slog.Debug("TLS handshake succeeded but no peer certificates", "target", hostPort)
		result.Error = "no peer cert"
		return result
	}
	leaf := state.PeerCertificates[0]
	domain := pickCertDomain(leaf)
	issuers := strings.Join(leaf.Issuer.Organization, " | ")
	certExpiry := leaf.NotAfter

	result.TLS = &types.TLSInfo{
		Version:       state.Version,
		ALPN:          state.NegotiatedProtocol,
		CertDomain:    domain,
		CertIssuer:    issuers,
		HandshakeTime: hsTime,
		CertExpiry:    certExpiry,
	}
	if host.Type == types.HostTypeDomain {
		match := leaf.VerifyHostname(host.Origin) == nil
		result.CertValid = &types.CertValidResult{SNIMatch: &match}
	}
	result.GeoCode = geoReader.GetGeo(host.IP)

	if state.Version == tls.VersionTLS13 && state.NegotiatedProtocol == "h2" && len(domain) > 0 && len(issuers) > 0 {
		result.Feasible = true
	}

	log := slog.Debug
	if result.Feasible {
		log = slog.Info
	}
	log("Connected to target", "feasible", result.Feasible, "ip", host.IP.String(),
		"origin", host.Origin,
		"tls", tls.VersionName(state.Version), "alpn", state.NegotiatedProtocol,
		"cert-domain", domain, "cert-issuer", issuers, "geo", result.GeoCode)

	return result
}

// pickCertDomain prefers the first DNS SAN (modern certs may omit CN entirely
// or carry only a placeholder there); falls back to CN. Returned value is
// lowercased and stripped of a trailing dot so equality checks are stable.
func pickCertDomain(leaf *x509.Certificate) string {
	d := ""
	if len(leaf.DNSNames) > 0 {
		d = leaf.DNSNames[0]
	} else {
		d = leaf.Subject.CommonName
	}
	d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
	return d
}
