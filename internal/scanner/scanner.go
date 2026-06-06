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
		// InsecureSkipVerify is intentional: this scanner aims to discover
		// Reali-TLS-feasible servers, not to validate PKI. Trust chain,
		// revocation, and CA signature are not checked. CertValidResult
		// reflects only feasibility heuristics + SNI hostname match.
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2", "http/1.1"},
		// Offer the X25519MLKEM768 post-quantum hybrid first, classical X25519
		// as fallback. crypto/tls sends a key share for BOTH (see hybridKeyExchange
		// .keyShares), so a non-PQC server still completes in one round trip —
		// no HelloRetryRequest, no handshake-time penalty. A server that picks
		// the hybrid behaves like current Chrome: a quality signal for a dest.
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519},
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
		Curve:         state.CurveID.String(),
		PQC:           isPQCCurve(state.CurveID),
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
		"curve", result.TLS.Curve, "pqc", result.TLS.PQC,
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

// isPQCCurve reports whether id is a post-quantum hybrid key exchange. ScanTLS
// only offers X25519MLKEM768, so that's the only hybrid a server can negotiate
// here; a dest that picks it behaves like current Chrome — a quality signal for
// a Reality steal target.
func isPQCCurve(id tls.CurveID) bool {
	return id == tls.X25519MLKEM768
}
