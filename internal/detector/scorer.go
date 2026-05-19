package detector

import (
	"crypto/tls"
	"time"

	"github.com/xtls/RealiTLScanner/internal/types"
)

func ComputeScore(result *types.ScanResult) int {
	score := 0
	if result.TLS == nil {
		return 0
	}

	// TLS 1.3 + H2 + valid cert + SNI match
	if result.CertValid != nil && result.CertValid.Valid && result.CertValid.SNIMatch {
		score++
	} else if result.TLS.Version >= tls.VersionTLS13 && result.TLS.ALPN == "h2" &&
		result.TLS.CertDomain != "" && result.TLS.CertIssuer != "" {
		score++
	}

	// Handshake time <= 200ms
	if result.TLS.HandshakeTime > 0 && result.TLS.HandshakeTime <= 200*time.Millisecond {
		score++
	}

	// No CDN
	if result.CDN == nil || result.CDN.Level == "none" || result.CDN.Level == "" {
		score++
	}

	// Not a hot website
	if result.HotSite == nil || !result.HotSite.IsHot {
		score++
	}

	// Certificate valid >= 60 days
	if !result.TLS.CertExpiry.IsZero() {
		daysLeft := int(time.Until(result.TLS.CertExpiry).Hours() / 24)
		if daysLeft >= 60 {
			score++
		}
	}

	return score
}

func ScoreToStars(score int) string {
	if score <= 0 {
		return ""
	}
	stars := ""
	for i := 0; i < score; i++ {
		stars += "*"
	}
	return stars
}
