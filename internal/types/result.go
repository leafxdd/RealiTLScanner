package types

import (
	"net"
	"time"
)

type TLSInfo struct {
	Version       uint16        `json:"version"`
	ALPN          string        `json:"alpn"`
	CertDomain    string        `json:"cert_domain"`
	CertIssuer    string        `json:"cert_issuer"`
	HandshakeTime time.Duration `json:"handshake_time"`
	CertExpiry    time.Time     `json:"cert_expiry,omitempty"`
}

type CDNResult struct {
	Level      string   `json:"level"`
	Confidence float64  `json:"confidence"`
	Keywords   []string `json:"keywords,omitempty"`
}

type GFWResult struct {
	Blocked bool   `json:"blocked"`
	Source  string `json:"source"`
}

type RedirectResult struct {
	Redirects  bool   `json:"redirects"`
	Target     string `json:"target,omitempty"`
	StatusCode int    `json:"status_code"`
	Server     string `json:"server,omitempty"` // HTTP Server response header (probe phase)
}

type HotSiteResult struct {
	IsHot    bool   `json:"is_hot"`
	Category string `json:"category,omitempty"`
}

// BlockResult flags a cert domain that is unsuitable as a Reality dest target.
// Hit (proxy panel / dynamic-DNS / NAS) is a hard disqualification; CheapTLD is
// a soft signal that only lowers the star score.
type BlockResult struct {
	Hit      bool     `json:"hit"`
	Reason   string   `json:"reason,omitempty"` // proxy_keyword | dynamic_dns | nas
	Keywords []string `json:"keywords,omitempty"`
	CheapTLD bool     `json:"cheap_tld,omitempty"`
}

// CertValidResult reflects basic TLS feasibility from the scanner's point of
// view — TLS 1.3 + h2 ALPN + non-empty CertDomain/Issuer — and whether the
// SNI passed to the handshake matches the leaf cert (via x509.VerifyHostname).
//
// This is NOT a full PKI verification: ScanTLS uses InsecureSkipVerify=true
// so chain-of-trust, revocation, and CA signature are not checked. Consumers
// that need true validity must perform their own verify against system roots.
type CertValidResult struct {
	Valid     bool      `json:"valid"`
	SNIMatch  *bool     `json:"sni_match,omitempty"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

type ScanResult struct {
	Host      Host      `json:"host"`
	IP        net.IP    `json:"ip"`
	Port      int       `json:"port"`
	Timestamp time.Time `json:"timestamp"`
	GeoCode   string    `json:"geo_code"`

	TLS *TLSInfo `json:"tls,omitempty"`

	CDN       *CDNResult       `json:"cdn,omitempty"`
	GFW       *GFWResult       `json:"gfw,omitempty"`
	Redirect  *RedirectResult  `json:"redirect,omitempty"`
	HotSite   *HotSiteResult   `json:"hot_site,omitempty"`
	CertValid *CertValidResult `json:"cert_valid,omitempty"`
	Block     *BlockResult     `json:"block,omitempty"`

	Feasible bool   `json:"feasible"`
	Score    int    `json:"score,omitempty"`
	Error    string `json:"error,omitempty"`
}
