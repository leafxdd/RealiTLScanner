package types

import (
	"net"
	"time"
)

type TLSInfo struct {
	Version    uint16 `json:"version"`
	ALPN       string `json:"alpn"`
	CertDomain string `json:"cert_domain"`
	CertIssuer string `json:"cert_issuer"`
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
}

type HotSiteResult struct {
	IsHot    bool   `json:"is_hot"`
	Category string `json:"category,omitempty"`
}

type CertValidResult struct {
	Valid     bool      `json:"valid"`
	SNIMatch  bool     `json:"sni_match"`
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

	Feasible bool   `json:"feasible"`
	Score    int    `json:"score,omitempty"`
	Error    string `json:"error,omitempty"`
}
