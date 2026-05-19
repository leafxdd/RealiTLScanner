package types

import (
	"net"
	"time"
)

type TLSInfo struct {
	Version    uint16
	ALPN       string
	CertDomain string
	CertIssuer string
}

type CDNResult struct {
	Level      string
	Confidence float64
	Keywords   []string
}

type GFWResult struct {
	Blocked bool
	Source  string
}

type RedirectResult struct {
	Redirects  bool
	Target     string
	StatusCode int
}

type HotSiteResult struct {
	IsHot    bool
	Category string
}

type CertValidResult struct {
	Valid     bool
	SNIMatch  bool
	ExpiresAt time.Time
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
