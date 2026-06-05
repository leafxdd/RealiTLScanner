package detector

import (
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

// serverCategory classifies an HTTP `Server` response header for Reality-dest
// suitability.
type serverCategory int

const (
	serverNone    serverCategory = iota // empty / absent header
	serverWeb                           // recognised general-purpose web server / CDN
	serverProxy                         // proxy-panel signature → disqualifying
	serverUnknown                       // non-empty but unrecognised
)

// proxyServerSignatures are substrings that, when present in a Server header,
// strongly indicate a proxy management panel rather than a real site. Such a
// host must not be used as a Reality dest. Best-effort only: most panels behind
// nginx/caddy expose no distinctive header, so the domain blocklist remains the
// primary "去伪" signal — this catches the ones that self-identify.
var proxyServerSignatures = []string{
	"x-ui", "xui", "3x-ui", "sing-box", "singbox", "v2board", "hysteria",
}

// webServerSignatures are recognised general-purpose web servers / CDNs. Their
// presence is a positive signal (looks like a real site), not disqualifying.
var webServerSignatures = []string{
	"nginx", "cloudflare", "apache", "caddy", "openresty", "tengine",
	"litespeed", "microsoft-iis", "iis", "lighttpd", "envoy", "haproxy",
	"gws", "gvs", "ats",
}

// classifyServer categorises a raw Server header value. Proxy signatures are
// checked first so a self-identifying panel is flagged even if it also names a
// fronting web server.
func classifyServer(server string) serverCategory {
	s := strings.ToLower(strings.TrimSpace(server))
	if s == "" {
		return serverNone
	}
	for _, sig := range proxyServerSignatures {
		if strings.Contains(s, sig) {
			return serverProxy
		}
	}
	for _, sig := range webServerSignatures {
		if strings.Contains(s, sig) {
			return serverWeb
		}
	}
	return serverUnknown
}

// vetoIfProxyServer disqualifies the candidate when its Server header is a
// proxy-panel signature, mirroring the blocklist veto so the scorer and 备注
// column treat it identically. It does not clobber a more specific blocklist
// hit already recorded for the domain. The caller is responsible for recording
// the raw Server string on result.Redirect.
func vetoIfProxyServer(result *types.ScanResult, server string) {
	if classifyServer(server) != serverProxy {
		return
	}
	if result.Block == nil || !result.Block.Hit {
		result.Block = &types.BlockResult{
			Hit:      true,
			Reason:   "proxy_server",
			Keywords: []string{strings.TrimSpace(server)},
		}
	}
	result.Feasible = false
}
