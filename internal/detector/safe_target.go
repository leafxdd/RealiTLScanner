package detector

import (
	"net"
	"strings"
)

// isSafeForProbe reports whether domain can be safely used as the target of
// an outbound HEAD probe (redirect / status detector).
//
// Rejects:
//   - empty / control chars / wildcard
//   - IP literal (both IPv4 and IPv6) — would bypass DNS and could hit
//     loopback / private / link-local / metadata services
//   - "localhost" / hostnames containing path/userinfo/port/query/fragment chars
//   - hostnames that DNS-resolve to private / loopback / link-local IPs
//
// The DNS-resolution check is best-effort with a short timeout; if lookup
// fails the host is still rejected.
func isSafeForProbe(domain string) bool {
	if domain == "" {
		return false
	}
	if strings.ContainsAny(domain, "/@:?#") {
		return false
	}
	if strings.ContainsRune(domain, '*') {
		return false
	}
	for _, r := range domain {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	if strings.EqualFold(domain, "localhost") || strings.HasSuffix(strings.ToLower(domain), ".localhost") {
		return false
	}
	if ip := net.ParseIP(domain); ip != nil {
		return false
	}
	// DNS check: reject if any resolved IP is non-public.
	ips, err := net.LookupIP(domain)
	if err != nil {
		return false
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return false
		}
	}
	return true
}

func isPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast() {
		return false
	}
	return true
}
