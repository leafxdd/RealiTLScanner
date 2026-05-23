package detector

import "testing"

func TestIsSafeForProbe(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		{"empty", "", false},
		{"localhost", "localhost", false},
		{"sub.localhost", "api.localhost", false},
		{"ipv4 literal", "127.0.0.1", false},
		{"ipv4 metadata", "169.254.169.254", false},
		{"ipv4 private", "192.168.1.1", false},
		{"ipv6 loopback literal", "::1", false},
		{"wildcard", "*.example.com", false},
		{"with port", "example.com:8080", false},
		{"with path", "example.com/foo", false},
		{"with userinfo", "user@example.com", false},
		{"with query", "example.com?x=1", false},
		{"with fragment", "example.com#frag", false},
		{"control char", "exa\x01mple.com", false},
		{"public domain", "example.com", true},
		{"public subdomain", "www.cloudflare.com", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isSafeForProbe(tt.domain)
			if got != tt.want {
				t.Errorf("isSafeForProbe(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}
