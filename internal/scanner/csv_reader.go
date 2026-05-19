package scanner

import (
	"bufio"
	"os"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

var fakeDomains = map[string]bool{
	"localhost":            true,
	"server.domain.com":   true,
	"johnnasmalley.hostname": true,
}

var fakeKeywords = []string{
	"Kubernetes Ingress Controller Fake Certificate",
	"CloudFlare Origin Certificate",
	"FortiGate",
	"Unspecified",
}

func ReadCSVDomains(path string) (<-chan types.Host, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}

	var domains []string
	seen := make(map[string]bool)
	scanner := bufio.NewScanner(f)

	first := true
	for scanner.Scan() {
		if first {
			first = false
			continue
		}
		line := scanner.Text()
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		domain := strings.TrimSpace(fields[2])
		domain = strings.Trim(domain, "\"")

		if !isValidDomain(domain) || seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}
	f.Close()

	ch := make(chan types.Host, len(domains))
	go func() {
		defer close(ch)
		for _, d := range domains {
			ch <- types.Host{Origin: d, Type: types.HostTypeDomain}
		}
	}()
	return ch, len(domains), nil
}

func DomainsToChannel(domains []string) (<-chan types.Host, int) {
	unique := make(map[string]bool)
	var valid []string
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d != "" && !unique[d] {
			unique[d] = true
			valid = append(valid, d)
		}
	}
	ch := make(chan types.Host, len(valid))
	go func() {
		defer close(ch)
		for _, d := range valid {
			ch <- types.Host{Origin: d, Type: types.HostTypeDomain}
		}
	}()
	return ch, len(valid)
}

func IsValidDomain(domain string) bool {
	return isValidDomain(domain)
}

func isValidDomain(domain string) bool {
	if domain == "" || len(domain) < 3 {
		return false
	}
	if strings.Contains(domain, "*") {
		return false
	}
	if strings.Contains(domain, "..") {
		return false
	}
	if strings.Contains(domain, ",") {
		return false
	}
	if strings.Contains(domain, " ") {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	if fakeDomains[domain] {
		return false
	}
	for _, kw := range fakeKeywords {
		if strings.Contains(domain, kw) {
			return false
		}
	}
	parts := strings.Split(domain, ".")
	if len(parts) == 4 {
		allShort := true
		for _, p := range parts {
			if len(p) > 3 {
				allShort = false
				break
			}
		}
		if allShort {
			return false
		}
	}
	return true
}
