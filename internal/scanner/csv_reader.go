package scanner

import (
	"encoding/csv"
	"io"
	"os"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

var fakeDomains = map[string]bool{
	"localhost":              true,
	"server.domain.com":      true,
	"johnnasmalley.hostname": true,
}

var fakeKeywords = []string{
	"Kubernetes Ingress Controller Fake Certificate",
	"CloudFlare Origin Certificate",
	"FortiGate",
	"Unspecified",
}

const certDomainColumn = 2

func ReadCSVDomains(path string) (<-chan types.Host, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()

	r := csv.NewReader(f)
	r.FieldsPerRecord = -1
	r.LazyQuotes = true

	var domains []string
	seen := make(map[string]bool)
	first := true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, 0, err
		}
		if first {
			first = false
			continue
		}
		if len(rec) <= certDomainColumn {
			continue
		}
		domain := strings.TrimSpace(rec[certDomainColumn])
		if !isValidDomain(domain) || seen[domain] {
			continue
		}
		seen[domain] = true
		domains = append(domains, domain)
	}

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
		if d == "" || unique[d] {
			continue
		}
		if !StrictDomainName(d) {
			continue
		}
		unique[d] = true
		valid = append(valid, d)
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
	if !StrictDomainName(domain) {
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
	// IPv4 literals (a.b.c.d with all parts ≤ 3 digits) are not real domains.
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
