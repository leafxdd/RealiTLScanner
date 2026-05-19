package scanner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net"
	"net/netip"
	"regexp"
	"strings"

	"github.com/xtls/RealiTLScanner/internal/types"
)

func Iterate(reader io.Reader, enableIPv6 bool) <-chan types.Host {
	s := bufio.NewScanner(reader)
	hostChan := make(chan types.Host)
	go func() {
		defer close(hostChan)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line == "" {
				continue
			}
			ip := net.ParseIP(line)
			if ip != nil && (ip.To4() != nil || enableIPv6) {
				hostChan <- types.Host{
					IP:     ip,
					Origin: line,
					Type:   types.HostTypeIP,
				}
				continue
			}
			_, _, err := net.ParseCIDR(line)
			if err == nil {
				p, err := netip.ParsePrefix(line)
				if err != nil {
					slog.Warn("Invalid cidr", "cidr", line, "err", err)
					continue
				}
				if !p.Addr().Is4() && !enableIPv6 {
					continue
				}
				p = p.Masked()
				addr := p.Addr()
				for {
					if !p.Contains(addr) {
						break
					}
					ip = net.ParseIP(addr.String())
					if ip != nil {
						hostChan <- types.Host{
							IP:     ip,
							Origin: line,
							Type:   types.HostTypeCIDR,
						}
					}
					addr = addr.Next()
				}
				continue
			}
			if ValidateDomainName(line) {
				hostChan <- types.Host{
					IP:     nil,
					Origin: line,
					Type:   types.HostTypeDomain,
				}
				continue
			}
			slog.Warn("Not a valid IP, IP CIDR or domain", "line", line)
		}
		if err := s.Err(); err != nil && !errors.Is(err, io.EOF) {
			slog.Error("Read file error", "err", err)
		}
	}()
	return hostChan
}

func IterateAddr(addr string, enableIPv6 bool) <-chan types.Host {
	hostChan := make(chan types.Host)
	_, _, err := net.ParseCIDR(addr)
	if err == nil {
		return Iterate(strings.NewReader(addr), enableIPv6)
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		ip, err = LookupIP(addr, enableIPv6)
		if err != nil {
			close(hostChan)
			slog.Error("Not a valid IP, IP CIDR or domain", "addr", addr)
			return hostChan
		}
	}
	go func() {
		slog.Info("Enable infinite mode", "init", ip.String())
		lowIP := ip
		highIP := ip
		hostChan <- types.Host{
			IP:     ip,
			Origin: addr,
			Type:   types.HostTypeIP,
		}
		for i := 0; i < math.MaxInt; i++ {
			if i%2 == 0 {
				lowIP = NextIP(lowIP, false)
				hostChan <- types.Host{
					IP:     lowIP,
					Origin: lowIP.String(),
					Type:   types.HostTypeIP,
				}
			} else {
				highIP = NextIP(highIP, true)
				hostChan <- types.Host{
					IP:     highIP,
					Origin: highIP.String(),
					Type:   types.HostTypeIP,
				}
			}
		}
	}()
	return hostChan
}

func LookupIP(addr string, enableIPv6 bool) (net.IP, error) {
	ips, err := net.LookupIP(addr)
	if err != nil {
		return nil, fmt.Errorf("failed to lookup: %w", err)
	}
	var arr []net.IP
	for _, ip := range ips {
		if ip.To4() != nil || enableIPv6 {
			arr = append(arr, ip)
		}
	}
	if len(arr) == 0 {
		return nil, errors.New("no IP found")
	}
	return arr[0], nil
}

func ValidateDomainName(domain string) bool {
	r := regexp.MustCompile(`(?m)^[A-Za-z0-9\-.]+$`)
	return r.MatchString(domain)
}

func ExistOnlyOne(arr []string) bool {
	exist := false
	for _, item := range arr {
		if item != "" {
			if exist {
				return false
			}
			exist = true
		}
	}
	return exist
}

func RemoveDuplicateStr(strSlice []string) []string {
	allKeys := make(map[string]bool)
	var list []string
	for _, item := range strSlice {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}

func CsvEscape(field string) string {
	if strings.ContainsAny(field, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(field, "\"", "\"\"") + "\""
	}
	return field
}

func NextIP(ip net.IP, increment bool) net.IP {
	ipb := big.NewInt(0).SetBytes(ip)
	if increment {
		ipb.Add(ipb, big.NewInt(1))
	} else {
		ipb.Sub(ipb, big.NewInt(1))
	}
	b := ipb.Bytes()
	b = append(make([]byte, len(ip)-len(b)), b...)
	return b
}
