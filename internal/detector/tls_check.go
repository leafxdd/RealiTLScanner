package detector

import (
	"context"
	"crypto/tls"

	"github.com/xtls/RealiTLScanner/internal/types"
)

type TLSCheckDetector struct{}

func NewTLSCheckDetector() *TLSCheckDetector { return &TLSCheckDetector{} }

func (d *TLSCheckDetector) Name() string { return "tls_check" }

func (d *TLSCheckDetector) Available() bool { return true }

func (d *TLSCheckDetector) Detect(_ context.Context, result *types.ScanResult) error {
	if result.TLS == nil {
		return nil
	}
	valid := result.TLS.Version >= tls.VersionTLS13 &&
		result.TLS.ALPN == "h2" &&
		result.TLS.CertDomain != "" &&
		result.TLS.CertIssuer != ""

	cv := &types.CertValidResult{Valid: valid}
	if result.Host.Type == types.HostTypeDomain {
		match := result.Host.Origin == result.TLS.CertDomain
		cv.SNIMatch = &match
	}
	result.CertValid = cv
	return nil
}
