package detector

import (
	"context"
	"net"

	"github.com/xtls/RealiTLScanner/internal/geo"
	"github.com/xtls/RealiTLScanner/internal/types"
)

type LocationDetector struct {
	geo *geo.Geo
}

func NewLocationDetector(g *geo.Geo) *LocationDetector {
	return &LocationDetector{geo: g}
}

func (d *LocationDetector) Name() string { return "location" }

func (d *LocationDetector) Available() bool { return d.geo != nil }

func (d *LocationDetector) Detect(_ context.Context, result *types.ScanResult) error {
	if result.IP == nil {
		return nil
	}
	result.GeoCode = d.geo.GetGeo(net.IP(result.IP))
	return nil
}
