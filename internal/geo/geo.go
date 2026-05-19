package geo

import (
	"log/slog"
	"net"

	"github.com/oschwald/geoip2-golang"
)

type Geo struct {
	reader *geoip2.Reader
}

func NewGeo() *Geo {
	db, err := geoip2.Open("Country.mmdb")
	if err != nil {
		slog.Warn("GeoIP database not found, geo lookup disabled", "err", err)
		return &Geo{}
	}
	return &Geo{reader: db}
}

func (g *Geo) GetGeo(ip net.IP) string {
	if g.reader == nil {
		return "N/A"
	}
	record, err := g.reader.Country(ip)
	if err != nil {
		return "N/A"
	}
	return record.Country.IsoCode
}

func (g *Geo) Close() {
	if g.reader != nil {
		g.reader.Close()
	}
}
