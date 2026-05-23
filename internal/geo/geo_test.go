package geo

import (
	"net"
	"testing"
)

func TestGeo_EmptyPathReturnsDisabled(t *testing.T) {
	g := NewGeo("")
	defer g.Close()
	if g.reader != nil {
		t.Error("empty path should leave reader nil (disabled)")
	}
	got := g.GetGeo(net.ParseIP("1.2.3.4"))
	if got != "N/A" {
		t.Errorf("disabled GetGeo should return N/A, got %q", got)
	}
}

func TestGeo_RespectsCustomPath(t *testing.T) {
	// Missing path should not panic; should fall back to disabled.
	g := NewGeo("/nonexistent/path/Country.mmdb")
	defer g.Close()
	if g.reader != nil {
		t.Error("nonexistent path should leave reader nil")
	}
}
