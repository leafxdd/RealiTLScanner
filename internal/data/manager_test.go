package data

import (
	"context"
	"os"
	"testing"
)

func TestEmbeddedData(t *testing.T) {
	if len(EmbeddedCDNKeywords) == 0 {
		t.Error("EmbeddedCDNKeywords should not be empty")
	}
	if len(EmbeddedHotWebsites) == 0 {
		t.Error("EmbeddedHotWebsites should not be empty")
	}
}

func TestDataManager_GetEmbedded(t *testing.T) {
	dm := NewDataManager(t.TempDir())

	data, err := dm.Get("cdn_keywords")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("cdn_keywords should return embedded data")
	}

	data, err = dm.Get("hot_websites")
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("hot_websites should return embedded data")
	}
}

func TestDataManager_State(t *testing.T) {
	dm := NewDataManager(t.TempDir())

	if dm.State("cdn_keywords") != StateReady {
		t.Error("embedded file should be Ready")
	}
	if dm.State("gfwlist") != StateMissing {
		t.Error("gfwlist should be Missing without download")
	}
	if dm.State("nonexistent") != StateMissing {
		t.Error("unknown file should be Missing")
	}
}

func TestDataManager_GetPath_Embedded(t *testing.T) {
	tmpDir := t.TempDir()
	dm := NewDataManager(tmpDir)

	path, err := dm.GetPath("cdn_keywords")
	if err != nil {
		t.Fatal(err)
	}
	if path == "" {
		t.Error("GetPath should return a path for embedded file")
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file should exist at path: %s", path)
	}
}

func TestDataManager_EnsureReady_Embedded(t *testing.T) {
	dm := NewDataManager(t.TempDir())
	err := dm.EnsureReady(context.Background(), "cdn_keywords", "hot_websites")
	if err != nil {
		t.Fatal(err)
	}
}
