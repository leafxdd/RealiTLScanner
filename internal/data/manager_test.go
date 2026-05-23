package data

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
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

func TestDataManager_DownloadRespectsMaxBytes(t *testing.T) {
	// Server streams more bytes than we allow without setting Content-Length.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		buf := make([]byte, 4096)
		for i := 0; i < 10; i++ {
			if _, err := w.Write(buf); err != nil {
				return
			}
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	dm := NewDataManager(dir)
	dm.files["test"] = &ManagedFile{
		Name:        "test",
		State:       StateMissing,
		Path:        filepath.Join(dir, "test.bin"),
		MaxAge:      time.Hour,
		DownloadURL: srv.URL,
		MaxBytes:    8192,
	}

	err := dm.EnsureReady(context.Background(), "test")
	if err == nil {
		t.Fatal("expected size-limit error")
	}
	if !strings.Contains(err.Error(), "exceeded") {
		t.Errorf("expected 'exceeded' in error, got: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "test.bin")); !os.IsNotExist(err) {
		t.Error("oversized download must not leave behind the final file")
	}
}

func TestDataManager_ConcurrentEnsureReady_NoDuplicateDownload(t *testing.T) {
	var hits int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&hits, 1)
		// Simulate slow response so concurrent callers actually overlap.
		time.Sleep(150 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	dm := NewDataManager(dir)
	dm.files["test"] = &ManagedFile{
		Name:        "test",
		State:       StateMissing,
		Path:        filepath.Join(dir, "test.bin"),
		MaxAge:      time.Hour,
		DownloadURL: srv.URL,
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := dm.EnsureReady(context.Background(), "test"); err != nil {
				t.Errorf("EnsureReady: %v", err)
			}
		}()
	}
	wg.Wait()

	got := atomic.LoadInt64(&hits)
	if got != 1 {
		t.Errorf("expected exactly 1 download, got %d", got)
	}
}

func TestDataManager_DownloadHonorsContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "999999999")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dm := NewDataManager(dir)
	dm.files["test"] = &ManagedFile{
		Name:        "test",
		State:       StateMissing,
		Path:        filepath.Join(dir, "test.bin"),
		MaxAge:      time.Hour,
		DownloadURL: srv.URL,
		MaxBytes:    1024,
	}

	err := dm.EnsureReady(context.Background(), "test")
	if err == nil {
		t.Fatal("expected Content-Length error")
	}
	if !strings.Contains(err.Error(), "Content-Length") {
		t.Errorf("expected Content-Length error, got: %v", err)
	}
}
