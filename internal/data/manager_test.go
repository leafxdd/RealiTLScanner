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

func TestDataManager_GetPath_EmbeddedCached(t *testing.T) {
	dm := NewDataManager(t.TempDir())

	p1, err := dm.GetPath("cdn_keywords")
	if err != nil {
		t.Fatal(err)
	}
	p2, err := dm.GetPath("cdn_keywords")
	if err != nil {
		t.Fatal(err)
	}
	if p1 != p2 {
		t.Errorf("GetPath should return cached path; got %q vs %q", p1, p2)
	}

	stat1, err := os.Stat(p1)
	if err != nil {
		t.Fatal(err)
	}
	// Re-call GetPath multiple times; ModTime must not change (no re-write).
	for i := 0; i < 10; i++ {
		if _, err := dm.GetPath("cdn_keywords"); err != nil {
			t.Fatal(err)
		}
	}
	stat2, err := os.Stat(p1)
	if err != nil {
		t.Fatal(err)
	}
	if !stat1.ModTime().Equal(stat2.ModTime()) {
		t.Errorf("embedded tmp was re-written; ModTime drifted %v -> %v",
			stat1.ModTime(), stat2.ModTime())
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

func TestDownloadURLs_MirrorsOnlyWhenMirrored(t *testing.T) {
	t.Setenv(mirrorEnvVar, "https://mirror.example, https://other.example/")

	direct := "https://raw.githubusercontent.com/o/r/f.txt"

	got := downloadURLs(&ManagedFile{DownloadURL: direct})
	if len(got) != 1 || got[0] != direct {
		t.Errorf("un-mirrored file should yield only the direct URL, got %v", got)
	}

	got = downloadURLs(&ManagedFile{DownloadURL: direct, Mirrored: true})
	want := []string{
		direct,
		"https://mirror.example/" + direct,
		"https://other.example/" + direct, // trailing slash on the base must not double up
	}
	if len(got) != len(want) {
		t.Fatalf("got %d URLs %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("URL %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestGithubMirrors_EnvDisables(t *testing.T) {
	t.Setenv(mirrorEnvVar, "")
	if got := githubMirrors(); len(got) != 0 {
		t.Errorf("empty %s should disable mirroring, got %v", mirrorEnvVar, got)
	}
	if got := downloadURLs(&ManagedFile{DownloadURL: "https://x/y", Mirrored: true}); len(got) != 1 {
		t.Errorf("mirroring disabled should yield only the direct URL, got %v", got)
	}
}

func TestDataManager_FallsBackToMirror(t *testing.T) {
	var directHits, mirrorHits int64
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&directHits, 1)
		w.WriteHeader(http.StatusForbidden)
	}))
	defer direct.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&mirrorHits, 1)
		w.Write([]byte("from-mirror"))
	}))
	defer mirror.Close()

	t.Setenv(mirrorEnvVar, mirror.URL)

	dir := t.TempDir()
	dm := NewDataManager(dir)
	dm.files["test"] = &ManagedFile{
		Name:        "test",
		State:       StateMissing,
		Path:        filepath.Join(dir, "test.bin"),
		MaxAge:      time.Hour,
		DownloadURL: direct.URL,
		Mirrored:    true,
	}

	if err := dm.EnsureReady(context.Background(), "test"); err != nil {
		t.Fatalf("EnsureReady should have recovered via the mirror: %v", err)
	}
	if directHits != 1 {
		t.Errorf("direct URL hit %d times, want 1", directHits)
	}
	if mirrorHits != 1 {
		t.Errorf("mirror hit %d times, want 1", mirrorHits)
	}
	if dm.State("test") != StateReady {
		t.Error("file should be Ready after a successful mirror download")
	}
	body, err := os.ReadFile(filepath.Join(dir, "test.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "from-mirror" {
		t.Errorf("file content = %q, want %q", body, "from-mirror")
	}
}

func TestDataManager_AllMirrorsFail(t *testing.T) {
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer fail.Close()

	t.Setenv(mirrorEnvVar, fail.URL+","+fail.URL)

	dir := t.TempDir()
	dm := NewDataManager(dir)
	dm.files["test"] = &ManagedFile{
		Name:        "test",
		State:       StateMissing,
		Path:        filepath.Join(dir, "test.bin"),
		MaxAge:      time.Hour,
		DownloadURL: fail.URL,
		Mirrored:    true,
	}

	err := dm.EnsureReady(context.Background(), "test")
	if err == nil {
		t.Fatal("expected an error when every candidate fails")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("expected the last attempt's error, got: %v", err)
	}
	if dm.State("test") != StateMissing {
		t.Error("file should be Missing after every candidate failed")
	}
}
