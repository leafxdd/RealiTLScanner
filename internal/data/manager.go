package data

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

type FileState int

const (
	StateMissing FileState = iota
	StateLoading
	StateReady
	StateStale
)

type ManagedFile struct {
	Name        string
	State       FileState
	Path        string
	LoadedAt    time.Time
	MaxAge      time.Duration
	DownloadURL string
	Embedded    []byte
	MaxBytes    int64 // cap for downloaded payload; 0 → use defaultMaxBytes
	Mirrored    bool  // DownloadURL is a GitHub URL → retry via public relays on failure
}

const defaultMaxBytes int64 = 200 << 20 // 200 MiB

// downloadTimeout caps a single download attempt. Generous because Country.mmdb
// is ~8.5 MiB and a public relay is usually slower than raw.githubusercontent.
const downloadTimeout = 90 * time.Second

// mirrorEnvVar overrides the built-in relay list (comma-separated). Set it to
// an empty value to disable mirroring entirely.
const mirrorEnvVar = "REALITLS_GH_MIRRORS"

// defaultGitHubMirrors are public GitHub relays tried in order after a direct
// download fails — the common case being GitHub being unreachable or throttled
// from mainland China. Each takes the full original URL appended to its base:
// https://ghfast.top/https://raw.githubusercontent.com/owner/repo/path.
var defaultGitHubMirrors = []string{
	"https://ghfast.top",
	"https://gh-proxy.com",
}

func githubMirrors() []string {
	raw, ok := os.LookupEnv(mirrorEnvVar)
	if !ok {
		return defaultGitHubMirrors
	}
	var out []string
	for _, m := range strings.Split(raw, ",") {
		if m = strings.TrimSpace(m); m != "" {
			out = append(out, m)
		}
	}
	return out
}

// downloadURLs returns the direct URL followed by its mirror rewrites. Files
// not marked Mirrored get the direct URL only — the relays proxy GitHub, so
// pointing anything else at them just wastes an attempt.
func downloadURLs(f *ManagedFile) []string {
	urls := []string{f.DownloadURL}
	if !f.Mirrored {
		return urls
	}
	for _, m := range githubMirrors() {
		urls = append(urls, strings.TrimSuffix(m, "/")+"/"+f.DownloadURL)
	}
	return urls
}

type DataManager struct {
	baseDir string
	files   map[string]*ManagedFile
	mu      sync.RWMutex
	sf      singleflight.Group
}

func NewDataManager(baseDir string) *DataManager {
	dm := &DataManager{
		baseDir: baseDir,
		files:   make(map[string]*ManagedFile),
	}

	dm.files["cdn_keywords"] = &ManagedFile{
		Name:     "cdn_keywords",
		State:    StateReady,
		Embedded: EmbeddedCDNKeywords,
	}
	dm.files["hot_websites"] = &ManagedFile{
		Name:     "hot_websites",
		State:    StateReady,
		Embedded: EmbeddedHotWebsites,
	}
	dm.files["blocklist"] = &ManagedFile{
		Name:     "blocklist",
		State:    StateReady,
		Embedded: EmbeddedBlocklist,
	}
	dm.files["gfwlist"] = &ManagedFile{
		Name:        "gfwlist",
		State:       StateMissing,
		Path:        filepath.Join(baseDir, "gfwlist.conf"),
		MaxAge:      7 * 24 * time.Hour,
		DownloadURL: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
		Mirrored:    true,
	}
	dm.files["geoip"] = &ManagedFile{
		Name:        "geoip",
		State:       StateMissing,
		Path:        filepath.Join(baseDir, "Country.mmdb"),
		MaxAge:      30 * 24 * time.Hour,
		DownloadURL: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
		Mirrored:    true,
	}

	for name, f := range dm.files {
		if f.Path != "" {
			if info, err := os.Stat(f.Path); err == nil {
				f.State = StateReady
				f.LoadedAt = info.ModTime()
				if time.Since(f.LoadedAt) > f.MaxAge {
					f.State = StateStale
				}
			}
		}
		// Embedded files are materialised once to TempDir; subsequent GetPath
		// calls return the cached path without re-writing.
		if f.Embedded != nil && f.Path == "" {
			tmp, err := os.CreateTemp("", "realitlscanner-"+name+"-*")
			if err != nil {
				slog.Warn("Failed to materialise embedded data", "name", name, "err", err)
				continue
			}
			if _, err := tmp.Write(f.Embedded); err != nil {
				slog.Warn("Failed to write embedded data", "name", name, "err", err)
				tmp.Close()
				os.Remove(tmp.Name())
				continue
			}
			if err := tmp.Close(); err != nil {
				slog.Warn("Failed to close embedded tmp", "name", name, "err", err)
				os.Remove(tmp.Name())
				continue
			}
			f.Path = tmp.Name()
		}
	}

	return dm
}

func (m *DataManager) EnsureReady(ctx context.Context, names ...string) error {
	for _, name := range names {
		m.mu.RLock()
		f, ok := m.files[name]
		state := FileState(StateMissing)
		if ok {
			state = f.State
		}
		m.mu.RUnlock()
		if !ok {
			return fmt.Errorf("unknown data file: %s", name)
		}
		if state == StateReady {
			continue
		}
		if f.Embedded != nil {
			continue
		}
		if f.DownloadURL == "" {
			continue
		}
		// singleflight dedups concurrent EnsureReady calls for the same file.
		_, err, _ := m.sf.Do(name, func() (any, error) {
			// Re-check inside flight — another caller may have finished it.
			m.mu.RLock()
			ready := f.State == StateReady
			m.mu.RUnlock()
			if ready {
				return nil, nil
			}
			slog.Info("Downloading data file...", "name", name, "url", f.DownloadURL)
			return nil, m.download(ctx, f)
		})
		if err != nil {
			return fmt.Errorf("failed to download %s: %w", name, err)
		}
	}
	return nil
}

func (m *DataManager) Get(name string) ([]byte, error) {
	m.mu.RLock()
	f, ok := m.files[name]
	m.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown data file: %s", name)
	}
	if f.Path != "" && (f.State == StateReady || f.State == StateStale) {
		data, err := os.ReadFile(f.Path)
		if err == nil {
			return data, nil
		}
	}
	if f.Embedded != nil {
		return f.Embedded, nil
	}
	return nil, fmt.Errorf("data file not available: %s", name)
}

func (m *DataManager) GetPath(name string) (string, error) {
	m.mu.RLock()
	f, ok := m.files[name]
	m.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("unknown data file: %s", name)
	}
	if f.Path != "" {
		return f.Path, nil
	}
	return "", fmt.Errorf("data file not available: %s", name)
}

func (m *DataManager) State(name string) FileState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if f, ok := m.files[name]; ok {
		return f.State
	}
	return StateMissing
}

// download fetches f from its direct URL, falling back to the public GitHub
// relays (see downloadURLs) when that fails. Returns the last error if every
// candidate fails.
func (m *DataManager) download(ctx context.Context, f *ManagedFile) error {
	m.setState(f, StateLoading)

	urls := downloadURLs(f)
	var lastErr error
	for i, u := range urls {
		if i > 0 {
			slog.Warn("Download failed, retrying via GitHub mirror",
				"name", f.Name, "mirror", u, "err", lastErr)
		}
		written, err := m.fetch(ctx, f, u)
		if err == nil {
			m.mu.Lock()
			f.State = StateReady
			f.LoadedAt = time.Now()
			m.mu.Unlock()
			slog.Info("Downloaded data file",
				"name", f.Name, "path", f.Path, "bytes", written, "mirrored", i > 0)
			return nil
		}
		lastErr = err
		// A cancelled context won't recover on the next URL — stop rather than
		// grinding through the whole mirror list.
		if ctx.Err() != nil {
			break
		}
	}

	m.setState(f, StateMissing)
	return lastErr
}

func (m *DataManager) setState(f *ManagedFile, state FileState) {
	m.mu.Lock()
	f.State = state
	m.mu.Unlock()
}

// fetch downloads rawURL into f.Path atomically (temp file + rename) and
// returns the bytes written. It does not touch f.State — download owns that,
// so a failed attempt doesn't mark the file Missing before the mirrors are
// tried.
func (m *DataManager) fetch(ctx context.Context, f *ManagedFile, rawURL string) (int64, error) {
	maxBytes := f.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}

	client := &http.Client{Timeout: downloadTimeout}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	if resp.ContentLength > 0 && resp.ContentLength > maxBytes {
		return 0, fmt.Errorf("Content-Length %d exceeds limit %d", resp.ContentLength, maxBytes)
	}

	if err := os.MkdirAll(filepath.Dir(f.Path), 0755); err != nil {
		return 0, err
	}

	tmpPath := f.Path + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		return 0, err
	}

	// Read at most maxBytes+1 so an over-limit body trips the size check
	// instead of silently truncating.
	written, copyErr := io.Copy(out, io.LimitReader(resp.Body, maxBytes+1))
	closeErr := out.Close()
	if copyErr == nil && closeErr != nil {
		copyErr = closeErr
	}
	if copyErr == nil && written > maxBytes {
		copyErr = fmt.Errorf("download exceeded %d bytes (got at least %d)", maxBytes, written)
	}
	if copyErr != nil {
		os.Remove(tmpPath)
		return 0, copyErr
	}

	if err := os.Rename(tmpPath, f.Path); err != nil {
		os.Remove(tmpPath)
		return 0, err
	}

	return written, nil
}
