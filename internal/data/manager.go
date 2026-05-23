package data

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
}

const defaultMaxBytes int64 = 200 << 20 // 200 MiB

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
	dm.files["gfwlist"] = &ManagedFile{
		Name:        "gfwlist",
		State:       StateMissing,
		Path:        filepath.Join(baseDir, "gfwlist.conf"),
		MaxAge:      7 * 24 * time.Hour,
		DownloadURL: "https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/gfw.txt",
	}
	dm.files["geoip"] = &ManagedFile{
		Name:        "geoip",
		State:       StateMissing,
		Path:        filepath.Join(baseDir, "Country.mmdb"),
		MaxAge:      30 * 24 * time.Hour,
		DownloadURL: "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/Country.mmdb",
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

func (m *DataManager) download(ctx context.Context, f *ManagedFile) error {
	m.mu.Lock()
	f.State = StateLoading
	m.mu.Unlock()

	maxBytes := f.MaxBytes
	if maxBytes <= 0 {
		maxBytes = defaultMaxBytes
	}

	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.DownloadURL, nil)
	if err != nil {
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return err
	}

	resp, err := client.Do(req)
	if err != nil {
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return fmt.Errorf("download failed: HTTP %d", resp.StatusCode)
	}

	if resp.ContentLength > 0 && resp.ContentLength > maxBytes {
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return fmt.Errorf("Content-Length %d exceeds limit %d", resp.ContentLength, maxBytes)
	}

	if err := os.MkdirAll(filepath.Dir(f.Path), 0755); err != nil {
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return err
	}

	tmpPath := f.Path + ".tmp"
	out, err := os.Create(tmpPath)
	if err != nil {
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return err
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
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return copyErr
	}

	if err := os.Rename(tmpPath, f.Path); err != nil {
		os.Remove(tmpPath)
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return err
	}

	m.mu.Lock()
	f.State = StateReady
	f.LoadedAt = time.Now()
	m.mu.Unlock()

	slog.Info("Downloaded data file", "name", f.Name, "path", f.Path, "bytes", written)
	return nil
}
