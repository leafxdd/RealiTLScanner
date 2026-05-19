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
}

type DataManager struct {
	baseDir string
	files   map[string]*ManagedFile
	mu      sync.RWMutex
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
		_ = name
	}

	return dm
}

func (m *DataManager) EnsureReady(ctx context.Context, names ...string) error {
	for _, name := range names {
		m.mu.RLock()
		f, ok := m.files[name]
		m.mu.RUnlock()
		if !ok {
			return fmt.Errorf("unknown data file: %s", name)
		}
		if f.State == StateReady {
			continue
		}
		if f.Embedded != nil {
			continue
		}
		if f.DownloadURL == "" {
			continue
		}
		slog.Info("Downloading data file...", "name", name, "url", f.DownloadURL)
		if err := m.download(ctx, f); err != nil {
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
	if f.Path != "" && (f.State == StateReady || f.State == StateStale) {
		return f.Path, nil
	}
	if f.Embedded != nil {
		tmpPath := filepath.Join(m.baseDir, name+".tmp")
		if err := os.WriteFile(tmpPath, f.Embedded, 0644); err != nil {
			return "", err
		}
		return tmpPath, nil
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

	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tmpPath)
		m.mu.Lock()
		f.State = StateMissing
		m.mu.Unlock()
		return err
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

	slog.Info("Downloaded data file", "name", f.Name, "path", f.Path)
	return nil
}
