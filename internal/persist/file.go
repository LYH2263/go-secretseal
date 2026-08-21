package persist

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"

	"example.com/secretseal/internal/keyring"
)

type Snapshot struct {
	Active  string          `json:"active"`
	Entries []keyring.Entry `json:"entries"`
}

type Store struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

func New(path string) *Store { return &Store{path: path} }

func (s *Store) Save(snap Snapshot) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	if s.f != nil {
		_ = s.f.Close()
		s.f = nil
	}
	b, err := json.MarshalIndent(snap, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	// 干净基座：写完即关闭，不常驻句柄
	return nil
}

func (s *Store) Load() (Snapshot, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return Snapshot{}, err
	}
	var snap Snapshot
	if err := json.Unmarshal(b, &snap); err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}

func (s *Store) Path() string { return s.path }
