package storage

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

type PasswordEntry struct {
	ID        string    `json:"id"`
	Note      string    `json:"note"`
	Data      string    `json:"data"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type SafeData struct {
	MasterHash string          `json:"master_hash"`
	MasterSalt string          `json:"master_salt"`
	Passwords  []PasswordEntry `json:"passwords"`
	Version    int             `json:"version"`
}

type Storage struct {
	filepath string
	mu       sync.RWMutex
}

func NewStorage(filepath string) *Storage {
	return &Storage{
		filepath: filepath,
	}
}

func (s *Storage) Load() (*SafeData, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := os.ReadFile(s.filepath)
	if err != nil {
		if os.IsNotExist(err) {
			return &SafeData{
				Passwords: []PasswordEntry{},
				Version:   1,
			}, nil
		}
		return nil, err
	}

	var safeData SafeData
	if err := json.Unmarshal(data, &safeData); err != nil {
		return nil, err
	}

	return &safeData, nil
}

func (s *Storage) Save(data *SafeData) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	tempFile := s.filepath + ".tmp"

	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(tempFile, jsonData, 0600); err != nil {
		return err
	}

	return os.Rename(tempFile, s.filepath)
}
