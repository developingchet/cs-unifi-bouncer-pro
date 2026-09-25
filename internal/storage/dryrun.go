package storage

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

type dryRunStore struct {
	base Store
}

// NewDryRunStore reads existing state without creating or changing the database.
func NewDryRunStore(dataDir string) (Store, error) {
	_, err := os.Stat(filepath.Join(dataDir, "bouncer.db"))
	if errors.Is(err, os.ErrNotExist) {
		return &dryRunStore{}, nil
	}
	if err != nil {
		return nil, err
	}
	base, err := NewBboltStoreReadOnly(dataDir)
	if err != nil {
		return nil, err
	}
	return &dryRunStore{base: base}, nil
}

func (s *dryRunStore) BanExists(ip string) (bool, error) {
	if s.base == nil {
		return false, nil
	}
	return s.base.BanExists(ip)
}
func (s *dryRunStore) BanGet(ip string) (*BanEntry, error) {
	if s.base == nil {
		return nil, nil
	}
	return s.base.BanGet(ip)
}
func (s *dryRunStore) BanList() (map[string]BanEntry, error) {
	if s.base == nil {
		return map[string]BanEntry{}, nil
	}
	return s.base.BanList()
}
func (s *dryRunStore) BanRecord(string, time.Time, bool) error { return nil }
func (s *dryRunStore) BanPut(string, BanEntry) error           { return nil }
func (s *dryRunStore) BanDelete(string) error                  { return nil }

func (s *dryRunStore) GetGroup(name string) (*GroupRecord, error) {
	if s.base == nil {
		return nil, nil
	}
	return s.base.GetGroup(name)
}
func (s *dryRunStore) ListGroups() (map[string]GroupRecord, error) {
	if s.base == nil {
		return map[string]GroupRecord{}, nil
	}
	return s.base.ListGroups()
}
func (s *dryRunStore) SetGroup(string, GroupRecord) error { return nil }
func (s *dryRunStore) DeleteGroup(string) error           { return nil }

func (s *dryRunStore) GetPolicy(name string) (*PolicyRecord, error) {
	if s.base == nil {
		return nil, nil
	}
	return s.base.GetPolicy(name)
}
func (s *dryRunStore) ListPolicies() (map[string]PolicyRecord, error) {
	if s.base == nil {
		return map[string]PolicyRecord{}, nil
	}
	return s.base.ListPolicies()
}
func (s *dryRunStore) SetPolicy(string, PolicyRecord) error { return nil }
func (s *dryRunStore) DeletePolicy(string) error            { return nil }

func (s *dryRunStore) RecordEvent(EventEntry) error { return nil }
func (s *dryRunStore) ListEvents(limit int) ([]EventEntry, error) {
	if s.base == nil {
		return nil, nil
	}
	return s.base.ListEvents(limit)
}
func (s *dryRunStore) ListEventsForIP(ip string, limit int) ([]EventEntry, error) {
	if s.base == nil {
		return nil, nil
	}
	return s.base.ListEventsForIP(ip, limit)
}
func (s *dryRunStore) SizeBytes() (int64, error) {
	if s.base == nil {
		return 0, nil
	}
	return s.base.SizeBytes()
}
func (s *dryRunStore) Close() error {
	if s.base == nil {
		return nil
	}
	return s.base.Close()
}
