package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/vmihailenco/msgpack/v5"
	bolt "go.etcd.io/bbolt"
)

const (
	bucketBans     = "bans"
	bucketRate     = "rate"
	bucketGroups   = "groups"
	bucketPolicies = "policies"
)

type bboltStore struct {
	db *bolt.DB
	mu sync.Mutex // guards rate bucket sliding-window writes
}

// NewBboltStore opens (or creates) a bbolt database at dataDir/bouncer.db.
func NewBboltStore(dataDir string) (Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, "bouncer.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt at %s: %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{bucketBans, bucketRate, bucketGroups, bucketPolicies} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &bboltStore{db: db}, nil
}

// ---- Ban operations --------------------------------------------------------

func (s *bboltStore) BanExists(ip string) (bool, error) {
	var exists bool
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketBans))
		exists = b.Get([]byte(ip)) != nil
		return nil
	})
	return exists, err
}

func (s *bboltStore) BanRecord(ip string, expiresAt time.Time, ipv6 bool) error {
	entry := BanEntry{
		RecordedAt: time.Now().UTC(),
		ExpiresAt:  expiresAt.UTC(),
		IPv6:       ipv6,
	}
	data, err := msgpack.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal BanEntry: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketBans)).Put([]byte(ip), data)
	})
}

func (s *bboltStore) BanDelete(ip string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketBans)).Delete([]byte(ip))
	})
}

func (s *bboltStore) BanList() (map[string]BanEntry, error) {
	result := make(map[string]BanEntry)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketBans)).ForEach(func(k, v []byte) error {
			var entry BanEntry
			if err := msgpack.Unmarshal(v, &entry); err != nil {
				return fmt.Errorf("unmarshal BanEntry for %s: %w", k, err)
			}
			result[string(k)] = entry
			return nil
		})
	})
	return result, err
}

// ---- APIRateGate -----------------------------------------------------------

// APIRateGate implements a sliding-window rate limit backed by bbolt.
// The rate bucket stores a []int64 of Unix nanosecond timestamps per endpoint.
// Returns allowed=true and appends the current timestamp if within budget.
func (s *bboltStore) APIRateGate(endpoint string, window time.Duration, max int) (bool, error) {
	if max <= 0 {
		return true, nil // unlimited
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var allowed bool
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRate))
		key := []byte(endpoint)
		cutoff := time.Now().Add(-window).UnixNano()
		now := time.Now().UnixNano()

		var timestamps []int64
		if raw := b.Get(key); raw != nil {
			if err := msgpack.Unmarshal(raw, &timestamps); err != nil {
				return fmt.Errorf("unmarshal rate timestamps: %w", err)
			}
		}

		// Prune entries outside window
		pruned := timestamps[:0]
		for _, ts := range timestamps {
			if ts >= cutoff {
				pruned = append(pruned, ts)
			}
		}

		if len(pruned) >= max {
			allowed = false
			// Still save pruned slice to keep bucket tidy
			data, err := msgpack.Marshal(pruned)
			if err != nil {
				return err
			}
			return b.Put(key, data)
		}

		allowed = true
		pruned = append(pruned, now)
		data, err := msgpack.Marshal(pruned)
		if err != nil {
			return err
		}
		return b.Put(key, data)
	})
	return allowed, err
}

// ---- Janitor ---------------------------------------------------------------

func (s *bboltStore) PruneExpiredBans() (int, error) {
	now := time.Now().UTC()
	var pruned int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketBans))
		var toDelete [][]byte
		if err := b.ForEach(func(k, v []byte) error {
			var entry BanEntry
			if err := msgpack.Unmarshal(v, &entry); err != nil {
				return nil // skip corrupt entries
			}
			if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
				key := make([]byte, len(k))
				copy(key, k)
				toDelete = append(toDelete, key)
			}
			return nil
		}); err != nil {
			return err
		}
		for _, k := range toDelete {
			if err := b.Delete(k); err != nil {
				return err
			}
			pruned++
		}
		return nil
	})
	return pruned, err
}

func (s *bboltStore) PruneExpiredRateEntries(window time.Duration) (int, error) {
	cutoff := time.Now().Add(-window).UnixNano()
	var pruned int
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketRate))
		return b.ForEach(func(k, v []byte) error {
			var timestamps []int64
			if err := msgpack.Unmarshal(v, &timestamps); err != nil {
				return nil
			}
			before := len(timestamps)
			filtered := timestamps[:0]
			for _, ts := range timestamps {
				if ts >= cutoff {
					filtered = append(filtered, ts)
				}
			}
			pruned += before - len(filtered)
			if len(filtered) == 0 {
				return b.Delete(k)
			}
			data, err := msgpack.Marshal(filtered)
			if err != nil {
				return err
			}
			return b.Put(k, data)
		})
	})
	return pruned, err
}

// ---- Group cache -----------------------------------------------------------

func (s *bboltStore) GetGroup(name string) (*GroupRecord, error) {
	var rec GroupRecord
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketGroups)).Get([]byte(name))
		if v == nil {
			return nil
		}
		found = true
		return msgpack.Unmarshal(v, &rec)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &rec, nil
}

func (s *bboltStore) SetGroup(name string, rec GroupRecord) error {
	data, err := msgpack.Marshal(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketGroups)).Put([]byte(name), data)
	})
}

func (s *bboltStore) DeleteGroup(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketGroups)).Delete([]byte(name))
	})
}

func (s *bboltStore) ListGroups() (map[string]GroupRecord, error) {
	result := make(map[string]GroupRecord)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketGroups)).ForEach(func(k, v []byte) error {
			var rec GroupRecord
			if err := msgpack.Unmarshal(v, &rec); err != nil {
				return err
			}
			result[string(k)] = rec
			return nil
		})
	})
	return result, err
}

// ---- Policy cache ----------------------------------------------------------

func (s *bboltStore) GetPolicy(name string) (*PolicyRecord, error) {
	var rec PolicyRecord
	var found bool
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket([]byte(bucketPolicies)).Get([]byte(name))
		if v == nil {
			return nil
		}
		found = true
		return msgpack.Unmarshal(v, &rec)
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &rec, nil
}

func (s *bboltStore) SetPolicy(name string, rec PolicyRecord) error {
	data, err := msgpack.Marshal(rec)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketPolicies)).Put([]byte(name), data)
	})
}

func (s *bboltStore) DeletePolicy(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketPolicies)).Delete([]byte(name))
	})
}

func (s *bboltStore) ListPolicies() (map[string]PolicyRecord, error) {
	result := make(map[string]PolicyRecord)
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketPolicies)).ForEach(func(k, v []byte) error {
			var rec PolicyRecord
			if err := msgpack.Unmarshal(v, &rec); err != nil {
				return err
			}
			result[string(k)] = rec
			return nil
		})
	})
	return result, err
}

// ---- Utility ---------------------------------------------------------------

func (s *bboltStore) SizeBytes() (int64, error) {
	info, err := os.Stat(s.db.Path())
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

func (s *bboltStore) Close() error {
	return s.db.Close()
}
