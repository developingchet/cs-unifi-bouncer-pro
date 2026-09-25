package storage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
	"github.com/vmihailenco/msgpack/v5"
	bolt "go.etcd.io/bbolt"
)

const (
	bucketBans     = "bans"
	bucketGroups   = "groups"
	bucketPolicies = "policies"
	bucketEvents   = "events"

	defaultMaxEvents = 10000
)

type bboltStore struct {
	db        *bolt.DB
	log       zerolog.Logger
	maxEvents int // ring-buffer cap for the events bucket; 0 = defaultMaxEvents
}

// NewBboltStore opens (or creates) a bbolt database at dataDir/bouncer.db.
// maxEvents controls the event audit-trail ring-buffer size (0 = default 10000).
func NewBboltStore(dataDir string, log zerolog.Logger, maxEvents int) (Store, error) {
	if err := os.MkdirAll(dataDir, 0o750); err != nil {
		return nil, fmt.Errorf("create data dir: %w", err)
	}
	path := filepath.Join(dataDir, "bouncer.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open bbolt at %s (stop the running bouncer before offline commands): %w", path, err)
	}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range []string{bucketBans, bucketGroups, bucketPolicies, bucketEvents} {
			if _, err := tx.CreateBucketIfNotExists([]byte(name)); err != nil {
				return fmt.Errorf("create bucket %s: %w", name, err)
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	if maxEvents <= 0 {
		maxEvents = defaultMaxEvents
	}
	return &bboltStore{db: db, log: log, maxEvents: maxEvents}, nil
}

// NewBboltStoreReadOnly opens an existing bbolt database in read-only mode.
// It does not create the file or buckets. The running daemon must release its
// exclusive database lock before an offline status command can open it.
func NewBboltStoreReadOnly(dataDir string) (Store, error) {
	path := filepath.Join(dataDir, "bouncer.db")
	db, err := bolt.Open(path, 0o600, &bolt.Options{
		ReadOnly: true,
		Timeout:  3 * time.Second,
	})
	if err != nil {
		return nil, fmt.Errorf("open bbolt (read-only) at %s (stop the running bouncer before offline status): %w", path, err)
	}
	return &bboltStore{db: db, log: zerolog.Nop()}, nil
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
		Claims:     map[string]time.Time{"legacy": expiresAt.UTC()},
	}
	return s.BanPut(ip, entry)
}

func (s *bboltStore) BanGet(ip string) (*BanEntry, error) {
	var entry *BanEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		value := tx.Bucket([]byte(bucketBans)).Get([]byte(ip))
		if value == nil {
			return nil
		}
		var decoded BanEntry
		if err := msgpack.Unmarshal(value, &decoded); err != nil {
			return fmt.Errorf("decode ban for %s: %w", ip, err)
		}
		entry = &decoded
		return nil
	})
	return entry, err
}

func (s *bboltStore) BanPut(ip string, entry BanEntry) error {
	data, err := msgpack.Marshal(entry)
	if err != nil {
		return fmt.Errorf("marshal BanEntry: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket([]byte(bucketBans)).Put([]byte(ip), data)
	})
}

func (s *bboltStore) BanPutMany(entries map[string]BanEntry) error {
	if len(entries) == 0 {
		return nil
	}
	encoded := make(map[string][]byte, len(entries))
	for ip, entry := range entries {
		data, err := msgpack.Marshal(entry)
		if err != nil {
			return fmt.Errorf("marshal BanEntry for %s: %w", ip, err)
		}
		encoded[ip] = data
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket([]byte(bucketBans))
		for ip, data := range encoded {
			if err := bucket.Put([]byte(ip), data); err != nil {
				return fmt.Errorf("put ban %s: %w", ip, err)
			}
		}
		return nil
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
	rec.UpdatedAt = time.Now().UTC()
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

// ---- Event history (audit trail) -------------------------------------------

// encodeSeq converts a uint64 sequence to a big-endian 8-byte key.
// bbolt stores keys in byte-sorted order, so this gives chronological iteration.
func encodeSeq(seq uint64) []byte {
	key := make([]byte, 8)
	binary.BigEndian.PutUint64(key, seq)
	return key
}

// RecordEvent appends an audit event to the events ring buffer.
// Oldest entries are pruned when the count exceeds s.maxEvents.
func (s *bboltStore) RecordEvent(e EventEntry) error {
	data, err := msgpack.Marshal(e)
	if err != nil {
		return fmt.Errorf("marshal EventEntry: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketEvents))
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		if err := b.Put(encodeSeq(seq), data); err != nil {
			return err
		}
		// Sequence keys are ordered, so only entries older than the cap need
		// inspection. A normal append removes at most one entry.
		if seq > uint64(s.maxEvents) {
			cutoff := encodeSeq(seq - uint64(s.maxEvents))
			cursor := b.Cursor()
			for key, _ := cursor.First(); key != nil && bytes.Compare(key, cutoff) <= 0; key, _ = cursor.Next() {
				if err := b.Delete(key); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// ListEvents returns up to limit events newest-first (limit=0 = all).
func (s *bboltStore) ListEvents(limit int) ([]EventEntry, error) {
	var events []EventEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketEvents))
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var e EventEntry
			if err := msgpack.Unmarshal(v, &e); err != nil {
				continue
			}
			events = append(events, e)
			if limit > 0 && len(events) >= limit {
				break
			}
		}
		return nil
	})
	return events, err
}

// ListEventsForIP returns up to limit events for a specific IP, newest-first (limit=0 = all).
func (s *bboltStore) ListEventsForIP(ip string, limit int) ([]EventEntry, error) {
	var events []EventEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(bucketEvents))
		c := b.Cursor()
		for k, v := c.Last(); k != nil; k, v = c.Prev() {
			var e EventEntry
			if err := msgpack.Unmarshal(v, &e); err != nil {
				continue
			}
			if e.IP == ip {
				events = append(events, e)
				if limit > 0 && len(events) >= limit {
					break
				}
			}
		}
		return nil
	})
	return events, err
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
