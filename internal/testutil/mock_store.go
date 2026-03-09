package testutil

import (
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// MockStore implements storage.Store with in-memory maps for testing.
// All methods are safe for concurrent use.
type MockStore struct {
	mu       sync.Mutex
	bans     map[string]storage.BanEntry
	groups   map[string]storage.GroupRecord
	policies map[string]storage.PolicyRecord
	events   []storage.EventEntry

	// Error injection: method -> next error (consumed on first call)
	errors map[string]error

	// SizeBytes value returned by SizeBytes()
	Size int64
}

// NewMockStore returns a zero-state MockStore ready for use.
func NewMockStore() *MockStore {
	return &MockStore{
		bans:     make(map[string]storage.BanEntry),
		groups:   make(map[string]storage.GroupRecord),
		policies: make(map[string]storage.PolicyRecord),
		errors:   make(map[string]error),
		Size:     1024,
	}
}

// SetError injects an error to be returned on the next call to the named method.
func (m *MockStore) SetError(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[method] = err
}

// check returns and clears any pending injected error for the named method.
// Must be called with m.mu held.
func (m *MockStore) check(method string) error {
	err := m.errors[method]
	delete(m.errors, method)
	return err
}

// copyMap returns a shallow copy of src. Package-level generic helper.
func copyMap[K comparable, V any](src map[K]V) map[K]V {
	dst := make(map[K]V, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

// --- Ban operations ---------------------------------------------------------

func (m *MockStore) BanExists(ip string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("BanExists"); err != nil {
		return false, err
	}
	_, ok := m.bans[ip]
	return ok, nil
}

func (m *MockStore) BanRecord(ip string, expiresAt time.Time, ipv6 bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("BanRecord"); err != nil {
		return err
	}
	m.bans[ip] = storage.BanEntry{
		RecordedAt: time.Now().UTC(),
		ExpiresAt:  expiresAt.UTC(),
		IPv6:       ipv6,
	}
	return nil
}

func (m *MockStore) BanDelete(ip string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("BanDelete"); err != nil {
		return err
	}
	delete(m.bans, ip)
	return nil
}

func (m *MockStore) BanList() (map[string]storage.BanEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("BanList"); err != nil {
		return nil, err
	}
	return copyMap(m.bans), nil
}

// --- Janitor helpers --------------------------------------------------------

func (m *MockStore) PruneExpiredBans() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("PruneExpiredBans"); err != nil {
		return 0, err
	}
	now := time.Now().UTC()
	pruned := 0
	for ip, entry := range m.bans {
		if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
			delete(m.bans, ip)
			pruned++
		}
	}
	return pruned, nil
}

// --- Group cache ------------------------------------------------------------

func (m *MockStore) GetGroup(name string) (*storage.GroupRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("GetGroup"); err != nil {
		return nil, err
	}
	rec, ok := m.groups[name]
	if !ok {
		return nil, nil
	}
	cp := rec
	return &cp, nil
}

func (m *MockStore) SetGroup(name string, rec storage.GroupRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("SetGroup"); err != nil {
		return err
	}
	m.groups[name] = rec
	return nil
}

func (m *MockStore) DeleteGroup(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("DeleteGroup"); err != nil {
		return err
	}
	delete(m.groups, name)
	return nil
}

func (m *MockStore) ListGroups() (map[string]storage.GroupRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("ListGroups"); err != nil {
		return nil, err
	}
	return copyMap(m.groups), nil
}

// --- Policy cache -----------------------------------------------------------

func (m *MockStore) GetPolicy(name string) (*storage.PolicyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("GetPolicy"); err != nil {
		return nil, err
	}
	rec, ok := m.policies[name]
	if !ok {
		return nil, nil
	}
	cp := rec
	return &cp, nil
}

func (m *MockStore) SetPolicy(name string, rec storage.PolicyRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("SetPolicy"); err != nil {
		return err
	}
	m.policies[name] = rec
	return nil
}

func (m *MockStore) DeletePolicy(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("DeletePolicy"); err != nil {
		return err
	}
	delete(m.policies, name)
	return nil
}

func (m *MockStore) ListPolicies() (map[string]storage.PolicyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("ListPolicies"); err != nil {
		return nil, err
	}
	return copyMap(m.policies), nil
}

// --- Event history ----------------------------------------------------------

func (m *MockStore) RecordEvent(e storage.EventEntry) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("RecordEvent"); err != nil {
		return err
	}
	m.events = append(m.events, e)
	return nil
}

func (m *MockStore) ListEvents(limit int) ([]storage.EventEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("ListEvents"); err != nil {
		return nil, err
	}
	result := make([]storage.EventEntry, len(m.events))
	// Return newest first
	for i, e := range m.events {
		result[len(m.events)-1-i] = e
	}
	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}
	return result, nil
}

func (m *MockStore) ListEventsForIP(ip string, limit int) ([]storage.EventEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("ListEventsForIP"); err != nil {
		return nil, err
	}
	var result []storage.EventEntry
	for i := len(m.events) - 1; i >= 0; i-- {
		if m.events[i].IP == ip {
			result = append(result, m.events[i])
			if limit > 0 && len(result) >= limit {
				break
			}
		}
	}
	return result, nil
}

// --- Utility ----------------------------------------------------------------

func (m *MockStore) SizeBytes() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.check("SizeBytes"); err != nil {
		return 0, err
	}
	return m.Size, nil
}

func (m *MockStore) Close() error {
	return nil
}
