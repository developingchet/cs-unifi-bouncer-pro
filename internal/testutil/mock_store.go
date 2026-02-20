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
	rate     map[string][]int64 // endpoint -> Unix-nano timestamps

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
		rate:     make(map[string][]int64),
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

func (m *MockStore) popError(method string) error {
	err := m.errors[method]
	delete(m.errors, method)
	return err
}

// --- Ban operations ---------------------------------------------------------

func (m *MockStore) BanExists(ip string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("BanExists"); err != nil {
		return false, err
	}
	_, ok := m.bans[ip]
	return ok, nil
}

func (m *MockStore) BanRecord(ip string, expiresAt time.Time, ipv6 bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("BanRecord"); err != nil {
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
	if err := m.popError("BanDelete"); err != nil {
		return err
	}
	delete(m.bans, ip)
	return nil
}

func (m *MockStore) BanList() (map[string]storage.BanEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("BanList"); err != nil {
		return nil, err
	}
	result := make(map[string]storage.BanEntry, len(m.bans))
	for k, v := range m.bans {
		result[k] = v
	}
	return result, nil
}

// --- APIRateGate ------------------------------------------------------------

func (m *MockStore) APIRateGate(endpoint string, window time.Duration, max int) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("APIRateGate"); err != nil {
		return false, err
	}
	if max <= 0 {
		return true, nil
	}
	cutoff := time.Now().Add(-window).UnixNano()
	now := time.Now().UnixNano()
	ts := m.rate[endpoint]

	// Prune old
	pruned := ts[:0]
	for _, t := range ts {
		if t >= cutoff {
			pruned = append(pruned, t)
		}
	}

	if len(pruned) >= max {
		m.rate[endpoint] = pruned
		return false, nil
	}
	m.rate[endpoint] = append(pruned, now)
	return true, nil
}

// --- Janitor helpers --------------------------------------------------------

func (m *MockStore) PruneExpiredBans() (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("PruneExpiredBans"); err != nil {
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

func (m *MockStore) PruneExpiredRateEntries(window time.Duration) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("PruneExpiredRateEntries"); err != nil {
		return 0, err
	}
	cutoff := time.Now().Add(-window).UnixNano()
	total := 0
	for ep, ts := range m.rate {
		pruned := ts[:0]
		for _, t := range ts {
			if t >= cutoff {
				pruned = append(pruned, t)
			}
		}
		total += len(ts) - len(pruned)
		if len(pruned) == 0 {
			delete(m.rate, ep)
		} else {
			m.rate[ep] = pruned
		}
	}
	return total, nil
}

// --- Group cache ------------------------------------------------------------

func (m *MockStore) GetGroup(name string) (*storage.GroupRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("GetGroup"); err != nil {
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
	if err := m.popError("SetGroup"); err != nil {
		return err
	}
	m.groups[name] = rec
	return nil
}

func (m *MockStore) DeleteGroup(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("DeleteGroup"); err != nil {
		return err
	}
	delete(m.groups, name)
	return nil
}

func (m *MockStore) ListGroups() (map[string]storage.GroupRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("ListGroups"); err != nil {
		return nil, err
	}
	result := make(map[string]storage.GroupRecord, len(m.groups))
	for k, v := range m.groups {
		result[k] = v
	}
	return result, nil
}

// --- Policy cache -----------------------------------------------------------

func (m *MockStore) GetPolicy(name string) (*storage.PolicyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("GetPolicy"); err != nil {
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
	if err := m.popError("SetPolicy"); err != nil {
		return err
	}
	m.policies[name] = rec
	return nil
}

func (m *MockStore) DeletePolicy(name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("DeletePolicy"); err != nil {
		return err
	}
	delete(m.policies, name)
	return nil
}

func (m *MockStore) ListPolicies() (map[string]storage.PolicyRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("ListPolicies"); err != nil {
		return nil, err
	}
	result := make(map[string]storage.PolicyRecord, len(m.policies))
	for k, v := range m.policies {
		result[k] = v
	}
	return result, nil
}

// --- Utility ----------------------------------------------------------------

func (m *MockStore) SizeBytes() (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.popError("SizeBytes"); err != nil {
		return 0, err
	}
	return m.Size, nil
}

func (m *MockStore) Close() error {
	return nil
}
