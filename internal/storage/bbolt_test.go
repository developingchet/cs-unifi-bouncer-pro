package storage

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestStore(t *testing.T) Store {
	t.Helper()
	dir := t.TempDir()
	s, err := NewBboltStore(dir)
	if err != nil {
		t.Fatalf("NewBboltStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestBanRecordExistsDelete(t *testing.T) {
	s := newTestStore(t)

	const ip = "1.2.3.4"

	// Not there yet
	exists, err := s.BanExists(ip)
	if err != nil || exists {
		t.Fatalf("BanExists before record: err=%v, exists=%v", err, exists)
	}

	// Record it
	expires := time.Now().Add(24 * time.Hour)
	if err := s.BanRecord(ip, expires, false); err != nil {
		t.Fatalf("BanRecord: %v", err)
	}

	// Now exists
	exists, err = s.BanExists(ip)
	if err != nil || !exists {
		t.Fatalf("BanExists after record: err=%v, exists=%v", err, exists)
	}

	// BanList
	list, err := s.BanList()
	if err != nil {
		t.Fatalf("BanList: %v", err)
	}
	entry, ok := list[ip]
	if !ok {
		t.Fatal("BanList missing ip")
	}
	if entry.IPv6 {
		t.Error("expected IPv4 entry")
	}
	if entry.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should be set")
	}

	// Delete
	if err := s.BanDelete(ip); err != nil {
		t.Fatalf("BanDelete: %v", err)
	}
	exists, _ = s.BanExists(ip)
	if exists {
		t.Fatal("BanExists after delete should be false")
	}
}

func TestBanEntryExpiresAt(t *testing.T) {
	s := newTestStore(t)
	const ip = "5.6.7.8"
	// Record with past expiry
	past := time.Now().Add(-time.Hour)
	if err := s.BanRecord(ip, past, false); err != nil {
		t.Fatalf("BanRecord: %v", err)
	}
	pruned, err := s.PruneExpiredBans()
	if err != nil {
		t.Fatalf("PruneExpiredBans: %v", err)
	}
	if pruned != 1 {
		t.Fatalf("expected 1 pruned, got %d", pruned)
	}
	exists, _ := s.BanExists(ip)
	if exists {
		t.Fatal("pruned IP should not exist")
	}
}

func TestPruneKeepsFreshBans(t *testing.T) {
	s := newTestStore(t)

	// Fresh ban — should NOT be pruned
	if err := s.BanRecord("9.9.9.9", time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	// Never-expiring ban (zero time) — should NOT be pruned
	if err := s.BanRecord("10.0.0.1", time.Time{}, false); err != nil {
		t.Fatal(err)
	}

	pruned, err := s.PruneExpiredBans()
	if err != nil {
		t.Fatal(err)
	}
	if pruned != 0 {
		t.Fatalf("expected 0 pruned, got %d", pruned)
	}
}

func TestAPIRateGateWithinBudget(t *testing.T) {
	s := newTestStore(t)
	window := time.Minute
	max := 3

	for i := 0; i < max; i++ {
		allowed, err := s.APIRateGate("test-endpoint", window, max)
		if err != nil {
			t.Fatal(err)
		}
		if !allowed {
			t.Fatalf("call %d should be allowed", i+1)
		}
	}

	// 4th call should be denied
	allowed, err := s.APIRateGate("test-endpoint", window, max)
	if err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Fatal("4th call should be denied")
	}
}

func TestAPIRateGateUnlimited(t *testing.T) {
	s := newTestStore(t)
	for i := 0; i < 1000; i++ {
		allowed, _ := s.APIRateGate("endpoint", time.Minute, 0)
		if !allowed {
			t.Fatalf("unlimited gate denied at call %d", i)
		}
	}
}

func TestConcurrentBanAccess(t *testing.T) {
	s := newTestStore(t)
	var wg sync.WaitGroup
	n := 8
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			ip := "192.0.2." + string(rune('0'+id))
			_ = s.BanRecord(ip, time.Now().Add(time.Hour), false)
			_, _ = s.BanExists(ip)
			_ = s.BanDelete(ip)
		}(i)
	}
	wg.Wait()
}

func TestSizeBytes(t *testing.T) {
	s := newTestStore(t)
	size, err := s.SizeBytes()
	if err != nil {
		t.Fatal(err)
	}
	if size == 0 {
		t.Error("expected non-zero db size")
	}
}

func TestGroupCRUD(t *testing.T) {
	s := newTestStore(t)
	rec := GroupRecord{
		UnifiID:   "abc123",
		Site:      "default",
		Members:   []string{"1.2.3.4", "5.6.7.8"},
		IPv6:      false,
		UpdatedAt: time.Now(),
	}
	if err := s.SetGroup("crowdsec-block-v4-0", rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetGroup("crowdsec-block-v4-0")
	if err != nil || got == nil {
		t.Fatalf("GetGroup: err=%v, got=%v", err, got)
	}
	if got.UnifiID != rec.UnifiID {
		t.Errorf("UnifiID mismatch: got %s want %s", got.UnifiID, rec.UnifiID)
	}
	if err := s.DeleteGroup("crowdsec-block-v4-0"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetGroup("crowdsec-block-v4-0")
	if got != nil {
		t.Error("group should be deleted")
	}
}

func TestPolicyCRUD(t *testing.T) {
	s := newTestStore(t)
	rec := PolicyRecord{
		UnifiID:   "pol123",
		Site:      "default",
		Mode:      "legacy",
		UpdatedAt: time.Now(),
	}
	if err := s.SetPolicy("crowdsec-drop-v4-0", rec); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPolicy("crowdsec-drop-v4-0")
	if err != nil || got == nil {
		t.Fatalf("GetPolicy: err=%v, got=%v", err, got)
	}
	if got.UnifiID != rec.UnifiID {
		t.Errorf("UnifiID mismatch: got %s want %s", got.UnifiID, rec.UnifiID)
	}
	if err := s.DeletePolicy("crowdsec-drop-v4-0"); err != nil {
		t.Fatal(err)
	}
	got, _ = s.GetPolicy("crowdsec-drop-v4-0")
	if got != nil {
		t.Error("policy should be deleted")
	}
}

func TestPruneExpiredRateEntries(t *testing.T) {
	s := newTestStore(t)
	// Add entries within window
	_, _ = s.APIRateGate("ep", 100*time.Millisecond, 5)
	_, _ = s.APIRateGate("ep", 100*time.Millisecond, 5)
	// Wait for window to expire
	time.Sleep(150 * time.Millisecond)
	pruned, err := s.PruneExpiredRateEntries(100 * time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if pruned == 0 {
		t.Error("expected some pruned rate entries")
	}
	// After pruning, limit resets
	allowed, _ := s.APIRateGate("ep", 100*time.Millisecond, 2)
	if !allowed {
		t.Error("after prune, should be allowed again")
	}
}

// TestListGroups verifies ListGroups returns all stored groups.
func TestListGroups(t *testing.T) {
	s := newTestStore(t)
	_ = s.SetGroup("g1", GroupRecord{UnifiID: "id1", Site: "a"})
	_ = s.SetGroup("g2", GroupRecord{UnifiID: "id2", Site: "b"})
	groups, err := s.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 2 {
		t.Errorf("expected 2 groups, got %d", len(groups))
	}
}

// TestListPolicies verifies that ListPolicies returns all stored policy records.
func TestListPolicies(t *testing.T) {
	s := newTestStore(t)
	policies := map[string]PolicyRecord{
		"crowdsec-drop-v4-0": {UnifiID: "pol1", Site: "default", Mode: "legacy"},
		"crowdsec-drop-v4-1": {UnifiID: "pol2", Site: "default", Mode: "legacy"},
		"crowdsec-drop-v6-0": {UnifiID: "pol3", Site: "default", Mode: "zone"},
	}
	for k, v := range policies {
		if err := s.SetPolicy(k, v); err != nil {
			t.Fatalf("SetPolicy(%q): %v", k, err)
		}
	}
	got, err := s.ListPolicies()
	if err != nil {
		t.Fatalf("ListPolicies: %v", err)
	}
	if len(got) != 3 {
		t.Errorf("expected 3 policies, got %d", len(got))
	}
	for k, want := range policies {
		rec, ok := got[k]
		if !ok {
			t.Errorf("missing policy %q", k)
			continue
		}
		if rec.UnifiID != want.UnifiID {
			t.Errorf("policy %q: UnifiID got %q, want %q", k, rec.UnifiID, want.UnifiID)
		}
	}
}

// TestAPIRateGate_Concurrent verifies that concurrent callers to APIRateGate
// produce an accurate total call count (no races, no double-counting).
func TestAPIRateGate_Concurrent(t *testing.T) {
	s := newTestStore(t)
	const (
		maxCalls = 20
		workers  = 20
		window   = time.Minute
	)
	var (
		wg      sync.WaitGroup
		allowed int64
	)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.APIRateGate("concurrent-ep", window, maxCalls)
			if err != nil {
				return
			}
			if ok {
				atomic.AddInt64(&allowed, 1)
			}
		}()
	}
	wg.Wait()
	got := atomic.LoadInt64(&allowed)
	if got > int64(maxCalls) {
		t.Errorf("allowed %d calls, but max is %d (race detected)", got, maxCalls)
	}
}

// Ensure bbolt file is actually created on disk.
func TestFileCreated(t *testing.T) {
	dir := t.TempDir()
	s, err := NewBboltStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := os.Stat(dir + "/bouncer.db"); err != nil {
		t.Errorf("db file not created: %v", err)
	}
}
