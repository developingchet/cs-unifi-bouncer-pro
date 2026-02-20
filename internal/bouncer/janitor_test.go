package bouncer

import (
	"context"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

func newJanitorTestStore(t *testing.T) storage.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := storage.NewBboltStore(dir)
	if err != nil {
		t.Fatalf("NewBboltStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestJanitor_PrunesExpiredBans(t *testing.T) {
	store := newJanitorTestStore(t)

	// Record a ban with past expiry
	past := time.Now().Add(-time.Hour)
	if err := store.BanRecord("1.2.3.4", past, false); err != nil {
		t.Fatal(err)
	}
	// Also record a fresh ban
	if err := store.BanRecord("5.6.7.8", time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}

	j := NewJanitor(store, nil, 100*time.Millisecond, time.Minute, zerolog.Nop())
	j.tick()

	// Expired ban should be gone
	exists, _ := store.BanExists("1.2.3.4")
	if exists {
		t.Error("expired ban should have been pruned")
	}
	// Fresh ban should remain
	exists, _ = store.BanExists("5.6.7.8")
	if !exists {
		t.Error("fresh ban should not be pruned")
	}
}

func TestJanitor_KeepsFreshBans(t *testing.T) {
	store := newJanitorTestStore(t)

	// Record a fresh ban
	if err := store.BanRecord("9.9.9.9", time.Now().Add(24*time.Hour), false); err != nil {
		t.Fatal(err)
	}

	j := NewJanitor(store, nil, 100*time.Millisecond, time.Minute, zerolog.Nop())
	j.tick()

	exists, _ := store.BanExists("9.9.9.9")
	if !exists {
		t.Error("fresh ban should not be pruned")
	}
}

func TestJanitor_PrunesRateEntries(t *testing.T) {
	store := newJanitorTestStore(t)

	// Use the rate gate to generate entries
	_, _ = store.APIRateGate("test-ep", 50*time.Millisecond, 5)
	_, _ = store.APIRateGate("test-ep", 50*time.Millisecond, 5)

	// Wait for entries to expire
	time.Sleep(100 * time.Millisecond)

	j := NewJanitor(store, nil, 100*time.Millisecond, 50*time.Millisecond, zerolog.Nop())
	j.tick()

	// After pruning, rate gate should be reset
	allowed, err := store.APIRateGate("test-ep", 50*time.Millisecond, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !allowed {
		t.Error("after prune, rate gate should allow requests again")
	}
}

func TestJanitor_UpdatesDBSizeMetric(t *testing.T) {
	store := newJanitorTestStore(t)

	j := NewJanitor(store, nil, 100*time.Millisecond, time.Minute, zerolog.Nop())
	// tick() should not panic even if Prometheus metrics aren't registered
	// (they register on first use). Just verify no error/panic.
	j.tick()
}

func TestJanitor_TickImmediatelyOnStart(t *testing.T) {
	store := newJanitorTestStore(t)

	// Record an expired ban
	if err := store.BanRecord("3.3.3.3", time.Now().Add(-time.Hour), false); err != nil {
		t.Fatal(err)
	}

	// Use a long ticker interval so the timer doesn't fire during the test
	j := NewJanitor(store, nil, 10*time.Minute, time.Minute, zerolog.Nop())
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- j.Run(ctx)
	}()

	// Wait for context to expire
	<-ctx.Done()
	<-done

	// The first tick should have run immediately on start, pruning the expired ban
	exists, _ := store.BanExists("3.3.3.3")
	if exists {
		t.Error("expired ban should have been pruned on first immediate tick")
	}
}
