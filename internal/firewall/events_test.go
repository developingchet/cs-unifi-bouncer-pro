package firewall

import (
	"context"
	"errors"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func TestShardEvents_CreateFailed(t *testing.T) {
	ctx := context.Background()
	const site = "events-site"
	ctrl := testutil.NewMockController()
	sm := NewShardManager(site, false, 10, zoneTestNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "zone")
	var got []ShardCreateFailure
	sm.SetEvents(ShardEvents{CreateFailed: func(f ShardCreateFailure) { got = append(got, f) }})
	if err := sm.EnsureShards(ctx); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		if _, err := sm.Add(ctx, ip); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	ctrl.SetError("CreateTrafficMatchingList", errors.New("UniFi API returned HTTP 422"))
	if err := sm.FlushDirty(ctx); err == nil {
		t.Fatal("FlushDirty succeeded although the create was refused")
	}
	if len(got) != 1 {
		t.Fatalf("CreateFailed called %d times, want 1", len(got))
	}
	f := got[0]
	if f.Site != site || f.Family != "v4" || f.Shard == "" || f.UnsyncedIPs != 2 ||
		f.ConsecutiveFailures != 1 || f.RetryIn != createBackoffBase {
		t.Fatalf("failure = %+v", f)
	}
}

func TestShardEvents_EntryRefused(t *testing.T) {
	ctrl := testutil.NewMockController()
	ctrl.RefuseGroupMember("203.0.113.77/32")
	sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, testutil.NewMockStore(), zerolog.Nop(), 0, false, "legacy")
	var got []RefusedEntry
	sm.SetEvents(ShardEvents{EntryRefused: func(r RefusedEntry) { got = append(got, r) }})

	ctx := context.Background()
	for _, ip := range []string{"198.51.100.1", "203.0.113.77/32"} {
		if err := sm.AddIP(ctx, ip); err != nil {
			t.Fatal(err)
		}
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("EntryRefused called %d times, want 1", len(got))
	}
	r := got[0]
	if r.Site != testSite || r.Family != "v4" || r.Entry != "203.0.113.77/32" || r.Shard == "" || r.RetryIn != refusalHold {
		t.Fatalf("refused entry = %+v", r)
	}
}

func TestShardEvents_ManagerConfigReachesShardManagers(t *testing.T) {
	called := false
	m := &managerImpl{cfg: ManagerConfig{ShardEvents: ShardEvents{EntryRefused: func(RefusedEntry) { called = true }}}}
	m.cb = newCircuitBreaker(1, 0)
	sm := NewShardManager(testSite, false, 10, testNamer(t), testutil.NewMockController(), testutil.NewMockStore(), zerolog.Nop(), 0, false, "legacy")
	m.attachShardCallbacks(sm)
	sm.events.entryRefused(RefusedEntry{})
	if !called {
		t.Fatal("ManagerConfig.ShardEvents was not attached to the shard manager")
	}
}
