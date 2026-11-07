package firewall

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// recordMembers returns the sorted members the group record of name holds.
func recordMembers(t *testing.T, store *testutil.MockStore, name string) []string {
	t.Helper()
	rec, err := store.GetGroup(cacheKey(testSite, name))
	if err != nil || rec == nil {
		t.Fatalf("group record %s = %v, %v", name, rec, err)
	}
	members := slices.Clone(rec.Members)
	slices.Sort(members)
	return members
}

// A flush saves the members of a shard it creates, and leaves later member
// changes to a save at most shardRecordInterval later instead of rewriting
// the record on every flush.
func TestFlushSavesGroupRecordMembersAtInterval(t *testing.T) {
	ctx := context.Background()
	store := testutil.NewMockStore()
	sm := NewShardManager(testSite, false, 10, testNamer(t), testutil.NewMockController(), store, zerolog.Nop(), 0, false, "legacy")
	now := time.Unix(1_000_000, 0)
	sm.now = func() time.Time { return now }
	if err := sm.EnsureShards(ctx); err != nil {
		t.Fatal(err)
	}
	const name = "crowdsec-block-v4-0"
	flush := func(ips ...string) {
		t.Helper()
		for _, ip := range ips {
			if _, err := sm.Add(ctx, ip); err != nil {
				t.Fatal(err)
			}
		}
		if err := sm.FlushDirty(ctx); err != nil {
			t.Fatal(err)
		}
	}

	flush("198.51.100.1")
	if got := recordMembers(t, store, name); !slices.Equal(got, []string{"198.51.100.1"}) {
		t.Fatalf("record of the created shard = %v, want its first member", got)
	}

	store.ResetCalls()
	flush("198.51.100.2")
	flush("198.51.100.3")
	if got := store.Calls("SetGroup"); got != 0 {
		t.Errorf("SetGroup calls within the interval = %d, want 0", got)
	}

	now = now.Add(shardRecordInterval)
	flush()
	if got := store.Calls("SetGroup"); got != 1 {
		t.Errorf("SetGroup calls once the interval passed = %d, want 1", got)
	}
	want := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	if got := recordMembers(t, store, name); !slices.Equal(got, want) {
		t.Errorf("record = %v, want %v", got, want)
	}
}

// Members flushed since the last save reach the group record at shutdown and
// at each reconcile, so a restart can still restore a shard whose controller
// list was emptied.
func TestShardRecordsSavedForRecovery(t *testing.T) {
	for _, tt := range []struct {
		name string
		save func(t *testing.T, m *managerImpl)
	}{
		{"shutdown", func(t *testing.T, m *managerImpl) {
			if err := m.SaveShardRecords(); err != nil {
				t.Fatal(err)
			}
		}},
		{"reconcile", func(t *testing.T, m *managerImpl) {
			if _, err := m.Reconcile(context.Background(), []string{testSite}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			mgr, ctrl, store := newTestManager(t, defaultManagerConfig())
			if err := mgr.EnsureInfrastructure(ctx, []string{testSite}); err != nil {
				t.Fatal(err)
			}
			m := mgr.(*managerImpl)
			ban := func(ips ...string) {
				t.Helper()
				for _, ip := range ips {
					if err := testutil.PutBan(store, ip, time.Time{}, false); err != nil {
						t.Fatal(err)
					}
					if err := m.ApplyBan(ctx, testSite, ip, false); err != nil {
						t.Fatal(err)
					}
				}
				if err := m.SyncDirty(ctx, []string{testSite}); err != nil {
					t.Fatal(err)
				}
			}
			const name = "crowdsec-block-v4-0"
			ban("198.51.100.1")
			ban("198.51.100.2", "198.51.100.3")
			want := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
			if got := recordMembers(t, store, name); slices.Equal(got, want) {
				t.Fatal("the second sync saved the record; the test needs it to lag")
			}

			tt.save(t, m)
			if got := recordMembers(t, store, name); !slices.Equal(got, want) {
				t.Fatalf("record after the save = %v, want %v", got, want)
			}

			// The controller list loses its members while the bouncer is down.
			rec, _ := store.GetGroup(cacheKey(testSite, name))
			ctrl.SetGroups(testSite, []controller.FirewallGroup{{
				ID: rec.UnifiID, Name: name, GroupType: "address-group", GroupMembers: []string{TMLPlaceholderV4},
			}})
			restarted := NewShardManager(testSite, false, 5, managerTestNamer(t), ctrl, store, zerolog.Nop(), 0, false, "legacy")
			if err := restarted.EnsureShards(ctx); err != nil {
				t.Fatal(err)
			}
			got := restarted.AllMembers()
			slices.Sort(got)
			if !slices.Equal(got, want) {
				t.Errorf("restored members = %v, want %v", got, want)
			}
		})
	}
}
