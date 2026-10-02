package firewall

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// TestEnsureShards_CachedMembersAreCheckedAgainstBanStore: a cached group
// record can be older than the ban database, for instance when the process
// stopped between a rebalance writing the record and the shards being
// flushed. Bans that have since expired or been lifted must not be replayed
// into the shard.
func TestEnsureShards_CachedMembersAreCheckedAgainstBanStore(t *testing.T) {
	const (
		live    = "198.51.100.1"
		expired = "198.51.100.2"
	)
	tests := []struct {
		name     string
		onActive bool // the controller object exists but holds only the placeholder
	}{
		{"controller object holds only the placeholder", true},
		{"controller object is missing", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			ctrl := testutil.NewMockController()
			store := testutil.NewMockStore()
			if err := store.BanRecord(live, time.Time{}, false); err != nil {
				t.Fatal(err)
			}
			record := storage.GroupRecord{Site: testSite, Index: 0, Members: []string{live, expired}}
			if tt.onActive {
				record.UnifiID = "group-0"
				ctrl.SetGroups(testSite, []controller.FirewallGroup{{
					ID: "group-0", Name: "crowdsec-block-v4-0", GroupType: "address-group",
					GroupMembers: []string{TMLPlaceholderV4},
				}})
			}
			if err := store.SetGroup(cacheKey(testSite, "crowdsec-block-v4-0"), record); err != nil {
				t.Fatal(err)
			}

			sm := NewShardManager(testSite, false, 10, testNamer(t), ctrl, store, zerolog.Nop(), 0, false, "legacy")
			if err := sm.EnsureShards(ctx); err != nil {
				t.Fatalf("EnsureShards: %v", err)
			}

			members := sm.AllMembers()
			if !slices.Equal(members, []string{live}) {
				t.Errorf("members = %v, want only %s: %s is no longer banned", members, live, expired)
			}
			if sm.Contains(expired) {
				t.Errorf("ban %s resurrected from the cache", expired)
			}
		})
	}
}
