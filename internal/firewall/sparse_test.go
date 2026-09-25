package firewall

import (
	"context"
	"fmt"
	"sort"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func tmlWith(id, name string, ips ...string) controller.TrafficMatchingList {
	items := make([]controller.TrafficMatchingListItem, 0, len(ips))
	for _, ip := range ips {
		items = append(items, controller.TrafficMatchingListItem{Type: "IP_ADDRESS", Value: ip})
	}
	return controller.TrafficMatchingList{ID: id, Name: name, Type: "IPV4_ADDRESSES", Items: items}
}

// TestSparseShards_NewShardNeverReusesAnIndex reproduces a production state
// where shard v4-1 is missing and the rest are full. Releases up to v1.2.5
// numbered a new shard len(shards), which collided with an existing name
// (crowdsec-block-v4-8), so every create failed and the overflowing bans were
// never enforced. New shards must take the next unused index, and every shard,
// including those past the gap, must get a block policy.
func TestSparseShards_NewShardNeverReusesAnIndex(t *testing.T) {
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	ctrl.SetTMLs(testSite, []controller.TrafficMatchingList{
		tmlWith("tml-0", "crowdsec-block-v4-0", "198.51.100.1", "198.51.100.2", "198.51.100.3"),
		tmlWith("tml-2", "crowdsec-block-v4-2", "198.51.100.4", "198.51.100.5", "198.51.100.6"),
		tmlWith("tml-3", "crowdsec-block-v4-3", "198.51.100.7", "198.51.100.8", "198.51.100.9"),
	})
	sm := NewShardManager(testSite, false, 3, zoneTestNamer(t), ctrl, store, zerolog.Nop(), 0, nil, false, "zone")
	if err := sm.EnsureShards(ctx); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	for i := 1; i <= 4; i++ {
		if _, _, err := sm.Add(ctx, fmt.Sprintf("203.0.113.%d", i)); err != nil {
			t.Fatalf("Add: %v", err)
		}
	}
	if err := sm.FlushDirty(ctx); err != nil {
		t.Fatalf("FlushDirty: %v", err)
	}

	tmls, _ := ctrl.ListTrafficMatchingLists(ctx, testSite)
	var names []string
	seen := map[string]bool{}
	for _, tml := range tmls {
		if seen[tml.Name] {
			t.Errorf("duplicate shard object %s", tml.Name)
		}
		seen[tml.Name] = true
		names = append(names, tml.Name)
	}
	sort.Strings(names)
	want := []string{"crowdsec-block-v4-0", "crowdsec-block-v4-2", "crowdsec-block-v4-3", "crowdsec-block-v4-4", "crowdsec-block-v4-5"}
	if fmt.Sprint(names) != fmt.Sprint(want) {
		t.Fatalf("shard objects = %v, want %v", names, want)
	}

	zm := newTestZoneManager(ctrl, store, zoneTestNamer(t))
	if err := zm.Bootstrap(ctx, []string{testSite}); err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	if err := zm.EnsurePolicies(ctx, testSite, sm, nil); err != nil {
		t.Fatalf("EnsurePolicies: %v", err)
	}
	policies, _ := ctrl.ListZonePolicies(ctx, testSite)
	covered := map[string]bool{}
	for _, p := range policies {
		covered[p.TrafficMatchingListIDs[0]] = true
	}
	for _, tml := range tmls {
		if !covered[tml.ID] {
			t.Errorf("shard %s has no block policy", tml.Name)
		}
	}
}

// emptyIDController answers every TML create with success but no ID, as a
// controller does when the name is already taken.
type emptyIDController struct{ *testutil.MockController }

func (c emptyIDController) CreateTrafficMatchingList(context.Context, string, controller.TrafficMatchingList) (controller.TrafficMatchingList, error) {
	return controller.TrafficMatchingList{}, nil
}

func TestCreateShardObject_EmptyIDAdoptsExisting(t *testing.T) {
	tests := []struct {
		name    string
		listed  []controller.TrafficMatchingList
		wantID  string
		wantErr bool
	}{
		{name: "name taken: adopted", listed: []controller.TrafficMatchingList{tmlWith("existing", "crowdsec-block-v4-0")}, wantID: "existing"},
		{name: "nothing listed: error", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := testutil.NewMockController()
			mock.SetTMLs(testSite, tt.listed)
			sm := NewShardManager(testSite, false, 3, zoneTestNamer(t), emptyIDController{mock}, testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "zone")
			id, err := sm.doCreateUniFiGroup(context.Background(), "crowdsec-block-v4-0")
			if (err != nil) != tt.wantErr || id != tt.wantID {
				t.Fatalf("doCreateUniFiGroup = %q, %v; want %q, err %v", id, err, tt.wantID, tt.wantErr)
			}
		})
	}
}
