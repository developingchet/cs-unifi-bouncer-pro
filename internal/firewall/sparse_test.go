package firewall

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

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

// TestAdd_ReportsEachNewShardOnce verifies that concurrent adds report every
// allocated shard exactly once, so its policy or rule is provisioned once.
func TestAdd_ReportsEachNewShardOnce(t *testing.T) {
	sm := NewShardManager(testSite, false, 3, zoneTestNamer(t), testutil.NewMockController(), testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "zone")
	if err := sm.EnsureShards(context.Background()); err != nil {
		t.Fatal(err)
	}
	const adds = 60
	reported := make(chan int, adds)
	var wg sync.WaitGroup
	for i := range adds {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, idx, err := sm.Add(context.Background(), fmt.Sprintf("203.0.113.%d", i+1))
			if err != nil {
				t.Error(err)
			}
			if idx >= 0 {
				reported <- idx
			}
		}()
	}
	wg.Wait()
	close(reported)
	seen := map[int]int{}
	for idx := range reported {
		seen[idx]++
	}
	sm.mu.RLock()
	shards := len(sm.fam.Shards)
	sm.mu.RUnlock()
	if len(seen) != shards {
		t.Errorf("reported %d new shards, allocated %d", len(seen), shards)
	}
	for idx, n := range seen {
		if n != 1 {
			t.Errorf("shard %d reported as new %d times", idx, n)
		}
	}
}

// TestCreateShardObject_RefusedCreateAdoptsExisting covers controllers that
// reject a duplicate name with a plain 4xx instead of a conflict: the existing
// object is adopted instead of retrying the create forever. A rate-limited
// create is not followed by a lookup.
func TestCreateShardObject_RefusedCreateAdoptsExisting(t *testing.T) {
	tests := []struct {
		name       string
		createErr  error
		listed     []controller.TrafficMatchingList
		wantID     string
		wantErr    bool
		wantLookup bool
	}{
		{
			name:      "duplicate name as HTTP 400: adopted",
			createErr: errors.New("UniFi API returned HTTP 400: name already in use"), wantLookup: true,
			listed: []controller.TrafficMatchingList{tmlWith("existing", "crowdsec-block-v4-0")}, wantID: "existing",
		},
		{
			name:      "refused and nothing listed: create error kept",
			createErr: errors.New("UniFi API returned HTTP 422: too many lists"), wantLookup: true, wantErr: true,
		},
		{
			name:      "rate limited: no lookup",
			createErr: &controller.ErrRateLimit{RetryAfter: time.Second}, wantErr: true,
			listed: []controller.TrafficMatchingList{tmlWith("existing", "crowdsec-block-v4-0")},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := testutil.NewMockController()
			mock.SetTMLs(testSite, tt.listed)
			mock.SetError("CreateTrafficMatchingList", tt.createErr)
			sm := NewShardManager(testSite, false, 3, zoneTestNamer(t), mock, testutil.NewMockStore(), zerolog.Nop(), 0, nil, false, "zone")
			id, err := sm.doCreateUniFiGroup(context.Background(), "crowdsec-block-v4-0")
			if (err != nil) != tt.wantErr || id != tt.wantID {
				t.Fatalf("doCreateUniFiGroup = %q, %v; want %q, err %v", id, err, tt.wantID, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, tt.createErr) {
				t.Errorf("error %v does not wrap the create error", err)
			}
			if got := mock.Calls("ListTrafficMatchingLists") > 0; got != tt.wantLookup {
				t.Errorf("looked up existing object = %v, want %v", got, tt.wantLookup)
			}
		})
	}
}
