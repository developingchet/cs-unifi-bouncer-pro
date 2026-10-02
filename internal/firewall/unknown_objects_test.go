package firewall

import (
	"bytes"
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// TestEnsureShards_ReportsObjectsTheStoreDoesNotKnow: groups named like this
// instance's own that its database has no record of usually mean another
// bouncer instance on the same site uses the same name templates.
func TestEnsureShards_ReportsObjectsTheStoreDoesNotKnow(t *testing.T) {
	ctx := context.Background()
	ctrl := testutil.NewMockController()
	store := testutil.NewMockStore()
	ctrl.SetGroups(testSite, []controller.FirewallGroup{
		{ID: "g0", Name: "crowdsec-block-v4-0", GroupType: "address-group", GroupMembers: []string{"198.51.100.1"}},
		{ID: "g1", Name: "crowdsec-block-v4-1", GroupType: "address-group", GroupMembers: []string{"198.51.100.2"}},
		{ID: "other", Name: "unrelated-group", GroupType: "address-group", GroupMembers: []string{"198.51.100.3"}},
	})
	if err := store.SetGroup(cacheKey(testSite, "crowdsec-block-v4-0"),
		storage.GroupRecord{UnifiID: "g0", Site: testSite, Members: []string{"198.51.100.1"}}); err != nil {
		t.Fatal(err)
	}
	sm := newV4ShardManager(t, 10, ctrl, store)
	if err := sm.EnsureShards(ctx); err != nil {
		t.Fatalf("EnsureShards: %v", err)
	}

	got := sm.TakeUnknownObjects()
	if want := []string{"crowdsec-block-v4-1"}; !slices.Equal(got, want) {
		t.Errorf("unknown objects = %v, want %v", got, want)
	}
	if again := sm.TakeUnknownObjects(); len(again) != 0 {
		t.Errorf("unknown objects were not cleared by taking them: %v", again)
	}
}

func TestLoadInfrastructureWarnsAboutObjectsTheStoreDoesNotKnow(t *testing.T) {
	ctrl := testutil.NewMockController()
	ctrl.SetGroups(testSite, []controller.FirewallGroup{
		{ID: "g0", Name: "crowdsec-block-v4-0", GroupType: "address-group", GroupMembers: []string{"198.51.100.1"}},
	})
	var logs bytes.Buffer
	mgr := NewManager(defaultManagerConfig(), ctrl, testutil.NewMockStore(), managerTestNamer(t), zerolog.New(&logs))

	if err := mgr.LoadInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "database has no record of") || !strings.Contains(out, "crowdsec-block-v4-0") {
		t.Errorf("log output %q lacks the warning about unrecorded objects", out)
	}
}
