package firewall

import (
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

func TestPolicyCacheSeparatesSites(t *testing.T) {
	store := newBboltStore(t)
	name := "crowdsec-drop-v4-0"
	for _, tc := range []struct{ site, id string }{{"site-a", "rule-a"}, {"site-b", "rule-b"}} {
		if err := setCachedPolicy(store, tc.site, name, storage.PolicyRecord{Site: tc.site, UnifiID: tc.id}); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct{ site, id string }{{"site-a", "rule-a"}, {"site-b", "rule-b"}} {
		rec, err := getCachedPolicy(store, tc.site, name)
		if err != nil || rec == nil || rec.UnifiID != tc.id {
			t.Fatalf("%s policy: %+v, %v", tc.site, rec, err)
		}
	}
	if err := deleteCachedPolicy(store, "site-a", name); err != nil {
		t.Fatal(err)
	}
	rec, err := getCachedPolicy(store, "site-b", name)
	if err != nil || rec == nil || rec.UnifiID != "rule-b" {
		t.Fatalf("other site's policy was removed: %+v, %v", rec, err)
	}
}

func TestPolicyCacheIgnoresBareNameKey(t *testing.T) {
	store := newBboltStore(t)
	name := "crowdsec-drop-v4-0"
	if err := store.SetPolicy(name, storage.PolicyRecord{Site: "site-a", UnifiID: "rule-a"}); err != nil {
		t.Fatal(err)
	}
	rec, err := getCachedPolicy(store, "site-a", name)
	if err != nil || rec != nil {
		t.Fatalf("bare-name policy record was read: %+v, %v", rec, err)
	}
}

func TestMigrateCacheKeys(t *testing.T) {
	store := newBboltStore(t)
	groupName := "crowdsec-block-v4-0"
	policyName := "crowdsec-drop-v4-0"
	mustSetGroup(t, store, groupName, storage.GroupRecord{Site: "site-a", UnifiID: "group-a", Members: []string{"192.0.2.1"}})
	mustSetGroup(t, store, "crowdsec-block-v4-1", storage.GroupRecord{Site: "site-a", UnifiID: "group-old"})
	mustSetGroup(t, store, cacheKey("site-a", "crowdsec-block-v4-1"), storage.GroupRecord{Site: "site-a", UnifiID: "group-new"})
	mustSetGroup(t, store, "orphan", storage.GroupRecord{UnifiID: "group-orphan"})
	if err := store.SetPolicy(policyName, storage.PolicyRecord{Site: "site-b", UnifiID: "rule-b", Mode: "legacy"}); err != nil {
		t.Fatal(err)
	}

	moved, err := MigrateCacheKeys(store)
	if err != nil {
		t.Fatal(err)
	}
	if moved != 3 {
		t.Fatalf("moved = %d, want 3", moved)
	}
	groups, err := store.ListGroups()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		cacheKey("site-a", groupName):             "group-a",
		cacheKey("site-a", "crowdsec-block-v4-1"): "group-new",
		"orphan": "group-orphan",
	}
	if len(groups) != len(want) {
		t.Fatalf("groups = %+v, want keys %v", groups, want)
	}
	for key, id := range want {
		if groups[key].UnifiID != id {
			t.Fatalf("group %q = %+v, want %s", key, groups[key], id)
		}
	}
	if members := groups[cacheKey("site-a", groupName)].Members; len(members) != 1 || members[0] != "192.0.2.1" {
		t.Fatalf("migrated members = %v", members)
	}
	if rec, err := getCachedPolicy(store, "site-b", policyName); err != nil || rec == nil || rec.UnifiID != "rule-b" {
		t.Fatalf("migrated policy = %+v, %v", rec, err)
	}
	if rec, err := store.GetPolicy(policyName); err != nil || rec != nil {
		t.Fatalf("bare-name policy remains: %+v, %v", rec, err)
	}

	again, err := MigrateCacheKeys(store)
	if err != nil || again != 0 {
		t.Fatalf("second run moved %d, %v; want 0", again, err)
	}
}

func mustSetGroup(t *testing.T, store storage.Store, key string, rec storage.GroupRecord) {
	t.Helper()
	if err := store.SetGroup(key, rec); err != nil {
		t.Fatal(err)
	}
}
