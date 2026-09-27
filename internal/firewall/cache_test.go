package firewall

import (
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

func TestPolicyCacheSeparatesSitesAndMigratesOldKey(t *testing.T) {
	store := newBboltStore(t)
	name := "crowdsec-drop-v4-0"
	if err := store.SetPolicy(name, storage.PolicyRecord{Site: "site-a", UnifiID: "rule-a"}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ site, id string }{{"site-a", "rule-a"}, {"site-b", "rule-b"}} {
		if tc.site == "site-b" {
			if err := setCachedPolicy(store, tc.site, name, storage.PolicyRecord{Site: tc.site, UnifiID: tc.id}); err != nil {
				t.Fatal(err)
			}
		}
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
