package banstate

import (
	"slices"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

func TestDropUnbannable(t *testing.T) {
	store := testutil.NewMockStore()
	claim := map[string]time.Time{"crowdsec:id:1": time.Now().Add(time.Hour)}
	for key, v6 := range map[string]bool{
		"203.0.113.5":     false, // whitelisted after it was banned
		"198.51.100.7":    false, // still bannable
		"10.1.2.3":        false, // private
		"32.0.0.0/3":      false, // broader than /8
		"2000::/3":        true,  // broader than /32
		"2001:db8:1::/48": true,  // still bannable
	} {
		if err := store.BanPut(key, storage.BanEntry{IPv6: v6, Claims: claim}); err != nil {
			t.Fatal(err)
		}
	}
	whitelist, err := decision.ParseWhitelist([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	dropped, err := DropUnbannable(store, whitelist)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"10.1.2.3", "2000::/3", "203.0.113.5", "32.0.0.0/3"}
	if !slices.Equal(dropped, want) {
		t.Fatalf("dropped %v, want %v", dropped, want)
	}
	bans, err := store.BanList()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 2 {
		t.Fatalf("kept %d bans, want 2: %v", len(bans), bans)
	}
	for _, key := range []string{"198.51.100.7", "2001:db8:1::/48"} {
		if _, ok := bans[key]; !ok {
			t.Errorf("%s dropped", key)
		}
	}
}
