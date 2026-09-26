package banstate

import (
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

func TestCanonicalizeHostPrefixes(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	store := testutil.NewMockStore()
	put := func(key string, entry storage.BanEntry) {
		t.Helper()
		if err := store.BanPut(key, entry); err != nil {
			t.Fatal(err)
		}
	}
	// Same address stored both ways: claims must merge.
	put("203.0.113.9/32", storage.BanEntry{RecordedAt: now.Add(-time.Hour), Pending: true,
		Claims: map[string]time.Time{"crowdsec:id:1": now.Add(2 * time.Hour), "shared": now.Add(time.Hour)}})
	put("203.0.113.9", storage.BanEntry{RecordedAt: now,
		Claims: map[string]time.Time{"crowdsec:id:2": now.Add(time.Hour), "shared": now.Add(3 * time.Hour)}})
	// Host prefix only.
	put("2001:db8::1/128", storage.BanEntry{RecordedAt: now, IPv6: true,
		Claims: map[string]time.Time{"crowdsec:id:3": now.Add(time.Hour)}})
	// Untouched.
	put("198.51.100.0/24", storage.BanEntry{RecordedAt: now,
		Claims: map[string]time.Time{"crowdsec:id:4": now.Add(time.Hour)}})

	n, err := CanonicalizeHostPrefixes(store)
	if err != nil || n != 2 {
		t.Fatalf("CanonicalizeHostPrefixes = %d, %v; want 2", n, err)
	}
	bans, err := store.BanList()
	if err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"203.0.113.9/32", "2001:db8::1/128"} {
		if _, ok := bans[gone]; ok {
			t.Errorf("%s still stored", gone)
		}
	}
	v4 := bans["203.0.113.9"]
	if len(v4.Claims) != 3 || !v4.Claims["shared"].Equal(now.Add(3*time.Hour)) {
		t.Errorf("merged claims = %v", v4.Claims)
	}
	if !v4.Pending || !v4.RecordedAt.Equal(now.Add(-time.Hour)) || !v4.ExpiresAt.Equal(now.Add(3*time.Hour)) {
		t.Errorf("merged entry = %+v", v4)
	}
	if v6, ok := bans["2001:db8::1"]; !ok || !v6.IPv6 {
		t.Errorf("IPv6 host prefix not rekeyed: %+v", bans)
	}
	if _, ok := bans["198.51.100.0/24"]; !ok {
		t.Error("range entry was touched")
	}

	if n, err := CanonicalizeHostPrefixes(store); err != nil || n != 0 {
		t.Fatalf("second run = %d, %v; want 0", n, err)
	}
}
