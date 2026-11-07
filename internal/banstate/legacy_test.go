package banstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

func TestClaimLegacyBans(t *testing.T) {
	store := testutil.NewMockStore()
	expiry := time.Now().Add(time.Hour).UTC()
	if err := store.BanPut("203.0.113.30", storage.BanEntry{ExpiresAt: expiry}); err != nil {
		t.Fatal(err)
	}
	if err := testutil.PutBan(store, "203.0.113.31", expiry, false); err != nil {
		t.Fatal(err)
	}
	changed, err := ClaimLegacyBans(store)
	if err != nil || changed != 1 {
		t.Fatalf("ClaimLegacyBans = %d, %v; want 1", changed, err)
	}
	entry, err := store.BanGet("203.0.113.30")
	if err != nil || entry == nil || len(entry.Claims) != 1 || !entry.Claims[LegacyClaim].Equal(expiry) {
		t.Fatalf("1.x ban = %+v, %v; want one legacy claim ending %v", entry, err, expiry)
	}
	entry, err = store.BanGet("203.0.113.31")
	if err != nil || entry == nil || len(entry.Claims) != 1 || !entry.Claims[testutil.BanSource].Equal(expiry) {
		t.Fatalf("claimed ban changed: %+v, %v", entry, err)
	}
	if changed, err := ClaimLegacyBans(store); err != nil || changed != 0 {
		t.Fatalf("second run = %d, %v; want 0", changed, err)
	}
}

func TestReleaseIgnoresBanWithoutClaims(t *testing.T) {
	store := testutil.NewMockStore()
	if err := store.BanPut("203.0.113.32", storage.BanEntry{ExpiresAt: time.Now().Add(-time.Minute)}); err != nil {
		t.Fatal(err)
	}
	fw := &recordingFirewall{}
	manager := New(store, fw, []string{"default"}, false)
	if removed, err := manager.Release(context.Background(), "203.0.113.32", "crowdsec:id:9"); err != nil || removed {
		t.Fatalf("release of an unclaimed source removed the ban: removed=%v err=%v", removed, err)
	}
	if fw.unbans != 0 {
		t.Fatal("release of an unclaimed source unbanned the IP")
	}
}

// A 1.x ban whose decision the first LAPI batch claims again is lifted when
// that decision is deleted, even after a failed unban attempt.
func TestRetiredLegacyClaimLetsDecisionLiftBan(t *testing.T) {
	store := testutil.NewMockStore()
	ip := "203.0.113.30"
	if err := store.BanPut(ip, storage.BanEntry{ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := ClaimLegacyBans(store); err != nil {
		t.Fatal(err)
	}
	fw := &recordingFirewall{}
	manager := New(store, fw, []string{"default"}, false)
	ctx := context.Background()
	if _, err := manager.Claim(ctx, ip, false, "crowdsec:id:9", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if retired, err := manager.RetireLegacyClaims(); err != nil || retired != 1 {
		t.Fatalf("RetireLegacyClaims = %d, %v; want 1", retired, err)
	}
	fw.unbanError = errors.New("controller unavailable")
	if _, err := manager.Release(ctx, ip, "crowdsec:id:9"); err == nil {
		t.Fatal("expected firewall error")
	}
	if entry, err := store.BanGet(ip); err != nil || entry == nil {
		t.Fatalf("ban removed after failed unban: entry=%v err=%v", entry, err)
	}
	fw.unbanError = nil
	if removed, err := manager.Release(ctx, ip, "crowdsec:id:9"); err != nil || !removed {
		t.Fatalf("1.x ban survived decision deletion: removed=%v err=%v", removed, err)
	}
	if fw.unbans != 1 {
		t.Fatalf("firewall unbans = %d, want 1", fw.unbans)
	}
}

func TestRetireLegacyClaimsKeepsUnclaimedBans(t *testing.T) {
	store := testutil.NewMockStore()
	expiry := time.Now().Add(time.Hour).UTC()
	bans := map[string]storage.BanEntry{
		"203.0.113.40": {ExpiresAt: expiry, Claims: map[string]time.Time{LegacyClaim: expiry}},
		"203.0.113.41": {ExpiresAt: expiry, Claims: map[string]time.Time{
			LegacyClaim: expiry, "blocklist:sha256:abc": expiry.Add(time.Hour)}},
		"203.0.113.42": {ExpiresAt: expiry, Claims: map[string]time.Time{
			LegacyClaim: expiry, "crowdsec:id:1": time.Now().Add(-time.Minute)}},
	}
	if err := store.BanPutMany(bans); err != nil {
		t.Fatal(err)
	}
	manager := New(store, &recordingFirewall{}, []string{"default"}, false)
	if retired, err := manager.RetireLegacyClaims(); err != nil || retired != 0 {
		t.Fatalf("RetireLegacyClaims = %d, %v; want 0", retired, err)
	}
	for ip := range bans {
		entry, err := store.BanGet(ip)
		if err != nil || entry == nil {
			t.Fatalf("%s: %+v, %v", ip, entry, err)
		}
		if _, ok := entry.Claims[LegacyClaim]; !ok {
			t.Fatalf("%s lost its legacy claim without an active decision: %+v", ip, entry.Claims)
		}
	}
}

func TestRetireLegacyClaimsUpdatesExpiry(t *testing.T) {
	store := testutil.NewMockStore()
	legacyExpiry := time.Now().Add(48 * time.Hour).UTC()
	decisionExpiry := time.Now().Add(time.Hour).UTC()
	if err := store.BanPut("203.0.113.50", storage.BanEntry{ExpiresAt: legacyExpiry, Claims: map[string]time.Time{
		LegacyClaim: legacyExpiry, "crowdsec:id:5": decisionExpiry}}); err != nil {
		t.Fatal(err)
	}
	manager := New(store, &recordingFirewall{}, []string{"default"}, false)
	if _, err := manager.RetireLegacyClaims(); err != nil {
		t.Fatal(err)
	}
	entry, err := store.BanGet("203.0.113.50")
	if err != nil || entry == nil || len(entry.Claims) != 1 || !entry.ExpiresAt.Equal(decisionExpiry) {
		t.Fatalf("entry = %+v, %v; want only the decision claim, expiring %v", entry, err, decisionExpiry)
	}
}
