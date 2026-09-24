package banstate

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

type recordingFirewall struct {
	firewall.Manager
	bans       int
	unbans     int
	banError   error
	unbanError error
}

func (f *recordingFirewall) ApplyBan(context.Context, string, string, bool) error {
	f.bans++
	return f.banError
}

func (f *recordingFirewall) ApplyUnban(context.Context, string, string, bool) error {
	if f.unbanError != nil {
		return f.unbanError
	}
	f.unbans++
	return nil
}

func TestOverlappingBanSources(t *testing.T) {
	for _, tc := range []struct {
		name    string
		sources []string
	}{
		{name: "crowdsec and feed", sources: []string{"crowdsec:id:7", "blocklist:https://feed.example/list"}},
		{name: "two decisions", sources: []string{"crowdsec:id:7", "crowdsec:id:8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store := testutil.NewMockStore()
			fw := &recordingFirewall{}
			manager := New(store, fw, []string{"default"}, false)
			ctx := context.Background()
			for _, source := range tc.sources {
				if _, err := manager.Claim(ctx, "203.0.113.10", false, source, time.Now().Add(time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			if fw.bans != 1 {
				t.Fatalf("firewall bans = %d, want 1", fw.bans)
			}
			if removed, err := manager.Release(ctx, "203.0.113.10", tc.sources[0]); err != nil || removed {
				t.Fatalf("first release removed ban: removed=%v err=%v", removed, err)
			}
			if fw.unbans != 0 {
				t.Fatal("first source release unbanned a still-owned IP")
			}
			if removed, err := manager.Release(ctx, "203.0.113.10", tc.sources[1]); err != nil || !removed {
				t.Fatalf("last release failed: removed=%v err=%v", removed, err)
			}
			if fw.unbans != 1 {
				t.Fatalf("firewall unbans = %d, want 1", fw.unbans)
			}
		})
	}
}

func TestFeedRenewalAndExpiry(t *testing.T) {
	store := testutil.NewMockStore()
	fw := &recordingFirewall{}
	manager := New(store, fw, []string{"default"}, false)
	ctx := context.Background()
	ip := "203.0.113.20"
	if _, err := manager.Claim(ctx, ip, false, "blocklist:feed", time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.Claim(ctx, ip, false, "blocklist:feed", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if removed, err := manager.Expire(ctx, ip); err != nil || removed {
		t.Fatalf("renewed feed was expired: removed=%v err=%v", removed, err)
	}
	if fw.unbans != 0 {
		t.Fatal("renewed feed was removed from firewall")
	}
}

func TestLegacyClaimAndFailedUnban(t *testing.T) {
	store := testutil.NewMockStore()
	if err := store.BanRecord("203.0.113.30", time.Now().Add(time.Hour), false); err != nil {
		t.Fatal(err)
	}
	fw := &recordingFirewall{}
	manager := New(store, fw, []string{"default"}, false)
	ctx := context.Background()
	if _, err := manager.Claim(ctx, "203.0.113.30", false, "crowdsec:id:9", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	fw.unbanError = errors.New("controller unavailable")
	if _, err := manager.Release(ctx, "203.0.113.30", "crowdsec:id:9"); err == nil {
		t.Fatal("expected firewall error")
	}
	entry, err := store.BanGet("203.0.113.30")
	if err != nil || entry == nil {
		t.Fatalf("ban removed after failed unban: entry=%v err=%v", entry, err)
	}
	fw.unbanError = nil
	if removed, err := manager.Release(ctx, "203.0.113.30", "crowdsec:id:9"); err != nil || !removed {
		t.Fatalf("legacy ban survived decision deletion: removed=%v err=%v", removed, err)
	}
	if fw.unbans != 1 {
		t.Fatalf("firewall unbans = %d, want 1", fw.unbans)
	}
}

func TestFailedBanIsRetried(t *testing.T) {
	store := testutil.NewMockStore()
	fw := &recordingFirewall{banError: errors.New("controller unavailable")}
	manager := New(store, fw, []string{"default"}, false)
	ctx := context.Background()
	ip := "203.0.113.40"
	if _, err := manager.Claim(ctx, ip, false, "crowdsec:id:10", time.Now().Add(time.Hour)); err == nil {
		t.Fatal("expected firewall error")
	}
	entry, err := store.BanGet(ip)
	if err != nil || entry == nil || !entry.Pending {
		t.Fatalf("failed ban was not queued: entry=%v err=%v", entry, err)
	}
	fw.banError = nil
	if _, err := manager.Claim(ctx, ip, false, "crowdsec:id:10", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	entry, err = store.BanGet(ip)
	if err != nil || entry == nil || entry.Pending || fw.bans != 2 {
		t.Fatalf("ban was not retried: entry=%v attempts=%d err=%v", entry, fw.bans, err)
	}
}

func TestManualUnbanWithoutStoredClaim(t *testing.T) {
	fw := &recordingFirewall{}
	manager := New(testutil.NewMockStore(), fw, []string{"default"}, false)
	if removed, err := manager.ReleaseAll(context.Background(), "203.0.113.50", false); err != nil || removed {
		t.Fatalf("unban failed: removed=%v err=%v", removed, err)
	}
	if fw.unbans != 1 {
		t.Fatalf("firewall unbans = %d, want 1", fw.unbans)
	}
}
