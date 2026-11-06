package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

const (
	upgradeFeedURL  = "https://feed.example/list"
	upgradeSite     = "default"
	upgradeGroup    = "crowdsec-block-v4-0"
	upgradePolicy   = "crowdsec-drop-v4-0"
	decidedBan      = "203.0.113.30" // 1.x ban whose decision is still active
	undecidedBan    = "203.0.113.31" // 1.x ban with no active decision
	hostPrefixBan   = "198.51.100.7"
	feedBan         = "192.0.2.50"
	upgradeDecision = "crowdsec:id:9"
)

// seed1xDatabase writes a ban database as 1.x left it: bans without claims,
// one keyed as a host prefix, a blocklist claim keyed by URL, and group and
// policy records keyed by bare name.
func seed1xDatabase(t *testing.T, dir string, expiry time.Time) {
	t.Helper()
	store, err := storage.NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	bans := map[string]storage.BanEntry{
		decidedBan:            {ExpiresAt: expiry},
		undecidedBan:          {ExpiresAt: expiry},
		hostPrefixBan + "/32": {ExpiresAt: expiry},
		feedBan: {ExpiresAt: expiry, Claims: map[string]time.Time{
			"blocklist:" + upgradeFeedURL: expiry}},
	}
	if err := store.BanPutMany(bans); err != nil {
		t.Fatal(err)
	}
	if err := store.SetGroup(upgradeGroup, storage.GroupRecord{UnifiID: "group-1", Site: upgradeSite, Members: []string{decidedBan}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetPolicy(upgradePolicy, storage.PolicyRecord{UnifiID: "rule-1", Site: upgradeSite, Mode: "legacy"}); err != nil {
		t.Fatal(err)
	}
}

func upgradeConfig(dir string) *config.Config {
	return &config.Config{DataDir: dir, BlocklistURLs: []string{upgradeFeedURL}, UnifiSites: []string{upgradeSite}}
}

type unbanRecorder struct {
	firewall.Manager
	unbanned []string
}

func (f *unbanRecorder) ApplyBan(context.Context, string, string, bool) error { return nil }

func (f *unbanRecorder) ApplyUnban(_ context.Context, _, ip string, _ bool) error {
	f.unbanned = append(f.unbanned, ip)
	return nil
}

func TestUpgradeFrom1x(t *testing.T) {
	dir := t.TempDir()
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	seed1xDatabase(t, dir, expiry)

	store, err := openStore(upgradeConfig(dir), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	for _, ip := range []string{decidedBan, undecidedBan, hostPrefixBan} {
		entry, err := store.BanGet(ip)
		if err != nil || entry == nil || len(entry.Claims) != 1 || !entry.Claims[banstate.LegacyClaim].Equal(expiry) {
			t.Fatalf("%s after upgrade = %+v, %v; want a legacy claim ending %v", ip, entry, err, expiry)
		}
	}
	feedKey := fmt.Sprintf("blocklist:sha256:%x", sha256.Sum256([]byte(upgradeFeedURL)))
	if entry, err := store.BanGet(feedBan); err != nil || entry == nil || !entry.Claims[feedKey].Equal(expiry) || len(entry.Claims) != 1 {
		t.Fatalf("feed ban after upgrade = %+v, %v; want claim %s", entry, err, feedKey)
	}
	if rec, err := store.GetGroup(upgradeSite + "\x00" + upgradeGroup); err != nil || rec == nil || rec.UnifiID != "group-1" {
		t.Fatalf("group record after upgrade = %+v, %v", rec, err)
	}
	if rec, err := store.GetPolicy(upgradeSite + "\x00" + upgradePolicy); err != nil || rec == nil || rec.UnifiID != "rule-1" {
		t.Fatalf("policy record after upgrade = %+v, %v", rec, err)
	}

	// The first LAPI batch claims the bans of active decisions; deleting
	// such a decision must then lift its 1.x ban.
	fw := &unbanRecorder{}
	claims := banstate.New(store, fw, []string{upgradeSite}, false)
	ctx := context.Background()
	if _, err := claims.Claim(ctx, decidedBan, false, upgradeDecision, expiry); err != nil {
		t.Fatal(err)
	}
	retireLegacyClaims(store, claims, zerolog.Nop())()
	if removed, err := claims.Release(ctx, decidedBan, upgradeDecision); err != nil || !removed {
		t.Fatalf("decision deletion left the 1.x ban: removed=%v err=%v", removed, err)
	}
	if entry, err := store.BanGet(undecidedBan); err != nil || entry == nil || entry.Claims[banstate.LegacyClaim].IsZero() {
		t.Fatalf("1.x ban without a decision lost its claim: %+v, %v", entry, err)
	}
	if len(fw.unbanned) != 1 || fw.unbanned[0] != decidedBan {
		t.Fatalf("unbanned = %v, want [%s]", fw.unbanned, decidedBan)
	}
	for _, name := range []string{migrationClaimLegacyBans, migrationScopeCacheKeys, migrationBlocklistSources, migrationRetireLegacyClaims} {
		if done, err := store.MigrationApplied(name); err != nil || !done {
			t.Fatalf("migration %s recorded = %v, %v", name, done, err)
		}
	}
}

func TestMigrationsRunOnce(t *testing.T) {
	dir := t.TempDir()
	seed1xDatabase(t, dir, time.Now().Add(time.Hour))
	store, err := openStore(upgradeConfig(dir), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	// Records written after the migrations ran are left alone on the next start.
	if err := store.BanPut("203.0.113.99", storage.BanEntry{ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetGroup("crowdsec-block-v4-9", storage.GroupRecord{UnifiID: "group-9", Site: upgradeSite}); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = openStore(upgradeConfig(dir), zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if entry, err := store.BanGet("203.0.113.99"); err != nil || entry == nil || entry.Claims != nil {
		t.Fatalf("claim migration ran again: %+v, %v", entry, err)
	}
	if rec, err := store.GetGroup("crowdsec-block-v4-9"); err != nil || rec == nil {
		t.Fatalf("cache key migration ran again: %+v, %v", rec, err)
	}
}

func TestFailedMigrationRunsAgain(t *testing.T) {
	store := testutil.NewMockStore()
	runs := 0
	failing := []dataMigration{{name: "example", run: func(storage.Store) error {
		runs++
		if runs == 1 {
			return errors.New("disk full")
		}
		return nil
	}}}
	if err := runMigrations(store, failing); err == nil {
		t.Fatal("expected the migration error")
	}
	if done, _ := store.MigrationApplied("example"); done {
		t.Fatal("failed migration was recorded")
	}
	for range 2 {
		if err := runMigrations(store, failing); err != nil {
			t.Fatal(err)
		}
	}
	if runs != 2 {
		t.Fatalf("runs = %d, want 2", runs)
	}
}

func TestDryRunSkipsMigrations(t *testing.T) {
	dir := t.TempDir()
	seed1xDatabase(t, dir, time.Now().Add(time.Hour))
	cfg := upgradeConfig(dir)
	cfg.DryRun = true
	store, err := openStore(cfg, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if done, err := store.MigrationApplied(migrationClaimLegacyBans); err != nil || done {
		t.Fatalf("dry run recorded a migration: %v, %v", done, err)
	}
	if entry, err := store.BanGet(decidedBan); err != nil || entry == nil || entry.Claims != nil {
		t.Fatalf("dry run changed a 1.x ban: %+v, %v", entry, err)
	}
}
