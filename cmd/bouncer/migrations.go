package main

import (
	"fmt"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/blocklist"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// Names under which data migrations are recorded in the database. A
// recorded name is never run again, so a name must not be reused for a
// different conversion.
const (
	migrationClaimLegacyBans    = "claim-1x-bans"
	migrationScopeCacheKeys     = "site-scoped-cache-keys"
	migrationBlocklistSources   = "blocklist-claim-sources"
	migrationRetireLegacyClaims = "retire-1x-ban-claims"
)

// dataMigration converts data written by an earlier release into the form
// this release reads. It runs once per database.
type dataMigration struct {
	name string
	run  func(storage.Store) error
}

// startupMigrations lists the migrations to run, in order, when the
// database is opened and before anything else reads it.
func startupMigrations(cfg *config.Config, log zerolog.Logger) []dataMigration {
	return []dataMigration{
		{name: migrationClaimLegacyBans, run: func(store storage.Store) error {
			n, err := banstate.ClaimLegacyBans(store)
			if n > 0 {
				log.Info().Int("bans", n).Msg("gave bans stored by 1.x a legacy claim that ends with the ban")
			}
			return err
		}},
		{name: migrationScopeCacheKeys, run: func(store storage.Store) error {
			n, err := firewall.MigrateCacheKeys(store)
			if n > 0 {
				log.Info().Int("records", n).Msg("moved group and policy records to site-scoped keys")
			}
			return err
		}},
		{name: migrationBlocklistSources, run: func(store storage.Store) error {
			return blocklist.MigrateLegacySources(store, configuredFeeds(cfg))
		}},
	}
}

// runMigrations runs each migration not yet recorded in store and records
// it. It stops at the first failure; the failed migration and the ones
// after it run again on the next start.
func runMigrations(store storage.Store, migrations []dataMigration) error {
	for _, m := range migrations {
		if err := runMigration(store, m); err != nil {
			return err
		}
	}
	return nil
}

func runMigration(store storage.Store, m dataMigration) error {
	done, err := store.MigrationApplied(m.name)
	if err != nil {
		return fmt.Errorf("check migration %s: %w", m.name, err)
	}
	if done {
		return nil
	}
	if err := m.run(store); err != nil {
		return fmt.Errorf("migration %s: %w", m.name, err)
	}
	if err := store.RecordMigration(m.name); err != nil {
		return fmt.Errorf("record migration %s: %w", m.name, err)
	}
	return nil
}

// retireLegacyClaims returns a callback for Bouncer.OnStartupSynced that
// drops the legacy claim of each 1.x ban a CrowdSec decision has claimed
// again. It must run after the first decision batch: only then has every
// active decision claimed its ban.
func retireLegacyClaims(store storage.Store, claims *banstate.Manager, log zerolog.Logger) func() {
	return func() {
		err := runMigration(store, dataMigration{name: migrationRetireLegacyClaims, run: func(storage.Store) error {
			n, err := claims.RetireLegacyClaims()
			if n > 0 {
				log.Info().Int("bans", n).Msg("dropped the legacy claim of 1.x bans that a CrowdSec decision now claims")
			}
			return err
		}})
		if err != nil {
			log.Warn().Err(err).Msg("failed to retire 1.x ban claims; retrying on the next start")
		}
	}
}

// configuredFeeds returns the blocklist feeds the configuration enables.
func configuredFeeds(cfg *config.Config) []blocklist.Feed {
	feeds := blocklist.PlainFeeds(cfg.BlocklistURLs)
	if feed := abuseIPDBFeed(cfg); feed.URL != "" {
		feeds = append(feeds, feed)
	}
	return feeds
}
