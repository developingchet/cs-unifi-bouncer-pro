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

// convertLegacyData converts data written by 1.x into the form this release
// reads. It runs every time the database is opened, before anything else
// reads it: 1.x can write to the database again after a rollback, and each
// conversion finds nothing to change in data this release wrote.
func convertLegacyData(store storage.Store, cfg *config.Config, log zerolog.Logger) error {
	claimed, err := banstate.ClaimLegacyBans(store)
	if err != nil {
		return fmt.Errorf("claim 1.x bans: %w", err)
	}
	if claimed > 0 {
		log.Info().Int("bans", claimed).Msg("gave bans stored by 1.x a legacy claim that ends with the ban")
	}
	moved, err := firewall.MigrateCacheKeys(store)
	if err != nil {
		return fmt.Errorf("move cache records to site-scoped keys: %w", err)
	}
	if moved > 0 {
		log.Info().Int("records", moved).Msg("moved group and policy records to site-scoped keys")
	}
	if err := blocklist.MigrateLegacySources(store, configuredFeeds(cfg)); err != nil {
		return fmt.Errorf("rekey blocklist claims: %w", err)
	}
	return nil
}

// retireLegacyClaims returns a callback for Bouncer.OnStartupSynced that
// drops the legacy claim of each 1.x ban a CrowdSec decision has claimed
// again. It must run after the first decision batch: only then has every
// active decision claimed its ban. It finds nothing to drop once no ban
// holds a legacy claim.
func retireLegacyClaims(claims *banstate.Manager, log zerolog.Logger) func() {
	return func() {
		n, err := claims.RetireLegacyClaims()
		if err != nil {
			log.Warn().Err(err).Msg("failed to retire 1.x ban claims; retrying on the next start")
			return
		}
		if n > 0 {
			log.Info().Int("bans", n).Msg("dropped the legacy claim of 1.x bans that a CrowdSec decision now claims")
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
