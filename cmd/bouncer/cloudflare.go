package main

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/webhook"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/whitelist"
	"github.com/rs/zerolog"
)

// cloudflarePairs parses CLOUDFLARE_ZONE_PAIRS. Zone IDs are resolved for each
// site later, by the whitelist manager.
func cloudflarePairs(cfg *config.Config) ([]whitelist.ZonePairConfig, error) {
	if !cfg.CloudflareWhitelistEnabled {
		return nil, nil
	}
	parsed, err := cfg.ParseCloudflareZonePairs()
	if err != nil {
		return nil, fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: %w", err)
	}
	pairs := make([]whitelist.ZonePairConfig, 0, len(parsed))
	for _, pair := range parsed {
		pairs = append(pairs, whitelist.ZonePairConfig{
			Site:     pair.Site,
			SrcName:  pair.Src,
			DstName:  pair.Dst,
			SrcPorts: pair.SrcPorts,
			DstPorts: pair.DstPorts,
			DstIPs:   pair.DstIPs,
		})
	}
	return pairs, nil
}

// cloudflarePairSource holds the Cloudflare zone pairs in effect. A SIGHUP
// replaces them, and the goroutine that runs the whitelist syncs picks them up
// for an immediate sync, so two syncs never run at once. A nil source holds
// no pairs.
type cloudflarePairSource struct {
	mu      sync.Mutex
	pairs   []whitelist.ZonePairConfig
	changed chan struct{}
}

func newCloudflarePairSource(pairs []whitelist.ZonePairConfig) *cloudflarePairSource {
	return &cloudflarePairSource{pairs: pairs, changed: make(chan struct{}, 1)}
}

// Pairs returns the pairs in effect.
func (s *cloudflarePairSource) Pairs() []whitelist.ZonePairConfig {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pairs
}

// Set replaces the pairs and reports whether they changed. A change is
// signalled on Changed; signals not yet received merge into one.
func (s *cloudflarePairSource) Set(pairs []whitelist.ZonePairConfig) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if reflect.DeepEqual(s.pairs, pairs) {
		return false
	}
	s.pairs = pairs
	select {
	case s.changed <- struct{}{}:
	default:
	}
	return true
}

// Changed receives a value after Set has changed the pairs.
func (s *cloudflarePairSource) Changed() <-chan struct{} {
	if s == nil {
		return nil
	}
	return s.changed
}

// reloadedCloudflarePairs returns the reloaded CLOUDFLARE_ZONE_PAIRS and
// whether a reload applies them: only when the whitelist runs and stays
// enabled. Turning the whitelist on or off needs a restart.
func reloadedCloudflarePairs(source *cloudflarePairSource, newCfg *config.Config, log zerolog.Logger) ([]whitelist.ZonePairConfig, bool) {
	if source == nil || !newCfg.CloudflareWhitelistEnabled {
		return nil, false
	}
	pairs, err := cloudflarePairs(newCfg)
	if err != nil {
		log.Warn().Err(err).Msg("SIGHUP: parse Cloudflare zone pairs failed")
		return nil, false
	}
	return pairs, true
}

// publishCloudflarePairs hands reloaded Cloudflare pairs to the whitelist,
// which syncs them at once when they changed.
func publishCloudflarePairs(source *cloudflarePairSource, pairs []whitelist.ZonePairConfig, log zerolog.Logger) {
	if source.Set(pairs) {
		log.Info().Msg("SIGHUP: Cloudflare zone pairs reloaded; the whitelist syncs them now")
	}
}

// checkCloudflareZones reports an error naming the first zone of the
// Cloudflare pairs that a site does not have.
func checkCloudflareZones(ctx context.Context, zm *firewall.ZoneManager, sites []string, pairs []whitelist.ZonePairConfig) error {
	for _, site := range sites {
		var names []string
		for _, pair := range config.SitePairs(pairs, site, func(p whitelist.ZonePairConfig) string { return p.Site }) {
			names = append(names, pair.SrcName, pair.DstName)
		}
		if len(names) == 0 {
			continue
		}
		if err := zm.CheckZones(ctx, site, names); err != nil {
			return fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: %w", err)
		}
	}
	return nil
}

// startCloudflareWhitelist runs the first Cloudflare whitelist sync and returns
// the manager for periodic refreshes, or nil when the feature is off. When it
// is off, objects left by an earlier run are drained; they can only exist if
// an API key created them.
func startCloudflareWhitelist(ctx context.Context, cfg *config.Config, ctrl controller.Controller,
	zm *firewall.ZoneManager, pairs []whitelist.ZonePairConfig, notifier *webhook.Notifier, log zerolog.Logger,
) *whitelist.Manager {
	if cfg.DryRun {
		return nil
	}
	if !cfg.CloudflareWhitelistEnabled {
		if cfg.UnifiAPIKey != "" {
			if err := whitelist.NewManager(ctrl, cfg.UnifiSites, nil, log).Drain(ctx); err != nil {
				log.Warn().Err(err).Msg("Cloudflare whitelist drain failed — orphaned policies may remain")
			}
		}
		return nil
	}
	provider := whitelist.NewCloudflareProvider(cfg.CloudflareIPv4URL, cfg.CloudflareIPv6URL)
	mgr := whitelist.NewManager(ctrl, cfg.UnifiSites, provider, log)
	mgr.SetIPv6(cfg.FirewallEnableIPv6)
	if zm != nil {
		mgr.SetBlockRecreator(zm)
	}
	if err := mgr.Sync(ctx, pairs); err != nil {
		log.Error().Err(err).
			Msg("initial Cloudflare whitelist sync FAILED — Cloudflare IPs will NOT be whitelisted until next tick; false positives possible")
		metrics.CloudflareWhitelistSyncErrors.Inc()
		fireCloudflareSyncFailed(notifier, "initial")
	} else {
		log.Info().Msg("Cloudflare whitelist initial sync complete")
	}
	return mgr
}

// whitelistSyncer is the part of whitelist.Manager the refresh loop uses.
type whitelistSyncer interface {
	Sync(ctx context.Context, zonePairs []whitelist.ZonePairConfig) error
}

// runCloudflareRefresh syncs the whitelist every interval, and at once when a
// SIGHUP changes the pairs in source.
func runCloudflareRefresh(ctx context.Context, mgr whitelistSyncer, source *cloudflarePairSource,
	interval time.Duration, notifier *webhook.Notifier, log zerolog.Logger,
) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := mgr.Sync(ctx, source.Pairs()); err != nil {
				log.Error().Err(err).Msg("Cloudflare whitelist refresh failed")
				metrics.CloudflareWhitelistSyncErrors.Inc()
				fireCloudflareSyncFailed(notifier, "refresh")
				continue
			}
			log.Info().Msg("Cloudflare whitelist refresh complete")
		case <-source.Changed():
			if err := mgr.Sync(ctx, source.Pairs()); err != nil {
				log.Error().Err(err).Msg("Cloudflare whitelist sync of the reloaded zone pairs failed")
				metrics.CloudflareWhitelistSyncErrors.Inc()
				fireCloudflareSyncFailed(notifier, "reload")
				continue
			}
			log.Info().Msg("Cloudflare whitelist synced with the reloaded zone pairs")
		}
	}
}
