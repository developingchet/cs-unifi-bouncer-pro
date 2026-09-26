package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/lapihttp"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/lapimetrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/webhook"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/whitelist"
	"github.com/rs/zerolog"
)

// reconcileDriftThreshold is the number of IPs a periodic reconcile must add
// or remove before it fires the reconcile_drift webhook.
const reconcileDriftThreshold = 100

// every calls fn on each tick of interval until ctx is cancelled.
func every(ctx context.Context, interval time.Duration, fn func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn()
		}
	}
}

func runPeriodicReconcile(ctx context.Context, fwMgr firewall.Manager, sites []string, interval time.Duration, notifier *webhook.Notifier, log zerolog.Logger) {
	every(ctx, interval, func() {
		start := time.Now()
		result, err := fwMgr.Reconcile(ctx, sites)
		metrics.ReconcileDuration.WithLabelValues("periodic").Observe(time.Since(start).Seconds())
		if err != nil {
			// A partial reconcile still repaired what it could; report both.
			log.Warn().Err(err).Msg("periodic reconcile error")
		}
		if result == nil {
			return
		}
		log.Info().Int("added", result.Added).Int("removed", result.Removed).
			Stringer("elapsed", result.Elapsed).Msg("periodic reconcile complete")
		if result.Added+result.Removed >= reconcileDriftThreshold {
			notifier.Fire("reconcile_drift", map[string]any{
				"added":   result.Added,
				"removed": result.Removed,
			})
		}
	})
}

func runStartupReconcile(ctx context.Context, fwMgr firewall.Manager, sites []string, log zerolog.Logger) {
	log.Info().Msg("running startup reconcile")
	start := time.Now()
	result, err := fwMgr.Reconcile(ctx, sites)
	if err != nil {
		log.Warn().Err(err).Msg("startup reconcile encountered errors")
	}
	metrics.ReconcileDuration.WithLabelValues("startup").Observe(time.Since(start).Seconds())
	if result != nil {
		log.Info().Int("added", result.Added).Int("removed", result.Removed).
			Stringer("elapsed", result.Elapsed).Msg("startup reconcile complete")
	}
}

// notifySIGHUP subscribes to SIGHUP. Call it before starting watchSIGHUP so a
// signal is never handled by the default action, which terminates the process.
func notifySIGHUP() chan os.Signal {
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	return sighup
}

// watchSIGHUP reloads the zone pairs and reconciles their policies on SIGHUP,
// without a restart.
func watchSIGHUP(ctx context.Context, sighup chan os.Signal, cfg *config.Config, fwMgr firewall.Manager, log zerolog.Logger) {
	defer signal.Stop(sighup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
			reloadZones(ctx, cfg, fwMgr, log)
		}
	}
}

func reloadZones(ctx context.Context, cfg *config.Config, fwMgr firewall.Manager, log zerolog.Logger) {
	if cfg.DryRun {
		log.Info().Msg("[DRY-RUN] skipping zone reload")
		return
	}
	newCfg, err := config.Load()
	if err != nil {
		log.Warn().Err(err).Msg("SIGHUP: reload config failed")
		return
	}
	newPairs, err := newCfg.ParseZonePairs()
	if err != nil {
		log.Warn().Err(err).Msg("SIGHUP: parse zone pairs failed")
		return
	}
	zm := fwMgr.ZoneManager()
	if zm == nil {
		log.Warn().Msg("SIGHUP: ZoneManager not available (legacy mode?), skipping reload")
		return
	}
	if err := zm.Reload(ctx, cfg.UnifiSites, newPairs); err != nil {
		log.Warn().Err(err).Msg("SIGHUP: zone reload failed")
		return
	}
	if _, err := fwMgr.Reconcile(ctx, cfg.UnifiSites); err != nil {
		log.Warn().Err(err).Msg("SIGHUP: zone policies could not be fully reconciled")
		return
	}
	log.Info().Msg("SIGHUP: zone pairs and policies reloaded successfully")
}

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
			SrcName:  pair.Src,
			DstName:  pair.Dst,
			SrcPorts: pair.SrcPorts,
			DstPorts: pair.DstPorts,
			DstIPs:   pair.DstIPs,
		})
	}
	return pairs, nil
}

// startCloudflareWhitelist runs the first Cloudflare whitelist sync and returns
// the manager for periodic refreshes, or nil when the feature is off. When it
// is off, objects left by an earlier run are drained; they can only exist if
// an API key created them.
func startCloudflareWhitelist(ctx context.Context, cfg *config.Config, ctrl controller.Controller,
	pairs []whitelist.ZonePairConfig, log zerolog.Logger,
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
	if err := mgr.Sync(ctx, pairs); err != nil {
		log.Error().Err(err).
			Msg("initial Cloudflare whitelist sync FAILED — Cloudflare IPs will NOT be whitelisted until next tick; false positives possible")
		metrics.CloudflareWhitelistSyncErrors.Inc()
	} else {
		log.Info().Msg("Cloudflare whitelist initial sync complete")
	}
	return mgr
}

func runCloudflareRefresh(ctx context.Context, mgr *whitelist.Manager, pairs []whitelist.ZonePairConfig, interval time.Duration, log zerolog.Logger) {
	every(ctx, interval, func() {
		if err := mgr.Sync(ctx, pairs); err != nil {
			log.Error().Err(err).Msg("Cloudflare whitelist refresh failed")
			metrics.CloudflareWhitelistSyncErrors.Inc()
			return
		}
		log.Info().Msg("Cloudflare whitelist refresh complete")
	})
}

// newMetricsRecorder starts the LAPI usage-metrics reporter, or returns a
// no-op recorder when reporting is disabled or in dry-run mode.
func newMetricsRecorder(ctx context.Context, cfg *config.Config, log zerolog.Logger) (bouncer.MetricsRecorder, error) {
	if cfg.LAPIMetricsPushInterval <= 0 || cfg.DryRun {
		return nopRecorder{}, nil
	}
	client, err := lapihttp.NewClient(cfg.CrowdSecLAPIVerifyTLS, cfg.CrowdSecLAPICACert, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("configure LAPI metrics client: %w", err)
	}
	reporter := lapimetrics.NewReporter(
		cfg.CrowdSecLAPIURL, cfg.CrowdSecLAPIKey, Version,
		cfg.LAPIMetricsPushInterval, client, log,
	)
	go reporter.Run(ctx)
	return reporter, nil
}
