package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
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

// runPeriodicReconcile reconciles every interval. Each tick first re-checks the
// sites loaded in legacy mode; when one now needs zone mode (the controller was
// upgraded to a zone-only release, or auto mode finds zones), the error is sent
// on modeChanged and the loop stops, so the daemon exits and its supervisor
// restarts it in the new mode.
func runPeriodicReconcile(ctx context.Context, fwMgr firewall.Manager, sites []string, interval time.Duration,
	notifier *webhook.Notifier, modeChanged chan<- error, log zerolog.Logger,
) {
	ctx, stop := context.WithCancel(ctx)
	defer stop()
	every(ctx, interval, func() {
		if err := fwMgr.CheckModeChange(ctx); err != nil {
			log.Error().Err(err).Msg("firewall mode changed; exiting so the bouncer restarts in the new mode")
			fireModeChanged(notifier, err)
			modeChanged <- err
			stop()
			return
		}
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
			notifier.Fire(webhook.EventReconcileDrift, map[string]any{
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
// without a restart, and hands reloaded Cloudflare zone pairs to cf.
// reconcilesOpen reports whether the startup reconcile gate has opened (see
// gateReconciles).
func watchSIGHUP(ctx context.Context, sighup chan os.Signal, cfg *config.Config, fwMgr firewall.Manager,
	cf *cloudflarePairSource, reconcilesOpen func() bool, log zerolog.Logger,
) {
	defer signal.Stop(sighup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-sighup:
			reloadZones(ctx, cfg, fwMgr, cf, reconcilesOpen, log)
		}
	}
}

// reloadedOnSIGHUP are the settings a SIGHUP applies; the Cloudflare pairs
// only while the whitelist runs.
var reloadedOnSIGHUP = []string{"ZONE_PAIRS", "EGRESS_ZONE_PAIRS"}

// reloadZones reads the configuration again and applies its zone pairs. The
// whole configuration must load: one that fails validation would also fail
// the next restart, so it is refused with its error and nothing changes.
// The Cloudflare pairs are handed over only once the zone pairs are in
// effect, so a refused zone reload leaves both as they were. Other changed
// settings are listed, by name only, as needing a restart.
func reloadZones(ctx context.Context, cfg *config.Config, fwMgr firewall.Manager, cf *cloudflarePairSource,
	reconcilesOpen func() bool, log zerolog.Logger,
) {
	if cfg.DryRun {
		log.Info().Msg("[DRY-RUN] skipping zone reload")
		return
	}
	newCfg, err := config.Load()
	if err != nil {
		log.Warn().Err(err).Msg("SIGHUP: reload config failed")
		return
	}
	applied := reloadedOnSIGHUP
	cfPairs, cfApplies := reloadedCloudflarePairs(cf, newCfg, log)
	if cfApplies {
		applied = append(slices.Clone(applied), "CLOUDFLARE_ZONE_PAIRS")
	}
	if changed := config.ChangedSettings(cfg, newCfg, applied...); len(changed) > 0 {
		log.Info().Strs("settings", changed).Msg("SIGHUP: changed settings take effect only after a restart")
	}
	// Legacy sites have no zone pairs to apply, so an empty ZONE_PAIRS is
	// expected there and checked only once a site uses zone mode.
	zm := fwMgr.ZoneManager()
	if zm == nil {
		if cfApplies {
			publishCloudflarePairs(cf, cfPairs, log)
		}
		log.Warn().Msg("SIGHUP: ZoneManager not available (legacy mode?), skipping reload")
		return
	}
	newPairs, err := newCfg.ManagedZonePairs()
	if err != nil {
		log.Warn().Err(err).Msg("SIGHUP: parse zone pairs failed")
		return
	}
	if len(newPairs) == 0 {
		// Applying an empty set would delete every block policy as an orphan.
		log.Error().Msg("SIGHUP: ZONE_PAIRS and EGRESS_ZONE_PAIRS name no zone pair; keeping the current zone pairs")
		return
	}
	if cfApplies {
		if err := checkCloudflareZones(ctx, zm, cfg.UnifiSites, cfPairs); err != nil {
			log.Warn().Err(err).Msg("SIGHUP: Cloudflare zone pairs refused; keeping the current zone pairs")
			return
		}
	}
	if err := zm.Reload(ctx, cfg.UnifiSites, newPairs); err != nil {
		log.Warn().Err(err).Msg("SIGHUP: zone reload failed")
		return
	}
	if cfApplies {
		publishCloudflarePairs(cf, cfPairs, log)
	}
	logSitePairs(newCfg, cfg.UnifiSites, log)
	enforceReloadedPairs(ctx, cfg, fwMgr, reconcilesOpen, log)
}

// enforceReloadedPairs brings the controller in line with zone pairs a
// SIGHUP has just applied.
func enforceReloadedPairs(ctx context.Context, cfg *config.Config, fwMgr firewall.Manager,
	reconcilesOpen func() bool, log zerolog.Logger,
) {
	if !reconcilesOpen() {
		// A full reconcile also removes controller members the ban database
		// does not hold. Until the startup gate opens the database may be
		// empty, so only the policies are brought in line with the new pairs.
		if err := fwMgr.RepairInfrastructure(ctx, cfg.UnifiSites); err != nil {
			log.Warn().Err(err).Msg("SIGHUP: zone policies could not be fully repaired")
			return
		}
		log.Info().Msg("SIGHUP: zone pairs and policies reloaded; bans are reconciled once the startup reconcile runs")
		return
	}
	if _, err := fwMgr.Reconcile(ctx, cfg.UnifiSites); err != nil {
		log.Warn().Err(err).Msg("SIGHUP: zone policies could not be fully reconciled")
		return
	}
	log.Info().Msg("SIGHUP: zone pairs and policies reloaded successfully")
}

// repairAndSyncWhitelist ensures the block policy or rule of every loaded
// shard, then runs the Cloudflare whitelist: the first sync, then a refresh
// every CLOUDFLARE_REFRESH_INTERVAL and after a SIGHUP changes the pairs.
// Shards that could not be provisioned are retried by the next sync; any other
// repair error is sent on failed and stops the daemon, as it did when the
// repair ran before startup finished.
func repairAndSyncWhitelist(ctx context.Context, cfg *config.Config, ctrl controller.Controller,
	fwMgr firewall.Manager, cfPairs *cloudflarePairSource, notifier *webhook.Notifier,
	failed chan<- error, log zerolog.Logger,
) {
	start := time.Now()
	log.Info().Msg("repairing firewall policies and rules")
	err := fwMgr.RepairInfrastructure(ctx, cfg.UnifiSites)
	if ctx.Err() != nil {
		return
	}
	if err != nil {
		failed <- fmt.Errorf("repair firewall infrastructure: %w", err)
		return
	}
	log.Info().Stringer("elapsed", time.Since(start)).Msg("firewall policies and rules repaired")
	cfManager := startCloudflareWhitelist(ctx, cfg, ctrl, fwMgr.ZoneManager(), cfPairs.Pairs(), notifier, log)
	if cfManager != nil {
		runCloudflareRefresh(ctx, cfManager, cfPairs, cfg.CloudflareRefreshInterval, notifier, log)
	}
}

// newMetricsRecorder starts the LAPI usage-metrics reporter, or returns a
// no-op recorder when reporting is disabled or in dry-run mode. The returned
// channel closes once the reporter has made its final push after ctx ends;
// shutdown waits on it so that push is not cut off.
func newMetricsRecorder(ctx context.Context, cfg *config.Config, log zerolog.Logger) (bouncer.MetricsRecorder, <-chan struct{}, error) {
	done := make(chan struct{})
	if cfg.LAPIMetricsPushInterval <= 0 || cfg.DryRun {
		close(done)
		return nopRecorder{}, done, nil
	}
	client, err := lapihttp.NewClient(cfg.CrowdSecLAPIVerifyTLS, cfg.CrowdSecLAPICACert, 5*time.Second)
	if err != nil {
		return nil, nil, fmt.Errorf("configure LAPI metrics client: %w", err)
	}
	reporter := lapimetrics.NewReporter(
		cfg.CrowdSecLAPIURL, cfg.CrowdSecLAPIKey, Version,
		cfg.LAPIMetricsPushInterval, client, log,
	)
	go func() {
		defer close(done)
		reporter.Run(ctx)
	}()
	return reporter, done, nil
}
