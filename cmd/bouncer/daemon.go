package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/blocklist"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/capabilities"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/webhook"
	"github.com/rs/zerolog"
)

func runDaemon() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := buildLogger(cfg)
	logStartup(cfg, log)

	store, err := openStore(cfg, log)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()

	ctrl, err := controller.NewClient(context.Background(), controllerConfig(cfg), log)
	if err != nil {
		return fmt.Errorf("init UniFi client: %w", err)
	}
	defer ctrl.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	cfPairs, err := cloudflarePairs(cfg)
	if err != nil {
		return err
	}
	if cfg.UnifiSitesAuto {
		discovered, err := ctrl.DiscoverSites(ctx)
		if err != nil {
			return fmt.Errorf("auto-discover sites: %w", err)
		}
		cfg.UnifiSites = filterExcluded(discovered, cfg.UnifiSitesExclude)
		if len(cfg.UnifiSites) == 0 {
			return fmt.Errorf("auto-discover sites: no site left to manage; discovered %s, UNIFI_SITES_EXCLUDE removes all of them",
				strings.Join(discovered, ", "))
		}
		log.Info().Strs("sites", cfg.UnifiSites).Msg("auto-discovered UniFi sites")
	} else if err := checkSitesExist(ctx, ctrl, cfg.UnifiSites, log); err != nil {
		return err
	}

	// The notifier is a no-op when WEBHOOK_URL is empty or in dry-run mode.
	webhookURL := cfg.WebhookURL
	if cfg.DryRun {
		webhookURL = ""
	}
	notifier := webhook.New(webhookURL, cfg.WebhookEvents, log)
	webhookDone := make(chan struct{})
	go func() {
		defer close(webhookDone)
		notifier.Run(ctx)
	}()

	fwMgr, err := buildFWManager(cfg, ctrl, store, log,
		func() { notifier.Fire(webhook.EventCircuitBreakerOpen, nil) },
		func() { notifier.Fire(webhook.EventCircuitBreakerClose, nil) },
	)
	if err != nil {
		return err
	}
	claims := banstate.New(store, fwMgr, cfg.UnifiSites, cfg.DryRun)

	log.Info().Strs("sites", cfg.UnifiSites).Msg("ensuring firewall infrastructure")
	if err := fwMgr.EnsureInfrastructure(ctx, cfg.UnifiSites); err != nil {
		return fmt.Errorf("ensure infrastructure: %w", err)
	}
	go watchSIGHUP(ctx, notifySIGHUP(), cfg, fwMgr, log)
	cfManager := startCloudflareWhitelist(ctx, cfg, ctrl, cfPairs, log)

	recorder, recorderDone, err := newMetricsRecorder(ctx, cfg, log)
	if err != nil {
		return err
	}
	bouncer.BinaryVersion = Version
	bnc, err := bouncer.New(cfg, ctrl, store, fwMgr, claims, recorder, log)
	if err != nil {
		return fmt.Errorf("build bouncer: %w", err)
	}

	if len(cfg.BlocklistURLs) > 0 {
		protected, err := decision.ParseWhitelist(cfg.BlockWhitelist)
		if err != nil {
			return fmt.Errorf("parse blocklist whitelist: %w", err)
		}
		blMgr := blocklist.NewManager(cfg.BlocklistURLs, cfg.BlocklistRefreshInterval, cfg.BanTTL, claims, protected, cfg.DryRun, log)
		go blMgr.Run(ctx)
	}
	janitor := bouncer.NewJanitor(store, claims, cfg.JanitorInterval, log)
	go func() {
		if err := janitor.Run(ctx); err != nil {
			log.Warn().Err(err).Msg("janitor exited")
		}
	}()
	// Reconcile removes controller IPs the ban database does not hold. A fresh
	// or lost database holds nothing until the first LAPI batch arrives, so
	// reconciling earlier would strip every enforced ban from the controller.
	banCount := func() (int, error) {
		bans, err := store.BanList()
		return len(bans), err
	}
	gateReconciles(ctx, bnc.OnStartupSynced, banCount, startupReconcileFallback, func() {
		go func() {
			if cfg.FirewallReconcileOnStart {
				runStartupReconcile(ctx, fwMgr, cfg.UnifiSites, log)
			}
			if cfg.FirewallReconcileInterval > 0 {
				runPeriodicReconcile(ctx, fwMgr, cfg.UnifiSites, cfg.FirewallReconcileInterval, notifier, log)
			}
		}()
	}, log)
	if cfManager != nil {
		go runCloudflareRefresh(ctx, cfManager, cfPairs, cfg.CloudflareRefreshInterval, log)
	}

	done := make(chan error, 1)
	go func() { done <- bnc.Run(ctx) }()
	return awaitShutdown(ctx, cfg, done, log, webhookDone, recorderDone)
}

// awaitShutdown returns when the bouncer stops. After a signal it allows
// SHUTDOWN_GRACE_PERIOD for the bouncer to stop and for each drain (queued
// webhooks, the final usage-metrics push) to finish, then forces the process
// to exit.
func awaitShutdown(ctx context.Context, cfg *config.Config, done <-chan error, log zerolog.Logger, drains ...<-chan struct{}) error {
	stopped := done
	var err error
	select {
	case err = <-done:
		if ctx.Err() == nil {
			return err // stopped on its own, not by a signal
		}
		closed := make(chan error, 1)
		closed <- err
		stopped = closed
	case <-ctx.Done():
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownGracePeriod)
	defer shutdownCancel()
	select {
	case err = <-stopped:
		for _, drain := range drains {
			select {
			case <-drain:
			case <-shutdownCtx.Done():
			}
		}
		return err
	case <-shutdownCtx.Done():
		log.Warn().Stringer("grace_period", cfg.ShutdownGracePeriod).
			Msg("shutdown grace period exceeded; forcing exit")
		// Deferred cleanup is skipped on purpose: the database or controller
		// client may be what is stuck.
		shutdownCancel()
		os.Exit(1)
		return nil
	}
}

// logStartup logs the version, capabilities and configuration warnings.
func logStartup(cfg *config.Config, log zerolog.Logger) {
	for _, w := range cfg.DeprecationWarnings {
		log.Warn().Msg(w)
	}
	if w := cfg.InsecureLAPIURLWarning(); w != "" {
		log.Warn().Str("url", cfg.CrowdSecLAPIURL).Msg(w)
	}
	if cfg.UnifiAPIDebug && log.GetLevel() > zerolog.DebugLevel {
		log.Warn().Str("log_level", cfg.LogLevel).Msg("UNIFI_API_DEBUG logs at debug level; set LOG_LEVEL=debug to see it")
	}
	if len(cfg.BlockWhitelist) == 0 {
		log.Warn().Msg("BLOCK_WHITELIST is empty; add your public WAN address to prevent self-ban")
	}
	log.Info().Str("version", Version).Msg("cs-unifi-bouncer-pro starting")
	log.Info().
		Str("bouncer_type", capabilities.BouncerType).
		Str("layer", capabilities.Layer).
		Bool("ipv4", true).Bool("ipv6", cfg.FirewallEnableIPv6).
		Bool("captcha", capabilities.SupportsCaptcha).
		Bool("appsec", capabilities.SupportsAppSec).
		Msg("bouncer capabilities")
}

// checkSitesExist fails when a configured site is not on the controller, which
// otherwise surfaces later as a bare 401 from the first site-scoped request.
// A failed site listing only warns, so a key that cannot list sites still starts.
func checkSitesExist(ctx context.Context, ctrl controller.Controller, sites []string, log zerolog.Logger) error {
	known, err := ctrl.DiscoverSites(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("could not list UniFi sites to check UNIFI_SITES; continuing")
		return nil
	}
	for _, site := range sites {
		if !slices.Contains(known, site) {
			return fmt.Errorf("UNIFI_SITES: site %q is not on the controller; available sites: %s (use the short site name from the URL, e.g. \"default\")",
				site, strings.Join(known, ", "))
		}
	}
	return nil
}

// filterExcluded removes excluded sites from a site list.
func filterExcluded(sites, excluded []string) []string {
	if len(excluded) == 0 {
		return sites
	}
	excludeSet := make(map[string]bool, len(excluded))
	for _, e := range excluded {
		excludeSet[e] = true
	}
	result := make([]string, 0, len(sites))
	for _, s := range sites {
		if !excludeSet[s] {
			result = append(result, s)
		}
	}
	return result
}
