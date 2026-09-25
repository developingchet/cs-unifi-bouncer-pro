package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
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
		log.Info().Strs("sites", cfg.UnifiSites).Msg("auto-discovered UniFi sites")
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
		func() { notifier.Fire("circuit_breaker_open", nil) },
		func() { notifier.Fire("circuit_breaker_close", nil) },
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
	if cfg.FirewallReconcileOnStart {
		runStartupReconcile(ctx, fwMgr, cfg.UnifiSites, log)
	}

	recorder, err := newMetricsRecorder(ctx, cfg, log)
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
		blMgr := blocklist.NewManager(cfg.BlocklistURLs, cfg.BlocklistRefreshInterval, claims, protected, cfg.DryRun, log)
		go blMgr.Run(ctx)
	}
	janitor := bouncer.NewJanitor(store, claims, cfg.JanitorInterval, log)
	go func() {
		if err := janitor.Run(ctx); err != nil {
			log.Warn().Err(err).Msg("janitor exited")
		}
	}()
	if cfg.FirewallReconcileInterval > 0 {
		go runPeriodicReconcile(ctx, fwMgr, cfg.UnifiSites, cfg.FirewallReconcileInterval, notifier, log)
	}
	if cfManager != nil {
		go runCloudflareRefresh(ctx, cfManager, cfPairs, cfg.CloudflareRefreshInterval, log)
	}

	done := make(chan error, 1)
	go func() { done <- bnc.Run(ctx) }()
	return awaitShutdown(ctx, cfg, done, webhookDone, log)
}

// awaitShutdown returns when the bouncer stops. After a signal it allows
// SHUTDOWN_GRACE_PERIOD for the bouncer and queued webhooks to finish, then
// forces the process to exit.
func awaitShutdown(ctx context.Context, cfg *config.Config, done <-chan error, webhookDone <-chan struct{}, log zerolog.Logger) error {
	select {
	case err := <-done:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.ShutdownGracePeriod)
	defer shutdownCancel()
	select {
	case err := <-done:
		select {
		case <-webhookDone:
		case <-shutdownCtx.Done():
		}
		return err
	case <-shutdownCtx.Done():
		log.Warn().Dur("grace_period", cfg.ShutdownGracePeriod).
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
