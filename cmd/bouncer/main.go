package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/capabilities"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/lapi_metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/whitelist"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

// nopRecorder is a MetricsRecorder that discards all recordings.
// Used when LAPI_METRICS_PUSH_INTERVAL=0 (reporting disabled).
type nopRecorder struct{}

func (nopRecorder) RecordBan(_, _ string) {}
func (nopRecorder) RecordDeletion()       {}

// Version, Commit, and BuildDate are set by the build system via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:   "cs-unifi-bouncer-pro",
		Short: "CrowdSec bouncer for UniFi firewall management",
	}

	root.AddCommand(
		runCmd(),
		healthcheckCmd(),
		versionCmd(),
		reconcileCmd(),
		statusCmd(),
		drainCmd(),
		validateCmd(),
		diagnoseCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runCmd is the main daemon command.
func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the bouncer daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon()
		},
	}
}

func runDaemon() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	log := buildLogger(cfg)
	for _, w := range cfg.DeprecationWarnings {
		log.Warn().Msg(w)
	}
	if w := cfg.InsecureLAPIURLWarning(); w != "" {
		log.Warn().Str("url", cfg.CrowdSecLAPIURL).Msg(w)
	}
	log.Info().Str("version", Version).Msg("cs-unifi-bouncer-pro starting")
	log.Info().
		Str("bouncer_type", capabilities.BouncerType).
		Str("layer", capabilities.Layer).
		Bool("ipv4", true).Bool("ipv6", cfg.FirewallEnableIPv6).
		Bool("captcha", capabilities.SupportsCaptcha).
		Bool("appsec", capabilities.SupportsAppSec).
		Msg("bouncer capabilities")

	store, err := storage.NewBboltStore(cfg.DataDir, log)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}
	defer store.Close()

	ctrl, err := controller.NewClient(context.Background(), controller.ClientConfig{
		BaseURL:      cfg.UnifiURL,
		Username:     cfg.UnifiUsername,
		Password:     cfg.UnifiPassword,
		APIKey:       cfg.UnifiAPIKey,
		VerifyTLS:    cfg.UnifiVerifyTLS,
		CACertPath:   cfg.UnifiCACert,
		Timeout:      cfg.UnifiHTTPTimeout,
		Debug:        cfg.UnifiAPIDebug,
		ReauthMinGap: cfg.SessionReauthMinGap,
		EnableIPv6:   cfg.EnableIPv6,
	}, log)
	if err != nil {
		return fmt.Errorf("init UniFi client: %w", err)
	}
	defer ctrl.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Parse Cloudflare zone pairs if enabled (after ctx is created for zone resolution)
	var cfZonePairs []whitelist.ZonePairConfig
	if cfg.CloudflareWhitelistEnabled {
		parsedCFPairs, cfParseErr := cfg.ParseCloudflareZonePairs()
		if cfParseErr != nil {
			return fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: %w", cfParseErr)
		}
		for _, pair := range parsedCFPairs {
			// Resolve zone names to UUIDs - independent of main zone pair resolution.
			srcID, err := ctrl.GetZoneID(ctx, cfg.UnifiSites[0], pair.Src)
			if err != nil {
				return fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: resolve src zone %q: %w", pair.Src, err)
			}
			dstID, err := ctrl.GetZoneID(ctx, cfg.UnifiSites[0], pair.Dst)
			if err != nil {
				return fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: resolve dst zone %q: %w", pair.Dst, err)
			}
			cfZonePairs = append(cfZonePairs, whitelist.ZonePairConfig{
				SrcName:   pair.Src,
				DstName:   pair.Dst,
				SrcZoneID: srcID,
				DstZoneID: dstID,
				SrcPorts:  pair.SrcPorts,
				DstPorts:  pair.DstPorts,
			})
		}
	}

	fwMgr, err := buildFWManager(ctx, cfg, ctrl, store, log)
	if err != nil {
		return err
	}

	// Bootstrap infrastructure
	log.Info().Strs("sites", cfg.UnifiSites).Msg("ensuring firewall infrastructure")
	if err := fwMgr.EnsureInfrastructure(ctx, cfg.UnifiSites); err != nil {
		return fmt.Errorf("ensure infrastructure: %w", err)
	}

	// SIGHUP hot-reload: reload config and update zone pairs without restart.
	sighup := make(chan os.Signal, 1)
	signal.Notify(sighup, syscall.SIGHUP)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-sighup:
				newCfg, err := config.Load()
				if err != nil {
					log.Warn().Err(err).Msg("SIGHUP: reload config failed")
					continue
				}
				newPairs, err := newCfg.ParseZonePairs()
				if err != nil {
					log.Warn().Err(err).Msg("SIGHUP: parse zone pairs failed")
					continue
				}
				zm := fwMgr.ZoneManager()
				if zm == nil {
					log.Warn().Msg("SIGHUP: ZoneManager not available (legacy mode?), skipping reload")
					continue
				}
				if err := zm.Reload(ctx, newCfg.UnifiSites, newPairs); err != nil {
					log.Warn().Err(err).Msg("SIGHUP: zone reload completed with errors")
				} else {
					log.Info().Msg("SIGHUP: zone pairs reloaded successfully")
				}
			}
		}
	}()

	// Start Cloudflare whitelist sync if enabled
	var cfManager *whitelist.Manager
	if cfg.CloudflareWhitelistEnabled {
		cfProvider := whitelist.NewCloudflareProvider(cfg.CloudflareIPv4URL, cfg.CloudflareIPv6URL)
		cfManager = whitelist.NewManager(ctrl, cfg.UnifiSites, cfProvider, log)

		// cfZonePairs are already resolved above
		if err := cfManager.Sync(ctx, cfZonePairs); err != nil {
			log.Warn().Err(err).Msg("initial Cloudflare whitelist sync failed - will retry on next tick")
		} else {
			log.Info().Msg("Cloudflare whitelist initial sync complete")
		}
	}

	// Startup reconcile
	if cfg.FirewallReconcileOnStart {
		log.Info().Msg("running startup reconcile")
		start := time.Now()
		result, err := fwMgr.Reconcile(ctx, cfg.UnifiSites)
		if err != nil {
			log.Warn().Err(err).Msg("startup reconcile encountered errors")
		}
		elapsed := time.Since(start)
		metrics.ReconcileDuration.WithLabelValues("startup").Observe(elapsed.Seconds())
		if result != nil {
			log.Info().Int("added", result.Added).Int("removed", result.Removed).
				Dur("elapsed", result.Elapsed).Msg("startup reconcile complete")
		}
	}

	// Construct LAPI usage-metrics reporter.
	var recorder bouncer.MetricsRecorder
	if cfg.LAPIMetricsPushInterval > 0 {
		reporter := lapi_metrics.NewReporter(
			cfg.CrowdSecLAPIURL, cfg.CrowdSecLAPIKey, Version,
			cfg.LAPIMetricsPushInterval, log,
		)
		go reporter.Run(ctx)
		recorder = reporter
	} else {
		recorder = nopRecorder{}
	}

	bouncer.BinaryVersion = Version
	bnc, err := bouncer.New(cfg, ctrl, store, fwMgr, recorder, log)
	if err != nil {
		return fmt.Errorf("build bouncer: %w", err)
	}

	// Start janitor
	janitor := bouncer.NewJanitor(store, fwMgr, cfg.UnifiSites, cfg.JanitorInterval, log)
	go func() {
		if err := janitor.Run(ctx); err != nil {
			log.Warn().Err(err).Msg("janitor exited")
		}
	}()

	// Start periodic reconcile if configured
	if cfg.FirewallReconcileInterval > 0 {
		go runPeriodicReconcile(ctx, fwMgr, cfg.UnifiSites, cfg.FirewallReconcileInterval, log)
	}

	// Start periodic Cloudflare whitelist refresh if enabled
	if cfManager != nil {
		go func() {
			ticker := time.NewTicker(cfg.CloudflareRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if err := cfManager.Sync(ctx, cfZonePairs); err != nil {
						log.Error().Err(err).Msg("Cloudflare whitelist refresh failed")
					} else {
						log.Info().Msg("Cloudflare whitelist refresh complete")
					}
				}
			}
		}()
	}

	return bnc.Run(ctx)
}

func runPeriodicReconcile(ctx context.Context, fwMgr firewall.Manager, sites []string, interval time.Duration, log zerolog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			start := time.Now()
			result, err := fwMgr.Reconcile(ctx, sites)
			elapsed := time.Since(start)
			metrics.ReconcileDuration.WithLabelValues("periodic").Observe(elapsed.Seconds())
			if err != nil {
				log.Warn().Err(err).Msg("periodic reconcile error")
			} else if result != nil {
				log.Info().Int("added", result.Added).Int("removed", result.Removed).
					Dur("elapsed", result.Elapsed).Msg("periodic reconcile complete")
			}
		}
	}
}

// healthcheckCmd exits 0 if the controller is reachable.
func healthcheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Check health endpoint and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			resp, err := http.Get("http://" + cfg.HealthAddr + "/healthz") //nolint:noctx
			if err != nil {
				fmt.Fprintf(os.Stderr, "healthcheck failed: %v\n", err)
				os.Exit(1)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				fmt.Fprintf(os.Stderr, "healthcheck returned %d\n", resp.StatusCode)
				os.Exit(1)
			}
			fmt.Println("healthy")
			return nil
		},
	}
}

// versionCmd prints the version, commit, and build date, then exits.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information and exit",
		Long:  "Print the version, commit hash, and build date, then exit 0.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cs-unifi-bouncer-pro %s (commit: %s, built: %s)\n",
				Version, Commit, BuildDate)
		},
	}
}

// reconcileCmd runs a one-shot full reconcile.
func reconcileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reconcile",
		Short: "Run a one-shot full reconcile and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}

			log := buildLogger(cfg)
			for _, w := range cfg.DeprecationWarnings {
				log.Warn().Msg(w)
			}

			ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer cancel()

			store, err := storage.NewBboltStore(cfg.DataDir, log)
			if err != nil {
				return err
			}
			defer store.Close()

			ctrl, err := controller.NewClient(ctx, controller.ClientConfig{
				BaseURL:      cfg.UnifiURL,
				Username:     cfg.UnifiUsername,
				Password:     cfg.UnifiPassword,
				APIKey:       cfg.UnifiAPIKey,
				VerifyTLS:    cfg.UnifiVerifyTLS,
				CACertPath:   cfg.UnifiCACert,
				Timeout:      cfg.UnifiHTTPTimeout,
				Debug:        cfg.UnifiAPIDebug,
				ReauthMinGap: cfg.SessionReauthMinGap,
				EnableIPv6:   cfg.EnableIPv6,
			}, log)
			if err != nil {
				return err
			}
			defer ctrl.Close()

			fwMgr, err := buildFWManager(ctx, cfg, ctrl, store, log)
			if err != nil {
				return err
			}

			if err := fwMgr.EnsureInfrastructure(ctx, cfg.UnifiSites); err != nil {
				return err
			}

			start := time.Now()
			result, err := fwMgr.Reconcile(ctx, cfg.UnifiSites)
			elapsed := time.Since(start)
			metrics.ReconcileDuration.WithLabelValues("manual").Observe(elapsed.Seconds())
			if err != nil {
				return err
			}
			fmt.Printf("reconcile complete: added=%d removed=%d elapsed=%s\n",
				result.Added, result.Removed, result.Elapsed)
			return nil
		},
	}
}

// statusCmd prints a read-only summary of the bbolt database state.
// It opens the database in read-only mode and prints ban counts, group info,
// and policy info. Zero API calls are made; safe to run while daemon is running.
func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print a read-only summary of bbolt state (no API calls)",
		Long: `Print ban counts, shard groups, and firewall policies stored in bbolt.
Opens the database in read-only mode — safe to run while the daemon is running.`,
	}

	defaultDataDir := os.Getenv("DATA_DIR")
	if defaultDataDir == "" {
		defaultDataDir = "/data"
	}
	var dataDir string
	cmd.Flags().StringVar(&dataDir, "data-dir", defaultDataDir,
		"Path to the data directory containing bouncer.db (env: DATA_DIR)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		store, err := storage.NewBboltStoreReadOnly(dataDir)
		if err != nil {
			return fmt.Errorf("open store (read-only): %w", err)
		}
		defer store.Close()

		banList, err := store.BanList()
		if err != nil {
			return fmt.Errorf("list bans: %w", err)
		}
		groups, err := store.ListGroups()
		if err != nil {
			return fmt.Errorf("list groups: %w", err)
		}
		policies, err := store.ListPolicies()
		if err != nil {
			return fmt.Errorf("list policies: %w", err)
		}
		sizeBytes, err := store.SizeBytes()
		if err != nil {
			return fmt.Errorf("db size: %w", err)
		}

		now := time.Now()
		var activeBans, expiredBans int
		for _, entry := range banList {
			if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
				expiredBans++
			} else {
				activeBans++
			}
		}

		var maxUpdatedAt time.Time
		for _, rec := range groups {
			if rec.UpdatedAt.After(maxUpdatedAt) {
				maxUpdatedAt = rec.UpdatedAt
			}
		}

		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "FIELD\tVALUE")
		fmt.Fprintf(w, "bans_active\t%d\n", activeBans)
		fmt.Fprintf(w, "bans_expired\t%d\n", expiredBans)
		fmt.Fprintf(w, "groups\t%d\n", len(groups))
		fmt.Fprintf(w, "policies\t%d\n", len(policies))
		fmt.Fprintf(w, "db_size_bytes\t%d\n", sizeBytes)
		if !maxUpdatedAt.IsZero() {
			fmt.Fprintf(w, "last_group_update\t%s\n", maxUpdatedAt.UTC().Format(time.RFC3339))
		} else {
			fmt.Fprintf(w, "last_group_update\t-\n")
		}
		return w.Flush()
	}

	return cmd
}

// drainCmd removes all managed firewall objects from UniFi and cleans up bbolt.
func drainCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "drain",
		Short: "Remove all managed firewall objects from UniFi and clean up bbolt",
		Long: `Deletes all managed firewall policies/rules and shard groups for every
configured site, then removes corresponding entries from bbolt.

Requires either --force or --dry-run for safety.`,
	}

	var dryRun bool
	var force bool
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Log what would be removed without making changes")
	cmd.Flags().BoolVar(&force, "force", false, "Actually remove objects (required unless --dry-run)")

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		if !dryRun && !force {
			return fmt.Errorf("drain requires --force (or use --dry-run to preview)")
		}

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("load config: %w", err)
		}
		if dryRun {
			cfg.DryRun = true
		}

		log := buildLogger(cfg)
		for _, w := range cfg.DeprecationWarnings {
			log.Warn().Msg(w)
		}

		ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer cancel()

		store, err := storage.NewBboltStore(cfg.DataDir, log)
		if err != nil {
			return fmt.Errorf("open storage: %w", err)
		}
		defer store.Close()

		ctrl, err := controller.NewClient(ctx, controller.ClientConfig{
			BaseURL:      cfg.UnifiURL,
			Username:     cfg.UnifiUsername,
			Password:     cfg.UnifiPassword,
			APIKey:       cfg.UnifiAPIKey,
			VerifyTLS:    cfg.UnifiVerifyTLS,
			CACertPath:   cfg.UnifiCACert,
			Timeout:      cfg.UnifiHTTPTimeout,
			Debug:        cfg.UnifiAPIDebug,
			ReauthMinGap: cfg.SessionReauthMinGap,
			EnableIPv6:   cfg.EnableIPv6,
		}, log)
		if err != nil {
			return fmt.Errorf("init UniFi client: %w", err)
		}
		defer ctrl.Close()

		fwMgr, err := buildFWManager(ctx, cfg, ctrl, store, log)
		if err != nil {
			return err
		}

		// EnsureInfrastructure is needed so shard managers are populated before Drain.
		if !dryRun {
			log.Info().Strs("sites", cfg.UnifiSites).Msg("loading firewall infrastructure state")
			if err := fwMgr.EnsureInfrastructure(ctx, cfg.UnifiSites); err != nil {
				return fmt.Errorf("ensure infrastructure: %w", err)
			}
		}

		if err := fwMgr.Drain(ctx, cfg.UnifiSites); err != nil {
			return fmt.Errorf("drain: %w", err)
		}

		fmt.Printf("drain complete (dry_run=%v)\n", dryRun)
		return nil
	}

	return cmd
}

// buildFWManager constructs a firewall.Manager from config, controller, store, and logger.
// It does NOT call EnsureInfrastructure — callers do that themselves when needed.
func buildFWManager(ctx context.Context, cfg *config.Config,
	ctrl controller.Controller, store storage.Store, log zerolog.Logger,
) (firewall.Manager, error) {
	namer, err := firewall.NewNamer(
		cfg.GroupNameTemplate,
		cfg.RuleNameTemplate,
		cfg.PolicyNameTemplate,
		cfg.ObjectDescription,
	)
	if err != nil {
		return nil, fmt.Errorf("build namer: %w", err)
	}

	v4Cap, v6Cap := resolveCapacities(cfg)

	zonePairs, err := cfg.ParseZonePairs()
	if err != nil {
		return nil, fmt.Errorf("parse zone pairs: %w", err)
	}

	return firewall.NewManager(firewall.ManagerConfig{
		FirewallMode:                cfg.FirewallMode,
		EnableIPv6:                  cfg.FirewallEnableIPv6,
		GroupCapacityV4:             v4Cap,
		GroupCapacityV6:             v6Cap,
		DryRun:                      cfg.DryRun,
		APIShardDelay:               cfg.FirewallAPIShardDelay,
		FlushConcurrency:            cfg.FirewallFlushConcurrency,
		CircuitBreakerThreshold:     cfg.CircuitBreakerThreshold,
		CircuitBreakerResetInterval: cfg.CircuitBreakerResetInterval,
		ShardMergeThreshold:         cfg.ShardMergeThreshold,
		LegacyCfg: firewall.LegacyConfig{
			RuleIndexStartV4: cfg.LegacyRuleIndexStartV4,
			RuleIndexStartV6: cfg.LegacyRuleIndexStartV6,
			RulesetV4:        cfg.LegacyRulesetV4,
			RulesetV6:        cfg.LegacyRulesetV6,
			BlockAction:      cfg.FirewallBlockAction,
			LogDrops:         cfg.FirewallLogDrops,
			Description:      cfg.ObjectDescription,
			APIWriteDelay:    cfg.FirewallAPIShardDelay,
		},
		ZoneCfg: firewall.ZoneConfig{
			ZonePairs:     zonePairs,
			Description:   cfg.ObjectDescription,
			LogDrops:      cfg.FirewallLogDrops,
			APIWriteDelay: cfg.FirewallAPIShardDelay,
		},
	}, ctrl, store, namer, log), nil
}

// resolveCapacities determines effective v4/v6 group capacities from config,
// applying the per-family overrides and falling back to the shared capacity.
func resolveCapacities(cfg *config.Config) (v4Cap, v6Cap int) {
	v4Cap = cfg.FirewallGroupCapacityV4
	if v4Cap == 0 {
		v4Cap = cfg.FirewallGroupCapacity
	}
	v6Cap = cfg.FirewallGroupCapacityV6
	if v6Cap == 0 {
		v6Cap = v4Cap
	}
	return v4Cap, v6Cap
}

// validateCmd loads and validates config without making any API calls.
func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and exit (no API calls)",
		Long: `Load configuration from environment variables, run all validation rules,
and print a human-readable summary. Exits 0 on success, 1 on error.
No API calls are made — safe to run in CI without network access.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "configuration invalid: %v\n", err)
				os.Exit(1)
			}

			pairs, _ := cfg.ParseZonePairs()
			pairStr := fmt.Sprintf("%d pair(s)", len(pairs))
			if len(pairs) > 0 {
				parts := make([]string, 0, len(pairs))
				for _, p := range pairs {
					parts = append(parts, p.Src+"->"+p.Dst)
				}
				pairStr = strings.Join(parts, ", ")
			}

			v4Cap, _ := resolveCapacities(cfg)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "FIELD\tVALUE")
			fmt.Fprintf(w, "firewall_mode\t%s\n", cfg.FirewallMode)
			fmt.Fprintf(w, "zone_pairs\t%s\n", pairStr)
			fmt.Fprintf(w, "sites\t%s\n", strings.Join(cfg.UnifiSites, ", "))
			fmt.Fprintf(w, "ban_ttl\t%s\n", cfg.BanTTL)
			fmt.Fprintf(w, "shard_capacity\t%d\n", v4Cap)
			fmt.Fprintf(w, "cb_threshold\t%d\n", cfg.CircuitBreakerThreshold)
			fmt.Fprintf(w, "cb_reset_interval\t%s\n", cfg.CircuitBreakerResetInterval)
			fmt.Fprintf(w, "lapi_url\t%s\n", cfg.CrowdSecLAPIURL)
			fmt.Fprintf(w, "unifi_url\t%s\n", cfg.UnifiURL)
			if cfg.MetricsEnabled {
				fmt.Fprintf(w, "metrics_addr\t%s\n", cfg.MetricsAddr)
			} else {
				fmt.Fprintf(w, "metrics_addr\t(disabled)\n")
			}
			fmt.Fprintf(w, "health_addr\t%s\n", cfg.HealthAddr)
			_ = w.Flush()

			for _, warn := range cfg.DeprecationWarnings {
				fmt.Fprintf(os.Stderr, "WARNING: %s\n", warn)
			}
			if w2 := cfg.InsecureLAPIURLWarning(); w2 != "" {
				fmt.Fprintf(os.Stderr, "WARNING: %s\n", w2)
			}

			fmt.Println("\nconfiguration valid ✓")
			return nil
		},
	}
}

// diagCheck is a single row in the diagnose output table.
type diagCheck struct {
	name   string
	status string // "PASS", "FAIL", or "" for detail-only rows
	detail string
}

// diagnoseCmd runs a structured connectivity probe against LAPI and UniFi.
func diagnoseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diagnose",
		Short: "Run connectivity checks against LAPI and UniFi controller",
		Long: `Runs three-phase diagnostics:
  1. Load and validate configuration
  2. Probe CrowdSec LAPI reachability
  3. Probe UniFi controller reachability, and if zone mode: discover and list zones

Exits 0 when all checks pass, 1 if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var checks []diagCheck
			allPass := true

			// --- Phase 1: config ---
			cfg, err := config.Load()
			if err != nil {
				checks = append(checks, diagCheck{"config_valid", "FAIL", err.Error()})
				printDiagChecks(checks)
				os.Exit(1)
			}
			checks = append(checks, diagCheck{
				"config_valid", "PASS",
				fmt.Sprintf("mode=%s sites=%v", cfg.FirewallMode, cfg.UnifiSites),
			})

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// --- Phase 2: LAPI reachability ---
			lapiURL := cfg.CrowdSecLAPIURL + "/v1/decisions?limit=1"
			lapiClient := &http.Client{Timeout: 10 * time.Second}
			lapiReq, lapiReqErr := http.NewRequestWithContext(ctx, http.MethodGet, lapiURL, nil)
			if lapiReqErr != nil {
				checks = append(checks, diagCheck{"lapi_reachable", "FAIL", lapiReqErr.Error()})
				allPass = false
			} else {
				lapiReq.Header.Set("X-Api-Key", cfg.CrowdSecLAPIKey)
				lapiResp, lapiErr := lapiClient.Do(lapiReq)
				if lapiErr != nil {
					checks = append(checks, diagCheck{"lapi_reachable", "FAIL", lapiErr.Error()})
					allPass = false
				} else {
					_ = lapiResp.Body.Close()
					detail := fmt.Sprintf("%s → %d %s", cfg.CrowdSecLAPIURL, lapiResp.StatusCode, http.StatusText(lapiResp.StatusCode))
					switch {
					case lapiResp.StatusCode == http.StatusUnauthorized:
						checks = append(checks, diagCheck{"lapi_reachable", "FAIL",
							detail + " — authentication failed; check CROWDSEC_LAPI_KEY"})
						allPass = false
					case lapiResp.StatusCode >= 200 && lapiResp.StatusCode < 300:
						checks = append(checks, diagCheck{"lapi_reachable", "PASS", detail})
					default:
						checks = append(checks, diagCheck{"lapi_reachable", "WARN", detail})
					}
				}
			}

			// --- Phase 3: UniFi reachability ---
			diagLog := zerolog.Nop()
			ctrl, ctrlErr := controller.NewClient(ctx, controller.ClientConfig{
				BaseURL:      cfg.UnifiURL,
				Username:     cfg.UnifiUsername,
				Password:     cfg.UnifiPassword,
				APIKey:       cfg.UnifiAPIKey,
				VerifyTLS:    cfg.UnifiVerifyTLS,
				CACertPath:   cfg.UnifiCACert,
				Timeout:      cfg.UnifiHTTPTimeout,
				ReauthMinGap: cfg.SessionReauthMinGap,
				EnableIPv6:   cfg.EnableIPv6,
			}, diagLog)
			if ctrlErr != nil {
				checks = append(checks, diagCheck{"unifi_reachable", "FAIL", ctrlErr.Error()})
				allPass = false
				printDiagChecks(checks)
				if !allPass {
					os.Exit(1)
				}
				return nil
			}
			defer ctrl.Close()

			if pingErr := ctrl.Ping(ctx); pingErr != nil {
				checks = append(checks, diagCheck{"unifi_reachable", "FAIL", pingErr.Error()})
				allPass = false
			} else {
				checks = append(checks, diagCheck{"unifi_reachable", "PASS", cfg.UnifiURL + " ping ok"})
			}

			// --- Zone discovery (zone or auto mode) ---
			if cfg.FirewallMode != "legacy" {
				for _, site := range cfg.UnifiSites {
					zones, zoneErr := ctrl.DiscoverZones(ctx, site)
					if zoneErr != nil {
						checks = append(checks, diagCheck{
							"zone_discovery[" + site + "]", "FAIL", zoneErr.Error(),
						})
						allPass = false
						continue
					}
					checks = append(checks, diagCheck{
						"zone_discovery[" + site + "]", "PASS",
						fmt.Sprintf("%d zones found", len(zones)),
					})
					for _, z := range zones {
						checks = append(checks, diagCheck{"  " + z.Name, "", "id=" + z.ID})
					}
				}
			}

			printDiagChecks(checks)
			if !allPass {
				os.Exit(1)
			}
			return nil
		},
	}
}

func printDiagChecks(checks []diagCheck) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CHECK\tSTATUS\tDETAIL")
	for _, c := range checks {
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.name, c.status, c.detail)
	}
	_ = w.Flush()
}

// buildLogger constructs a zerolog.Logger based on config.
func buildLogger(cfg *config.Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	var base zerolog.Logger
	if cfg.LogFormat == "text" {
		cw := zerolog.NewConsoleWriter()
		cw.Out = logger.NewRedactWriter(os.Stderr)
		base = zerolog.New(cw).Level(level).With().Timestamp().Logger()
	} else {
		redactWriter := logger.NewRedactWriter(os.Stderr)
		base = zerolog.New(redactWriter).Level(level).With().Timestamp().Logger()
	}
	return base
}
