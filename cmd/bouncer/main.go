package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

// Version is set by the build system via -ldflags.
var Version = "dev"

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
	log.Info().Str("version", Version).Msg("cs-unifi-bouncer-pro starting")

	store, err := storage.NewBboltStore(cfg.DataDir)
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
	}, log)
	if err != nil {
		return fmt.Errorf("init UniFi client: %w", err)
	}
	defer ctrl.Close()

	namer, err := firewall.NewNamer(
		cfg.GroupNameTemplate,
		cfg.RuleNameTemplate,
		cfg.PolicyNameTemplate,
		cfg.ObjectDescription,
	)
	if err != nil {
		return fmt.Errorf("build namer: %w", err)
	}

	v4Cap, v6Cap := resolveCapacities(cfg)

	zonePairs, err := cfg.ParseZonePairs()
	if err != nil {
		return fmt.Errorf("parse zone pairs: %w", err)
	}

	fwMgr := firewall.NewManager(firewall.ManagerConfig{
		FirewallMode:     cfg.FirewallMode,
		EnableIPv6:       cfg.FirewallEnableIPv6,
		GroupCapacityV4:  v4Cap,
		GroupCapacityV6:  v6Cap,
		BatchWindow:      cfg.FirewallBatchWindow,
		DryRun:           cfg.DryRun,
		APIShardDelay:    cfg.FirewallAPIShardDelay,
		FlushConcurrency: cfg.FirewallFlushConcurrency,
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
			ZonePairs:            zonePairs,
			ZoneConnectionStates: cfg.ZoneConnectionStates,
			PolicyReorder:        cfg.ZonePolicyReorder,
			Description:          cfg.ObjectDescription,
			APIWriteDelay:        cfg.FirewallAPIShardDelay,
		},
	}, ctrl, store, namer, log)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Bootstrap infrastructure
	log.Info().Strs("sites", cfg.UnifiSites).Msg("ensuring firewall infrastructure")
	if err := fwMgr.EnsureInfrastructure(ctx, cfg.UnifiSites); err != nil {
		return fmt.Errorf("ensure infrastructure: %w", err)
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

	bouncer.BinaryVersion = Version
	bnc, err := bouncer.New(cfg, ctrl, store, fwMgr, log)
	if err != nil {
		return fmt.Errorf("build bouncer: %w", err)
	}

	// Start janitor
	janitor := bouncer.NewJanitor(store, nil, cfg.JanitorInterval, cfg.RateLimitWindow, log)
	go func() {
		if err := janitor.Run(ctx); err != nil {
			log.Warn().Err(err).Msg("janitor exited")
		}
	}()

	// Start periodic reconcile if configured
	if cfg.FirewallReconcileInterval > 0 {
		go runPeriodicReconcile(ctx, fwMgr, cfg.UnifiSites, cfg.FirewallReconcileInterval, log)
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

// versionCmd prints the version and exits.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cs-unifi-bouncer-pro %s\n", Version)
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

			store, err := storage.NewBboltStore(cfg.DataDir)
			if err != nil {
				return err
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
			}, log)
			if err != nil {
				return err
			}
			defer ctrl.Close()

			namer, err := firewall.NewNamer(cfg.GroupNameTemplate, cfg.RuleNameTemplate, cfg.PolicyNameTemplate, cfg.ObjectDescription)
			if err != nil {
				return err
			}

			zonePairs, err := cfg.ParseZonePairs()
			if err != nil {
				return err
			}

			rcV4Cap, rcV6Cap := resolveCapacities(cfg)
			fwMgr := firewall.NewManager(firewall.ManagerConfig{
				FirewallMode:     cfg.FirewallMode,
				EnableIPv6:       cfg.FirewallEnableIPv6,
				GroupCapacityV4:  rcV4Cap,
				GroupCapacityV6:  rcV6Cap,
				BatchWindow:      cfg.FirewallBatchWindow,
				DryRun:           cfg.DryRun,
				APIShardDelay:    cfg.FirewallAPIShardDelay,
				FlushConcurrency: cfg.FirewallFlushConcurrency,
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
					ZonePairs:            zonePairs,
					ZoneConnectionStates: cfg.ZoneConnectionStates,
					PolicyReorder:        cfg.ZonePolicyReorder,
					Description:          cfg.ObjectDescription,
					APIWriteDelay:        cfg.FirewallAPIShardDelay,
				},
			}, ctrl, store, namer, log)

			ctx := context.Background()
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
