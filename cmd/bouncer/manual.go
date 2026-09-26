package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

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

			store, err := openStore(cfg, log)
			if err != nil {
				return err
			}
			defer store.Close()

			ctrl, err := controller.NewClient(ctx, controllerConfig(cfg), log)
			if err != nil {
				return err
			}
			defer ctrl.Close()

			fwMgr, err := buildFWManager(cfg, ctrl, store, log, nil, nil)
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

		store, err := openStore(cfg, log)
		if err != nil {
			return fmt.Errorf("open storage: %w", err)
		}
		defer store.Close()

		ctrl, err := controller.NewClient(ctx, controllerConfig(cfg), log)
		if err != nil {
			return fmt.Errorf("init UniFi client: %w", err)
		}
		defer ctrl.Close()

		fwMgr, err := buildFWManager(cfg, ctrl, store, log, nil, nil)
		if err != nil {
			return err
		}

		log.Info().Strs("sites", cfg.UnifiSites).Msg("loading firewall infrastructure state")
		if err := fwMgr.PrepareDrain(ctx, cfg.UnifiSites); err != nil {
			return fmt.Errorf("prepare drain: %w", err)
		}

		if err := fwMgr.Drain(ctx, cfg.UnifiSites); err != nil {
			return fmt.Errorf("drain: %w", err)
		}

		fmt.Printf("drain complete (dry_run=%v)\n", dryRun)
		return nil
	}

	return cmd
}

// banCmd manually bans an IP across all configured UniFi sites.
func banCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ban <IP>",
		Short: "Manually ban an IP across all configured UniFi sites",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dur, _ := cmd.Flags().GetDuration("duration")
			return runManualBan(args[0], dur)
		},
	}
	cmd.Flags().Duration("duration", 24*time.Hour, "Ban duration (0 = BAN_TTL; longer durations are capped at BAN_TTL)")
	return cmd
}

// unbanCmd manually unbans an IP from all configured UniFi sites.
func unbanCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "unban <IP>",
		Short: "Manually unban an IP from all configured UniFi sites",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runManualUnban(args[0])
		},
	}
}

func runManualBan(ip string, dur time.Duration) error {
	var parseErr error
	ip, _, parseErr = decision.ParseAndSanitize(ip)
	if parseErr != nil {
		return parseErr
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := buildLogger(cfg)
	if dur < 0 {
		return fmt.Errorf("ban duration must not be negative")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	store, ctrl, fwMgr, err := openManualSession(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer store.Close()
	defer ctrl.Close()

	if dur == 0 || dur > cfg.BanTTL {
		dur = cfg.BanTTL
	}
	expiresAt := time.Now().Add(dur)
	isIPv6 := decision.IsIPv6(ip)

	claims := banstate.New(store, fwMgr, cfg.UnifiSites, cfg.DryRun)
	if _, err := claims.Claim(ctx, ip, isIPv6, "manual", expiresAt); err != nil {
		return fmt.Errorf("ban %s: %w", ip, err)
	}
	if err := fwMgr.SyncDirty(ctx, cfg.UnifiSites); err != nil {
		return fmt.Errorf("flush manual ban to UniFi: %w", err)
	}
	fmt.Printf("banned %s across %d site(s) (expires: %s)\n", ip, len(cfg.UnifiSites), expiresAt.Format(time.RFC3339))
	return nil
}

func runManualUnban(ip string) error {
	var parseErr error
	ip, _, parseErr = decision.ParseAndSanitize(ip)
	if parseErr != nil {
		return parseErr
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := buildLogger(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	store, ctrl, fwMgr, err := openManualSession(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer store.Close()
	defer ctrl.Close()

	claims := banstate.New(store, fwMgr, cfg.UnifiSites, cfg.DryRun)
	if _, err := claims.ReleaseAll(ctx, ip, decision.IsIPv6(ip)); err != nil {
		return fmt.Errorf("unban %s: %w", ip, err)
	}
	if err := fwMgr.SyncDirty(ctx, cfg.UnifiSites); err != nil {
		return fmt.Errorf("flush manual unban to UniFi: %w", err)
	}
	fmt.Printf("unbanned %s from %d site(s)\n", ip, len(cfg.UnifiSites))
	return nil
}

// openManualSession prepares the store, controller, and firewall state used by
// the one-shot ban and unban commands.
func openManualSession(ctx context.Context, cfg *config.Config, log zerolog.Logger) (storage.Store, controller.Controller, firewall.Manager, error) {
	store, err := openStore(cfg, log)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open storage: %w", err)
	}
	ctrl, err := controller.NewClient(ctx, controllerConfig(cfg), log)
	if err != nil {
		_ = store.Close()
		return nil, nil, nil, fmt.Errorf("init UniFi client: %w", err)
	}
	fwMgr, err := buildFWManager(cfg, ctrl, store, log, nil, nil)
	if err == nil {
		err = fwMgr.EnsureInfrastructure(ctx, cfg.UnifiSites)
	}
	if err != nil {
		_ = ctrl.Close()
		_ = store.Close()
		return nil, nil, nil, fmt.Errorf("ensure infrastructure: %w", err)
	}
	return store, ctrl, fwMgr, nil
}
