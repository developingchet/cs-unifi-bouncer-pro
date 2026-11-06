package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/whitelist"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

// daemonReconcileTimeout bounds the wait for a reconcile run by the daemon.
// It is longer than the daemon's own limit, so the daemon's answer arrives.
const daemonReconcileTimeout = 31 * time.Minute

// reconcileCmd runs a one-shot full reconcile, through the running bouncer
// when there is one.
func reconcileCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reconcile",
		Short: "Run a one-shot full reconcile and exit",
		Long: `Reconcile every configured site's firewall objects with the ban database.
While the bouncer runs, the reconcile is run by the bouncer itself through its
health server (run the command inside the bouncer's container); otherwise the
database is opened directly.`,
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

			if daemonRunning(cfg.DataDir) {
				ctx, cancel := context.WithTimeout(ctx, daemonReconcileTimeout)
				defer cancel()
				return reconcileThroughDaemon(ctx, cfg.DataDir)
			}
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

			fwMgr, err := buildFWManager(cfg, ctrl, store, log, nil)
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

		fwMgr, err := buildFWManager(cfg, ctrl, store, log, nil)
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
		if err := drainWhitelist(ctx, cfg, ctrl, log); err != nil {
			return fmt.Errorf("drain Cloudflare whitelist: %w", err)
		}

		fmt.Printf("drain complete (dry_run=%v)\n", cfg.DryRun)
		return nil
	}

	return cmd
}

// drainWhitelist removes, or with dry-run previews the removal of, the
// Cloudflare whitelist policies and lists. They exist only when an API key
// created them, as zone mode requires one.
func drainWhitelist(ctx context.Context, cfg *config.Config, ctrl controller.Controller, log zerolog.Logger) error {
	if cfg.UnifiAPIKey == "" {
		return nil
	}
	mgr := whitelist.NewManager(ctrl, cfg.UnifiSites, nil, log)
	if cfg.DryRun {
		return mgr.PreviewDrain(ctx)
	}
	return mgr.Drain(ctx)
}

// banCmd manually bans an IP across all configured UniFi sites.
func banCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ban <IP>",
		Short: "Manually ban an IP across all configured UniFi sites",
		Long: `Ban an address or range across every configured site. The ban passes the
same guards as a CrowdSec decision (private ranges, BLOCK_WHITELIST, ranges
broader than /8 or /32) and is recorded in the history with origin "manual".
While the bouncer runs, it applies the ban itself through its health server
(run the command inside the bouncer's container); otherwise the database is
opened directly.`,
		Args: cobra.ExactArgs(1),
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
		Long: `Lift every ban on an address or range, whichever source made it, and record
the unban in the history with origin "manual". While the bouncer runs, it
lifts the ban itself through its health server; otherwise the database is
opened directly.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runManualUnban(args[0])
		},
	}
}

func runManualBan(value string, dur time.Duration) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	whitelist, err := decision.ParseWhitelist(cfg.BlockWhitelist)
	if err != nil {
		return fmt.Errorf("BLOCK_WHITELIST: %w", err)
	}
	ip, err := bouncer.CheckManualBan(value, whitelist)
	if err != nil {
		return err
	}
	if _, err := bouncer.ManualBanDuration(dur, cfg.BanTTL); err != nil {
		return err
	}
	log := buildLogger(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if daemonRunning(cfg.DataDir) {
		return banThroughDaemon(ctx, cfg.DataDir, ip, dur)
	}
	return withManualActions(ctx, cfg, log, func(actions *bouncer.ManualActions) error {
		res, err := actions.Ban(ctx, ip, dur)
		if err != nil {
			return err
		}
		if res.SyncErr != nil {
			return fmt.Errorf("ban of %s recorded, but %w; the bouncer writes it when it starts", res.IP, res.SyncErr)
		}
		fmt.Println(banMessage(res.IP, len(cfg.UnifiSites), res.ExpiresAt, cfg.DryRun))
		return nil
	})
}

// banThroughDaemon asks the running bouncer to ban ip.
func banThroughDaemon(ctx context.Context, dataDir, ip string, dur time.Duration) error {
	req := bouncer.ControlBanRequest{IP: ip}
	if dur > 0 {
		req.Duration = dur.String()
	}
	var resp bouncer.ControlResponse
	if err := callControl(ctx, dataDir, http.MethodPost, bouncer.ControlBanPath, req, &resp); err != nil {
		return err
	}
	if resp.SyncError != "" {
		return fmt.Errorf("ban of %s recorded by the running bouncer, which retries writing it to UniFi: %s",
			printable(resp.IP), printable(resp.SyncError))
	}
	var expiresAt time.Time
	if resp.ExpiresAt != nil {
		expiresAt = *resp.ExpiresAt
	}
	fmt.Println(banMessage(printable(resp.IP), resp.Sites, expiresAt, false))
	return nil
}

// banMessage reports a manual ban; a dry run changes nothing, so it says what
// would have happened.
func banMessage(ip string, sites int, expiresAt time.Time, dryRun bool) string {
	if dryRun {
		return fmt.Sprintf("[DRY-RUN] would ban %s across %d site(s) (expires: %s)", ip, sites, expiresAt.Format(time.RFC3339))
	}
	return fmt.Sprintf("banned %s across %d site(s) (expires: %s)", ip, sites, expiresAt.Format(time.RFC3339))
}

// unbanMessage reports a manual unban, worded like banMessage.
func unbanMessage(ip string, sites int, dryRun bool) string {
	if dryRun {
		return fmt.Sprintf("[DRY-RUN] would unban %s from %d site(s)", ip, sites)
	}
	return fmt.Sprintf("unbanned %s from %d site(s)", ip, sites)
}

func runManualUnban(value string) error {
	ip, _, err := decision.ParseAndSanitize(value)
	if err != nil {
		return err
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := buildLogger(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	if daemonRunning(cfg.DataDir) {
		err = unbanThroughDaemon(ctx, cfg.DataDir, ip)
	} else {
		err = withManualActions(ctx, cfg, log, func(actions *bouncer.ManualActions) error {
			res, err := actions.Unban(ctx, ip)
			if err != nil {
				return err
			}
			if res.SyncErr != nil {
				return fmt.Errorf("unban of %s recorded, but %w; the bouncer writes it when it starts", res.IP, res.SyncErr)
			}
			fmt.Println(unbanMessage(res.IP, len(cfg.UnifiSites), cfg.DryRun))
			return nil
		})
	}
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, crowdSecUnbanWarning(ip))
	return nil
}

// unbanThroughDaemon asks the running bouncer to lift every ban on ip.
func unbanThroughDaemon(ctx context.Context, dataDir, ip string) error {
	var resp bouncer.ControlResponse
	if err := callControl(ctx, dataDir, http.MethodPost, bouncer.ControlUnbanPath, bouncer.ControlUnbanRequest{IP: ip}, &resp); err != nil {
		return err
	}
	if resp.SyncError != "" {
		return fmt.Errorf("unban of %s recorded by the running bouncer, which retries writing it to UniFi: %s",
			printable(resp.IP), printable(resp.SyncError))
	}
	fmt.Println(unbanMessage(printable(resp.IP), resp.Sites, false))
	return nil
}

// reconcileThroughDaemon asks the running bouncer to reconcile every site.
func reconcileThroughDaemon(ctx context.Context, dataDir string) error {
	var resp bouncer.ReconcileResponse
	if err := callControl(ctx, dataDir, http.MethodPost, bouncer.ControlReconcilePath, nil, &resp); err != nil {
		return err
	}
	elapsed := time.Duration(resp.ElapsedSeconds * float64(time.Second)).Round(time.Millisecond)
	fmt.Printf("reconcile complete: added=%d removed=%d elapsed=%s\n", resp.Added, resp.Removed, elapsed)
	if resp.Error != "" {
		return fmt.Errorf("reconcile was partial: %s", printable(resp.Error))
	}
	return nil
}

// withManualActions opens the database, controller and firewall state for a
// one-shot ban or unban while the daemon is stopped, and runs fn on them.
func withManualActions(ctx context.Context, cfg *config.Config, log zerolog.Logger, fn func(*bouncer.ManualActions) error) error {
	store, ctrl, fwMgr, err := openManualSession(ctx, cfg, log)
	if err != nil {
		return err
	}
	defer store.Close()
	defer ctrl.Close()
	claims := banstate.New(store, fwMgr, cfg.UnifiSites, cfg.DryRun)
	actions, err := newManualActions(cfg, claims, fwMgr, store, log)
	if err != nil {
		return err
	}
	return fn(actions)
}

// newManualActions builds the manual ban, unban and reconcile actions over
// the ban-state manager, with the guards of BLOCK_WHITELIST.
func newManualActions(cfg *config.Config, claims *banstate.Manager, fwMgr firewall.Manager,
	store storage.Store, log zerolog.Logger,
) (*bouncer.ManualActions, error) {
	whitelist, err := decision.ParseWhitelist(cfg.BlockWhitelist)
	if err != nil {
		return nil, fmt.Errorf("BLOCK_WHITELIST: %w", err)
	}
	return &bouncer.ManualActions{
		Claims:    claims,
		Firewall:  fwMgr,
		History:   store,
		Sites:     cfg.UnifiSites,
		BanTTL:    cfg.BanTTL,
		Whitelist: whitelist,
		DryRun:    cfg.DryRun,
		Log:       log,
	}, nil
}

// crowdSecUnbanWarning explains that an unban only lasts until CrowdSec
// distributes the decision again. The bouncer re-applies every active
// decision on the next stream pull or resync, so a decision CrowdSec still
// holds brings the ban back.
func crowdSecUnbanWarning(ip string) string {
	flag := "--ip"
	if strings.Contains(ip, "/") {
		flag = "--range"
	}
	return fmt.Sprintf("warning: if CrowdSec still holds a decision for %s the ban returns on the next "+
		"decision pull or resync; remove it there too: cscli decisions delete %s %s", ip, flag, ip)
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
	fwMgr, err := buildFWManager(cfg, ctrl, store, log, nil)
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
