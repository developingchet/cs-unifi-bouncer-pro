package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

// MetricsRecorder is implemented by the LAPI usage-metrics reporter.
// A no-op implementation is used when reporting is disabled.
type MetricsRecorder interface {
	RecordBan(origin, remediationType string)
	RecordDeletion()
}

// SyncJob represents a single ban or unban operation.
type SyncJob struct {
	Action          string // "ban" or "delete"
	IP              string
	IPv6            bool
	ExpiresAt       time.Time
	Origin          string    // CrowdSec decision origin (e.g. "CAPI", "crowdsec")
	RemediationType string    // CrowdSec remediation type (e.g. "ban")
	ReceivedAt      time.Time // when this decision passed the filter pipeline; zero = unknown
}

// JobHandler processes a single SyncJob.
type JobHandler func(ctx context.Context, job SyncJob) error

// makeJobHandler returns a JobHandler that performs idempotency checks
// and firewall API calls for each SyncJob.
func makeJobHandler(
	ctrl controller.Controller,
	store storage.Store,
	fwMgr firewall.Manager,
	cfg *config.Config,
	recorder MetricsRecorder,
	log zerolog.Logger,
) JobHandler {
	return func(ctx context.Context, job SyncJob) error {
		// Step 1: Idempotency check
		exists, err := store.BanExists(job.IP)
		if err != nil {
			return fmt.Errorf("BanExists: %w", err)
		}
		if job.Action == "ban" && exists {
			log.Debug().Str("ip", job.IP).Msg("skipping: already banned")
			return nil
		}
		if job.Action == "delete" && !exists {
			log.Debug().Str("ip", job.IP).Msg("skipping: not in ban list")
			return nil
		}

		// In dry run, skip bbolt state mutations and recorder calls to keep state consistent.
		if cfg.DryRun {
			log.Info().Str("action", job.Action).Str("ip", job.IP).Bool("ipv6", job.IPv6).
				Strs("sites", cfg.UnifiSites).Msg("[DRY-RUN] would persist job to bbolt")
			return nil
		}

		// Step 2: Persist ban to bbolt BEFORE applying to UniFi.
		// This order ensures that a crash between the two leaves the IP recorded in bbolt,
		// so FIREWALL_RECONCILE_ON_START can restore it to UniFi on next startup.
		// For the delete path the order is reversed: remove from UniFi first so a crash
		// after the API call but before bbolt cleanup leaves the IP in bbolt (and reconcile
		// will add it back), which is the safe side.
		if job.Action == "ban" {
			if err := store.BanRecord(job.IP, job.ExpiresAt, job.IPv6); err != nil {
				log.Warn().Err(err).Str("ip", job.IP).Msg("failed to record ban in bbolt")
			}
		}

		// Step 3: Apply to all sites
		sites := cfg.UnifiSites
		for _, site := range sites {
			var applyErr error
			switch job.Action {
			case "ban":
				applyErr = fwMgr.ApplyBan(ctx, site, job.IP, job.IPv6)
			case "delete":
				applyErr = fwMgr.ApplyUnban(ctx, site, job.IP, job.IPv6)
			}

			if applyErr != nil {
				var unauth *controller.ErrUnauthorized
				var rateLimit *controller.ErrRateLimit
				if errors.As(applyErr, &unauth) {
					return applyErr
				}
				if errors.As(applyErr, &rateLimit) {
					return applyErr
				}
				return fmt.Errorf("apply %s for site %s: %w", job.Action, site, applyErr)
			}
		}

		// Step 4: Finalize bbolt state and record LAPI metrics.
		switch job.Action {
		case "ban":
			// Observe decision-to-block latency for successfully applied bans.
			if !job.ReceivedAt.IsZero() {
				metrics.DecisionLatency.Observe(time.Since(job.ReceivedAt).Seconds())
			}
			recorder.RecordBan(job.Origin, job.RemediationType)
		case "delete":
			if err := store.BanDelete(job.IP); err != nil {
				log.Warn().Err(err).Str("ip", job.IP).Msg("failed to delete ban from bbolt")
			}
			recorder.RecordDeletion()
		}

		log.Debug().Str("action", job.Action).Str("ip", job.IP).Bool("ipv6", job.IPv6).
			Strs("sites", cfg.UnifiSites).Msg("job applied")
		return nil
	}
}

// metricsHandler returns the Prometheus HTTP handler.
func metricsHandler() http.Handler {
	return promhttp.Handler()
}
