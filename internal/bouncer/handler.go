package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/pool"
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

// makeJobHandler returns a JobHandler that performs idempotency checks,
// rate gating, and firewall API calls for each SyncJob.
func makeJobHandler(
	ctrl controller.Controller,
	store storage.Store,
	fwMgr firewall.Manager,
	cfg *config.Config,
	recorder MetricsRecorder,
	log zerolog.Logger,
) pool.JobHandler {
	return func(ctx context.Context, job pool.SyncJob) error {
		// Step 1: Idempotency check
		exists, err := store.BanExists(job.IP)
		if err != nil {
			return fmt.Errorf("BanExists: %w", err)
		}
		if job.Action == "ban" && exists {
			metrics.JobsDropped.WithLabelValues("already_banned").Inc()
			log.Debug().Str("ip", job.IP).Msg("skipping: already banned")
			return nil
		}
		if job.Action == "delete" && !exists {
			metrics.JobsDropped.WithLabelValues("not_found").Inc()
			log.Debug().Str("ip", job.IP).Msg("skipping: not in ban list")
			return nil
		}

		// Step 2: API rate gate
		if cfg.RateLimitMaxCalls > 0 {
			allowed, gateErr := store.APIRateGate("unifi-group-update", cfg.RateLimitWindow, cfg.RateLimitMaxCalls)
			if gateErr != nil {
				return fmt.Errorf("APIRateGate: %w", gateErr)
			}
			if !allowed {
				metrics.JobsDropped.WithLabelValues("rate_limited").Inc()
				log.Warn().Str("ip", job.IP).Msg("rate limited: re-enqueue")
				return fmt.Errorf("rate limited") // triggers retry with backoff
			}
		}

		// Step 3: Apply to all sites
		sites := cfg.UnifiSites
		if job.Site != "" {
			sites = []string{job.Site}
		}

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
					return applyErr // pool will retry; session.EnsureAuth is called inside ApplyBan
				}
				if errors.As(applyErr, &rateLimit) {
					return applyErr // pool will retry
				}
				return fmt.Errorf("apply %s for site %s: %w", job.Action, site, applyErr)
			}
		}

		// Step 4: Persist to bbolt and record LAPI metrics
		// In dry run, ApplyBan/ApplyUnban already returned without writing to UniFi.
		// Skip bbolt state mutations and recorder calls to keep state consistent.
		if cfg.DryRun {
			log.Info().Str("action", job.Action).Str("ip", job.IP).Bool("ipv6", job.IPv6).
				Strs("sites", cfg.UnifiSites).Msg("[DRY-RUN] would persist job to bbolt")
			return nil
		}

		switch job.Action {
		case "ban":
			if err := store.BanRecord(job.IP, job.ExpiresAt, job.IPv6); err != nil {
				log.Warn().Err(err).Str("ip", job.IP).Msg("failed to record ban in bbolt")
			}
			recorder.RecordBan(job.Origin, job.RemediationType)
		case "delete":
			if err := store.BanDelete(job.IP); err != nil {
				log.Warn().Err(err).Str("ip", job.IP).Msg("failed to delete ban from bbolt")
			}
			recorder.RecordDeletion()
		}

		log.Info().Str("action", job.Action).Str("ip", job.IP).Bool("ipv6", job.IPv6).
			Strs("sites", cfg.UnifiSites).Msg("job applied")
		return nil
	}
}

// metricsHandler returns the Prometheus HTTP handler.
func metricsHandler() http.Handler {
	return promhttp.Handler()
}
