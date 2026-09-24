package bouncer

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
)

type MetricsRecorder interface {
	RecordBan(origin, remediationType string)
	RecordDeletion()
}

type SyncJob struct {
	Action           string
	IP               string
	IPv6             bool
	ExpiresAt        time.Time
	DurationOverride bool
	Source           string
	Origin           string
	RemediationType  string
	Scenario         string
	ReceivedAt       time.Time
}

type JobHandler func(ctx context.Context, job SyncJob) error

func makeJobHandler(
	_ controller.Controller,
	store storage.Store,
	fwMgr firewall.Manager,
	cfg *config.Config,
	recorder MetricsRecorder,
	log zerolog.Logger,
	shared ...*banstate.Manager,
) JobHandler {
	claims := banstate.New(store, fwMgr, cfg.UnifiSites, cfg.DryRun)
	if len(shared) > 0 && shared[0] != nil {
		claims = shared[0]
	}
	return func(ctx context.Context, job SyncJob) error {
		if len(cfg.ZonePairsScenarioMap) > 0 {
			return fmt.Errorf("ZONE_PAIRS_SCENARIO_MAP is not supported without separate firewall policies")
		}
		if job.Action != "ban" && job.Action != "delete" {
			return fmt.Errorf("unknown decision action %q", job.Action)
		}
		if cfg.DryRun {
			log.Info().Str("action", job.Action).Str("ip", job.IP).Msg("[DRY-RUN] would update ban")
			return nil
		}
		source := job.Source
		if source == "" {
			return fmt.Errorf("decision source is required")
		}
		switch job.Action {
		case "ban":
			expiry := job.ExpiresAt
			if expiry.IsZero() || (!job.DurationOverride && time.Until(expiry) > cfg.BanTTL) {
				expiry = time.Now().Add(cfg.BanTTL)
			}
			applied, err := claims.Claim(ctx, job.IP, job.IPv6, source, expiry)
			if err != nil {
				return fmt.Errorf("apply ban: %w", err)
			}
			if !applied {
				return nil
			}
			if !job.ReceivedAt.IsZero() {
				metrics.DecisionLatency.Observe(time.Since(job.ReceivedAt).Seconds())
			}
			recorder.RecordBan(job.Origin, job.RemediationType)
			if err := store.RecordEvent(storage.EventEntry{
				Action: "ban", Origin: job.Origin, Scenario: job.Scenario,
				IP: job.IP, RecordedAt: time.Now(),
			}); err != nil {
				log.Warn().Err(err).Str("ip", job.IP).Msg("failed to record ban event")
			}
		case "delete":
			removed, err := claims.Release(ctx, job.IP, source)
			if err != nil {
				return fmt.Errorf("apply unban: %w", err)
			}
			if !removed {
				return nil
			}
			recorder.RecordDeletion()
			if err := store.RecordEvent(storage.EventEntry{
				Action: "unban", IP: job.IP, RecordedAt: time.Now(),
			}); err != nil {
				log.Warn().Err(err).Str("ip", job.IP).Msg("failed to record unban event")
			}
		}
		log.Debug().Str("action", job.Action).Str("ip", job.IP).Strs("sites", cfg.UnifiSites).Msg("job applied")
		return nil
	}
}

func metricsHandler() http.Handler {
	return promhttp.Handler()
}
