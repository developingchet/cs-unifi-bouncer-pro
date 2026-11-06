package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
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

// JobHandler applies jobs in order and returns one error per job, nil when
// the job was applied or needed no change. Consecutive bans are claimed
// together, and the history events of the whole call are written at once.
type JobHandler func(ctx context.Context, jobs []SyncJob) []error

var errNoSource = errors.New("decision source is required")

// jobApplier is the JobHandler of the daemon.
type jobApplier struct {
	store    storage.Store
	claims   *banstate.Manager
	cfg      *config.Config
	recorder MetricsRecorder
	log      zerolog.Logger
}

func makeJobHandler(
	store storage.Store,
	claims *banstate.Manager,
	cfg *config.Config,
	recorder MetricsRecorder,
	log zerolog.Logger,
) JobHandler {
	a := &jobApplier{store: store, claims: claims, cfg: cfg, recorder: recorder, log: log}
	return a.handle
}

func (a *jobApplier) handle(ctx context.Context, jobs []SyncJob) []error {
	errs := make([]error, len(jobs))
	if a.cfg.DryRun {
		for i, job := range jobs {
			if errs[i] = checkAction(job); errs[i] == nil {
				a.log.Info().Str("action", job.Action).Str("ip", job.IP).Msg("[DRY-RUN] would update ban")
			}
		}
		return errs
	}
	var events []storage.EventEntry
	for start := 0; start < len(jobs); {
		end := start + 1
		if jobs[start].Action == "ban" {
			for end < len(jobs) && jobs[end].Action == "ban" {
				end++
			}
			events = a.applyBans(ctx, jobs[start:end], errs[start:end], events)
		} else {
			var event *storage.EventEntry
			if event, errs[start] = a.applyDelete(ctx, jobs[start]); event != nil {
				events = append(events, *event)
			}
		}
		start = end
	}
	if len(events) > 0 {
		if err := a.store.RecordEvents(events); err != nil {
			a.log.Warn().Err(err).Int("events", len(events)).Msg("failed to record ban history events")
		}
	}
	return errs
}

func checkAction(job SyncJob) error {
	if job.Action != "ban" && job.Action != "delete" {
		return fmt.Errorf("unknown decision action %q", job.Action)
	}
	return nil
}

// applyBans claims jobs, which are all bans, in one batch and appends the
// history event of each ban that took effect.
func (a *jobApplier) applyBans(ctx context.Context, jobs []SyncJob, errs []error, events []storage.EventEntry) []storage.EventEntry {
	claims := make([]banstate.Claim, 0, len(jobs))
	index := make([]int, 0, len(jobs)) // claims[k] is jobs[index[k]]
	for i, job := range jobs {
		if job.Source == "" {
			errs[i] = errNoSource
			continue
		}
		claims = append(claims, banstate.Claim{IP: job.IP, IPv6: job.IPv6, Source: job.Source, Expiry: a.banExpiry(job)})
		index = append(index, i)
	}
	results, err := a.claims.ClaimBatch(ctx, claims)
	for k, i := range index {
		if k >= len(results) {
			errs[i] = fmt.Errorf("apply ban: %w", err)
			continue
		}
		if results[k].Err != nil {
			errs[i] = results[k].Err
			continue
		}
		if !results[k].Added {
			continue
		}
		job := jobs[i]
		if !job.ReceivedAt.IsZero() {
			metrics.DecisionLatency.Observe(time.Since(job.ReceivedAt).Seconds())
		}
		a.recorder.RecordBan(job.Origin, job.RemediationType)
		events = append(events, storage.EventEntry{
			Action: "ban", Origin: job.Origin, Scenario: job.Scenario,
			IP: job.IP, RecordedAt: time.Now(),
		})
		a.log.Debug().Str("action", job.Action).Str("ip", job.IP).Strs("sites", a.cfg.UnifiSites).Msg("job applied")
	}
	return events
}

// banExpiry caps a ban's expiry at BAN_TTL unless a scenario duration
// override set it.
func (a *jobApplier) banExpiry(job SyncJob) time.Time {
	expiry := job.ExpiresAt
	if expiry.IsZero() || (!job.DurationOverride && time.Until(expiry) > a.cfg.BanTTL) {
		expiry = time.Now().Add(a.cfg.BanTTL)
	}
	return expiry
}

// applyDelete releases the claim of job. It returns the history event to
// record when the address was unbanned.
func (a *jobApplier) applyDelete(ctx context.Context, job SyncJob) (*storage.EventEntry, error) {
	if err := checkAction(job); err != nil {
		return nil, err
	}
	if job.Source == "" {
		return nil, errNoSource
	}
	removed, err := a.claims.Release(ctx, job.IP, job.Source)
	if err != nil {
		return nil, fmt.Errorf("apply unban: %w", err)
	}
	if !removed {
		return nil, nil
	}
	a.recorder.RecordDeletion()
	a.log.Debug().Str("action", job.Action).Str("ip", job.IP).Strs("sites", a.cfg.UnifiSites).Msg("job applied")
	return &storage.EventEntry{Action: "unban", IP: job.IP, RecordedAt: time.Now()}, nil
}

func metricsHandler() http.Handler {
	return promhttp.Handler()
}
