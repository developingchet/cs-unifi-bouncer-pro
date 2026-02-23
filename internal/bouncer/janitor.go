package bouncer

import (
	"context"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// Janitor performs periodic housekeeping: pruning expired bans, updating gauges.
type Janitor struct {
	store    storage.Store
	interval time.Duration
	log      zerolog.Logger
}

// NewJanitor creates a Janitor.
func NewJanitor(store storage.Store, interval time.Duration, log zerolog.Logger) *Janitor {
	return &Janitor{
		store:    store,
		interval: interval,
		log:      log,
	}
}

// Run executes the janitor loop until ctx is cancelled.
func (j *Janitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on start
	j.tick()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			j.tick()
		}
	}
}

func (j *Janitor) tick() {
	// Prune expired bans
	pruned, err := j.store.PruneExpiredBans()
	if err != nil {
		j.log.Warn().Err(err).Msg("janitor: prune expired bans failed")
	} else if pruned > 0 {
		j.log.Info().Int("count", pruned).Msg("janitor: pruned expired bans")
	}

	// Update DB size gauge
	size, err := j.store.SizeBytes()
	if err != nil {
		j.log.Warn().Err(err).Msg("janitor: read db size failed")
	} else {
		metrics.DBSizeBytes.Set(float64(size))
	}

	j.log.Debug().Msg("janitor: tick complete")
}
