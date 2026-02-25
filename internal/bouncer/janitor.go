package bouncer

import (
	"context"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// Janitor performs periodic housekeeping: pruning expired bans, updating gauges.
type Janitor struct {
	store    storage.Store
	fwMgr    firewall.Manager
	sites    []string
	interval time.Duration
	log      zerolog.Logger
}

// NewJanitor creates a Janitor. The fwMgr is used to call ApplyUnban on expired
// bans before they are pruned from bbolt, keeping UniFi state consistent.
func NewJanitor(store storage.Store, fwMgr firewall.Manager, sites []string,
	interval time.Duration, log zerolog.Logger) *Janitor {
	return &Janitor{
		store:    store,
		fwMgr:    fwMgr,
		sites:    sites,
		interval: interval,
		log:      log,
	}
}

// Run executes the janitor loop until ctx is cancelled.
func (j *Janitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()

	// Run immediately on start
	j.tick(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			j.tick(ctx)
		}
	}
}

func (j *Janitor) tick(ctx context.Context) {
	// Unban expired IPs from UniFi before pruning them from bbolt.
	banList, err := j.store.BanList()
	if err != nil {
		j.log.Warn().Err(err).Msg("janitor: failed to list bans for expiry reap")
	} else {
		now := time.Now()
		type expiredEntry struct {
			ip   string
			ipv6 bool
		}
		var expired []expiredEntry
		for ip, entry := range banList {
			if !entry.ExpiresAt.IsZero() && entry.ExpiresAt.Before(now) {
				expired = append(expired, expiredEntry{ip: ip, ipv6: entry.IPv6})
			}
		}
		if len(expired) > 0 {
			j.log.Info().Int("count", len(expired)).Msg("expiry reaper: unbanning expired IPs")
			for _, e := range expired {
				for _, site := range j.sites {
					if err := j.fwMgr.ApplyUnban(ctx, site, e.ip, e.ipv6); err != nil {
						j.log.Warn().Err(err).Str("ip", e.ip).Str("site", site).
							Msg("expiry reaper: unban failed")
					}
				}
			}
		}
	}

	// Prune expired bans from bbolt.
	pruned, err := j.store.PruneExpiredBans()
	if err != nil {
		j.log.Warn().Err(err).Msg("janitor: prune expired bans failed")
	} else {
		j.log.Info().Int("pruned", pruned).Msg("janitor: pruned expired bans from bbolt")
	}

	// Update DB size gauge.
	size, err := j.store.SizeBytes()
	if err != nil {
		j.log.Warn().Err(err).Msg("janitor: read db size failed")
	} else {
		metrics.DBSizeBytes.Set(float64(size))
	}

	j.log.Debug().Msg("janitor: tick complete")
}
