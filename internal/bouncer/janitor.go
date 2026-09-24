package bouncer

import (
	"context"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

type Janitor struct {
	store    storage.Store
	claims   *banstate.Manager
	interval time.Duration
	log      zerolog.Logger
}

func NewJanitor(store storage.Store, fwMgr firewall.Manager, sites []string,
	interval time.Duration, log zerolog.Logger, shared ...*banstate.Manager) *Janitor {
	claims := banstate.New(store, fwMgr, sites, false)
	if len(shared) > 0 && shared[0] != nil {
		claims = shared[0]
	}
	return &Janitor{store: store, claims: claims, interval: interval, log: log}
}

func (j *Janitor) Run(ctx context.Context) error {
	ticker := time.NewTicker(j.interval)
	defer ticker.Stop()
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
	bans, err := j.store.BanList()
	if err != nil {
		j.log.Warn().Err(err).Msg("janitor: failed to list bans")
	} else {
		now := time.Now()
		for ip, entry := range bans {
			if !hasExpiredClaim(entry, now) {
				continue
			}
			removed, err := j.claims.Expire(ctx, ip)
			if err != nil {
				j.log.Warn().Err(err).Str("ip", ip).Msg("janitor: failed to expire ban")
				continue
			}
			if removed {
				if err := j.store.RecordEvent(storage.EventEntry{
					Action: "expire", Origin: "expired", IP: ip, RecordedAt: now,
				}); err != nil {
					j.log.Warn().Err(err).Str("ip", ip).Msg("janitor: failed to record expiry")
				}
			}
		}
	}
	if size, err := j.store.SizeBytes(); err == nil {
		metrics.DBSizeBytes.Set(float64(size))
	} else {
		j.log.Warn().Err(err).Msg("janitor: read db size failed")
	}
}

func hasExpiredClaim(entry storage.BanEntry, now time.Time) bool {
	if entry.Claims == nil {
		return !entry.ExpiresAt.IsZero() && !entry.ExpiresAt.After(now)
	}
	for _, expiry := range entry.Claims {
		if !expiry.IsZero() && !expiry.After(now) {
			return true
		}
	}
	return false
}
