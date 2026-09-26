package main

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// startupReconcileFallback bounds how long reconciles wait for the first LAPI
// batch when the ban database already holds bans.
const startupReconcileFallback = 5 * time.Minute

// gateReconciles calls start once the ban database can be trusted to remove
// IPs from the controller: after the first LAPI batch has been applied
// (registered through onSynced), or after fallback when the database already
// holds bans, such as a restart with an intact volume while the LAPI is
// unreachable. An empty database keeps waiting for the LAPI, because
// reconciling it would strip every enforced ban from the controller.
func gateReconciles(ctx context.Context, onSynced func(func()), banCount func() (int, error),
	fallback time.Duration, start func(), log zerolog.Logger,
) {
	var started atomic.Bool
	once := sync.OnceFunc(func() {
		started.Store(true)
		start()
	})
	onSynced(once)
	go func() {
		timer := time.NewTimer(fallback)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		if started.Load() {
			return
		}
		n, err := banCount()
		switch {
		case err != nil:
			log.Warn().Err(err).Msg("no CrowdSec decisions yet and the ban database is unreadable; reconcile waits for the LAPI")
		case n == 0:
			log.Warn().Msg("no CrowdSec decisions yet and the ban database is empty; reconcile waits for the LAPI")
		default:
			log.Warn().Int("bans", n).Stringer("waited", fallback).
				Msg("no CrowdSec decisions yet; reconciling from the existing ban database")
			once()
		}
	}()
}
