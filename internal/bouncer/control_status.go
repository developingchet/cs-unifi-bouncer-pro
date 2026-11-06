package bouncer

import (
	"net/http"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

// SyncStatus is the body of a GET to SyncStatusPath: the firewall sync state
// that the dirty_shards, unsynced_ips, circuit_breaker_open and
// last_sync_timestamp_seconds metrics expose.
type SyncStatus struct {
	// StartupSynced is true once the first CrowdSec decision batch has
	// been applied.
	StartupSynced bool `json:"startup_synced"`
	// DirtyShards is the number of shards waiting to be written at the last sync.
	DirtyShards int `json:"dirty_shards"`
	// UnsyncedIPs is the number of bans not enforced on the controller yet.
	UnsyncedIPs int `json:"unsynced_ips"`
	// UnsyncedBySite breaks UnsyncedIPs down; only non-zero entries appear.
	UnsyncedBySite []metrics.UnsyncedCount `json:"unsynced_by_site"`
	// CircuitBreakerOpen is true while controller writes are suspended.
	CircuitBreakerOpen bool `json:"circuit_breaker_open"`
	// LastSync is when a sync last wrote every dirty shard; null before the first.
	LastSync *time.Time `json:"last_sync"`
	// LastSyncAgeSeconds is the time since LastSync; absent before the first.
	LastSyncAgeSeconds *float64 `json:"last_sync_age_seconds,omitempty"`
}

func (c *control) syncStatus(w http.ResponseWriter, _ *http.Request) {
	state, err := metrics.ReadSyncState()
	if err != nil {
		c.log.Warn().Err(err).Msg("read sync state")
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "sync state unavailable"})
		return
	}
	synced := c.synced != nil && c.synced()
	writeJSON(w, http.StatusOK, newSyncStatus(state, synced, time.Now()))
}

func newSyncStatus(state metrics.SyncState, synced bool, now time.Time) SyncStatus {
	status := SyncStatus{
		StartupSynced:      synced,
		DirtyShards:        state.DirtyShards,
		UnsyncedIPs:        state.UnsyncedTotal(),
		UnsyncedBySite:     state.Unsynced,
		CircuitBreakerOpen: state.CircuitBreakerOpen,
	}
	if status.UnsyncedBySite == nil {
		status.UnsyncedBySite = []metrics.UnsyncedCount{}
	}
	if !state.LastSync.IsZero() {
		last := state.LastSync
		age := now.Sub(last).Seconds()
		status.LastSync = &last
		status.LastSyncAgeSeconds = &age
	}
	return status
}
