package bouncer

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
)

func TestSyncStatusEndpoint(t *testing.T) {
	f := newControlFixture(t)
	last := time.Now().Add(-90 * time.Second)
	metrics.DirtyShards.Set(3)
	metrics.CircuitBreakerState.Set(1)
	metrics.LastSyncTimestamp.Set(float64(last.UnixNano()) / 1e9)
	metrics.UnsyncedIPs.WithLabelValues("v6", "status-site").Set(4)
	metrics.UnsyncedIPs.WithLabelValues("v4", "status-site").Set(2)
	t.Cleanup(func() {
		metrics.DirtyShards.Set(0)
		metrics.CircuitBreakerState.Set(0)
		metrics.LastSyncTimestamp.Set(0)
		metrics.UnsyncedIPs.DeleteLabelValues("v6", "status-site")
		metrics.UnsyncedIPs.DeleteLabelValues("v4", "status-site")
	})

	w := f.call(SyncStatusPath, "", callOpts{method: http.MethodGet})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q", ct)
	}
	var got SyncStatus
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if !got.StartupSynced || got.DirtyShards != 3 || !got.CircuitBreakerOpen {
		t.Errorf("status = %+v", got)
	}
	var site []metrics.UnsyncedCount
	for _, u := range got.UnsyncedBySite {
		if u.Site == "status-site" {
			site = append(site, u)
		}
	}
	if len(site) != 2 || site[0].Family != "v4" || site[0].Count != 2 || site[1].Family != "v6" || site[1].Count != 4 {
		t.Errorf("unsynced_by_site for the test site = %+v, want v4=2 then v6=4", site)
	}
	if got.UnsyncedIPs < 6 {
		t.Errorf("unsynced_ips = %d, want at least 6", got.UnsyncedIPs)
	}
	if got.LastSync == nil || got.LastSync.Sub(last).Abs() > time.Millisecond {
		t.Errorf("last_sync = %v, want %v", got.LastSync, last)
	}
	if got.LastSyncAgeSeconds == nil || *got.LastSyncAgeSeconds < 89 || *got.LastSyncAgeSeconds > 120 {
		t.Errorf("last_sync_age_seconds = %v, want about 90", got.LastSyncAgeSeconds)
	}
}

func TestSyncStatusBeforeFirstSync(t *testing.T) {
	status := newSyncStatus(metrics.SyncState{}, false, time.Now())
	data, err := json.Marshal(status)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"startup_synced":false,"dirty_shards":0,"unsynced_ips":0,"unsynced_by_site":[],"circuit_breaker_open":false,"last_sync":null}`
	if string(data) != want {
		t.Errorf("body = %s, want %s", data, want)
	}
}
