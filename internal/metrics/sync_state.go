package metrics

import (
	"fmt"
	"sort"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// UnsyncedCount is the number of bans not yet enforced for one site and
// address family.
type UnsyncedCount struct {
	Site   string `json:"site"`
	Family string `json:"family"`
	Count  int    `json:"count"`
}

// SyncState is the firewall sync state the gauges hold, read back for the
// status endpoint so it reports exactly what /metrics does.
type SyncState struct {
	DirtyShards        int
	Unsynced           []UnsyncedCount // non-zero entries only, by site then family
	CircuitBreakerOpen bool
	LastSync           time.Time // zero until a sync has written every dirty shard
}

// UnsyncedTotal is the number of unenforced bans across sites and families.
func (s SyncState) UnsyncedTotal() int {
	total := 0
	for _, u := range s.Unsynced {
		total += u.Count
	}
	return total
}

// ReadSyncState reads the dirty shard, unsynced IP, circuit breaker and last
// sync gauges.
func ReadSyncState() (SyncState, error) {
	dirty, err := gaugeValue(DirtyShards)
	if err != nil {
		return SyncState{}, err
	}
	breaker, err := gaugeValue(CircuitBreakerState)
	if err != nil {
		return SyncState{}, err
	}
	last, err := gaugeValue(LastSyncTimestamp)
	if err != nil {
		return SyncState{}, err
	}
	unsynced, err := unsyncedCounts()
	if err != nil {
		return SyncState{}, err
	}
	state := SyncState{DirtyShards: int(dirty), Unsynced: unsynced, CircuitBreakerOpen: breaker == 1}
	if last > 0 {
		sec := int64(last)
		state.LastSync = time.Unix(sec, int64((last-float64(sec))*1e9)).UTC()
	}
	return state, nil
}

func gaugeValue(g prometheus.Gauge) (float64, error) {
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return 0, fmt.Errorf("read gauge: %w", err)
	}
	return m.GetGauge().GetValue(), nil
}

// unsyncedCounts returns the non-zero UnsyncedIPs series.
func unsyncedCounts() ([]UnsyncedCount, error) {
	ch := make(chan prometheus.Metric)
	go func() {
		UnsyncedIPs.Collect(ch)
		close(ch)
	}()
	var counts []UnsyncedCount
	var firstErr error
	for metric := range ch {
		var m dto.Metric
		if err := metric.Write(&m); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read unsynced_ips: %w", err)
			}
			continue
		}
		count := int(m.GetGauge().GetValue())
		if count == 0 {
			continue
		}
		u := UnsyncedCount{Count: count}
		for _, label := range m.GetLabel() {
			switch label.GetName() {
			case "site":
				u.Site = label.GetValue()
			case "family":
				u.Family = label.GetValue()
			}
		}
		counts = append(counts, u)
	}
	sort.Slice(counts, func(i, j int) bool {
		if counts[i].Site != counts[j].Site {
			return counts[i].Site < counts[j].Site
		}
		return counts[i].Family < counts[j].Family
	})
	return counts, firstErr
}
