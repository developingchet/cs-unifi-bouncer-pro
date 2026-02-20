package metrics_test

import (
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

// TestMetricCollectorsNonNil verifies all 15 package-level metric variables
// are non-nil and pass Prometheus linting rules.
func TestMetricCollectorsNonNil(t *testing.T) {
	tests := []struct {
		name string
		c    prometheus.Collector
	}{
		{"DecisionsProcessed", metrics.DecisionsProcessed},
		{"DecisionsFiltered", metrics.DecisionsFiltered},
		{"JobsEnqueued", metrics.JobsEnqueued},
		{"JobsDropped", metrics.JobsDropped},
		{"JobsProcessed", metrics.JobsProcessed},
		{"APICalls", metrics.APICalls},
		{"APIDuration", metrics.APIDuration},
		{"AuthErrors", metrics.AuthErrors},
		{"ReauthTotal", metrics.ReauthTotal},
		{"ActiveBans", metrics.ActiveBans},
		{"FirewallGroupSize", metrics.FirewallGroupSize},
		{"DBSizeBytes", metrics.DBSizeBytes},
		{"WorkerQueueDepth", metrics.WorkerQueueDepth},
		{"ReconcileDuration", metrics.ReconcileDuration},
		{"ReconcileDelta", metrics.ReconcileDelta},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.c == nil {
				t.Fatal("collector is nil")
			}
			lintErrs, err := testutil.CollectAndLint(tc.c)
			if err != nil {
				t.Errorf("CollectAndLint gather error: %v", err)
			}
			if len(lintErrs) > 0 {
				t.Errorf("prometheus lint errors: %v", lintErrs)
			}
		})
	}
}

// TestMetricNamesAndHelp verifies all expected metrics are registered under the
// crowdsec_unifi_ namespace and have non-empty help strings.
// Uses Describe() rather than Gather() so Vec metrics with no observations
// are checked correctly.
func TestMetricNamesAndHelp(t *testing.T) {
	// Map of expected fqName → collector that should produce it.
	cases := []struct {
		name string
		c    prometheus.Collector
	}{
		{"crowdsec_unifi_decisions_processed_total", metrics.DecisionsProcessed},
		{"crowdsec_unifi_decisions_filtered_total", metrics.DecisionsFiltered},
		{"crowdsec_unifi_jobs_enqueued_total", metrics.JobsEnqueued},
		{"crowdsec_unifi_jobs_dropped_total", metrics.JobsDropped},
		{"crowdsec_unifi_jobs_processed_total", metrics.JobsProcessed},
		{"crowdsec_unifi_api_calls_total", metrics.APICalls},
		{"crowdsec_unifi_api_duration_seconds", metrics.APIDuration},
		{"crowdsec_unifi_auth_errors_total", metrics.AuthErrors},
		{"crowdsec_unifi_reauth_total", metrics.ReauthTotal},
		{"crowdsec_unifi_active_bans", metrics.ActiveBans},
		{"crowdsec_unifi_firewall_group_size", metrics.FirewallGroupSize},
		{"crowdsec_unifi_db_size_bytes", metrics.DBSizeBytes},
		{"crowdsec_unifi_worker_queue_depth", metrics.WorkerQueueDepth},
		{"crowdsec_unifi_reconcile_duration_seconds", metrics.ReconcileDuration},
		{"crowdsec_unifi_reconcile_delta", metrics.ReconcileDelta},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan *prometheus.Desc, 32)
			go func() {
				tc.c.Describe(ch)
				close(ch)
			}()

			found := false
			for d := range ch {
				s := d.String()
				// Desc.String() format:
				//   Desc{fqName: "crowdsec_unifi_foo", help: "Some help.", ...}
				if strings.Contains(s, tc.name) {
					found = true
					if strings.Contains(s, `help: ""`) {
						t.Errorf("descriptor for %s has an empty help string", tc.name)
					}
					if !strings.HasPrefix(tc.name, "crowdsec_unifi_") {
						t.Errorf("metric name %s does not have crowdsec_unifi_ prefix", tc.name)
					}
				}
			}
			if !found {
				t.Errorf("no descriptor containing %q returned by Describe()", tc.name)
			}
		})
	}
}
