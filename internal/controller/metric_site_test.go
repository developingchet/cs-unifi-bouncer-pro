package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	promtest "github.com/prometheus/client_golang/prometheus/testutil"
)

func TestAPIMetricsCarryTheSite(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"meta":{"rc":"ok"},"data":[]}`))
	}))
	defer srv.Close()
	c := newTestClient(srv.URL, "api-key")
	ctx := context.Background()

	calls := metrics.APICalls.WithLabelValues("list-groups", "2xx", "metrics-site")
	before := promtest.ToFloat64(calls)
	if _, err := c.ListFirewallGroups(ctx, "metrics-site"); err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if got := promtest.ToFloat64(calls) - before; got != 1 {
		t.Errorf("api_calls_total{endpoint=list-groups,site=metrics-site} rose by %v, want 1", got)
	}

	siteless := metrics.APICalls.WithLabelValues("ping", "2xx", "")
	before = promtest.ToFloat64(siteless)
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if got := promtest.ToFloat64(siteless) - before; got != 1 {
		t.Errorf("api_calls_total{endpoint=ping,site=\"\"} rose by %v, want 1", got)
	}
}
