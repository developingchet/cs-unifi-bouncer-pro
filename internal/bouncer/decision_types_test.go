package bouncer

import (
	"context"
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
)

func TestBouncer_BlockDecisionTypes(t *testing.T) {
	tests := []struct {
		name     string
		types    []string
		wantJobs int
	}{
		{"captcha dropped by default", nil, 0},
		{"captcha banned when listed", []string{"ban", "captcha"}, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.Config{UnifiSites: []string{"default"}, BanTTL: time.Hour, BlockDecisionTypes: tt.types}
			b := newTestBouncer(t, cfg)
			var jobs []SyncJob
			b.handler = func(_ context.Context, batch []SyncJob) []error {
				jobs = append(jobs, batch...)
				return make([]error, len(batch))
			}
			typ, scope, ip := "captcha", "ip", "198.51.100.9"
			d := &models.Decision{ID: 7, Type: &typ, Scope: &scope, Value: &ip}
			b.handleDecisionBlock(context.Background(), &models.DecisionsStreamResponse{New: []*models.Decision{d}}, "stream")
			if len(jobs) != tt.wantJobs {
				t.Fatalf("jobs = %+v, want %d", jobs, tt.wantJobs)
			}
			if tt.wantJobs == 1 && (jobs[0].Action != "ban" || jobs[0].RemediationType != "captcha") {
				t.Fatalf("job = %+v, want a ban with remediation type captcha", jobs[0])
			}
		})
	}
}
