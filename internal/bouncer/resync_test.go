package bouncer

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

const resyncDecisions = `[
 {"id":1,"origin":"crowdsec","scenario":"ssh-bf","scope":"Ip","type":"ban","value":"203.0.113.1","duration":"3h"},
 {"id":2,"origin":"crowdsec","scenario":"ssh-bf","scope":"Ip","type":"ban","value":"203.0.113.2","duration":"3h"},
 {"id":3,"origin":"crowdsec","scenario":"ssh-bf","scope":"Ip","type":"ban","value":"10.0.0.5","duration":"3h"}
]`

func newResyncBouncer(t *testing.T, body string, status int) (*Bouncer, *[]SyncJob, *int) {
	t.Helper()
	requests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/decisions" || r.Header.Get("X-Api-Key") != "test-key" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	cfg := &config.Config{
		UnifiSites:      []string{"default"},
		BanTTL:          24 * time.Hour,
		CrowdSecLAPIURL: srv.URL,
		CrowdSecLAPIKey: "test-key",
	}
	b := newTestBouncer(t, cfg)
	var jobs []SyncJob
	b.handler = func(_ context.Context, job SyncJob) error {
		jobs = append(jobs, job)
		return nil
	}
	return b, &jobs, &requests
}

func TestResync_AppliesOnlyUnclaimedDecisions(t *testing.T) {
	b, jobs, _ := newResyncBouncer(t, resyncDecisions, http.StatusOK)
	if err := b.store.BanPut("203.0.113.1", storage.BanEntry{
		Claims: map[string]time.Time{"crowdsec:id:1": time.Now().Add(time.Hour)},
	}); err != nil {
		t.Fatal(err)
	}

	if err := b.resync(context.Background()); err != nil {
		t.Fatalf("resync: %v", err)
	}
	// id 1 is claimed and id 3 is a private address the filter rejects.
	if len(*jobs) != 1 || (*jobs)[0].Source != "crowdsec:id:2" || (*jobs)[0].Action != "ban" {
		t.Fatalf("jobs = %+v, want one ban for crowdsec:id:2", *jobs)
	}
	if _, ok := b.resyncRejected["crowdsec:id:3"]; !ok {
		t.Fatalf("rejected decision not remembered: %v", b.resyncRejected)
	}
}

func TestResync_ForgetsRejectedDecisionsThatExpire(t *testing.T) {
	b, _, _ := newResyncBouncer(t, `[]`, http.StatusOK)
	b.resyncRejected = map[string]struct{}{"crowdsec:id:9": {}}
	if err := b.resync(context.Background()); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if len(b.resyncRejected) != 0 {
		t.Fatalf("resyncRejected = %v, want empty", b.resyncRejected)
	}
}

func TestResync_Errors(t *testing.T) {
	tests := []struct {
		name   string
		body   string
		status int
		want   string
	}{
		{"server error", `oops`, http.StatusInternalServerError, "500"},
		{"bad json", `{"not":"a list"}`, http.StatusOK, "decode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, jobs, _ := newResyncBouncer(t, tt.body, tt.status)
			err := b.resync(context.Background())
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tt.want)
			}
			if len(*jobs) != 0 {
				t.Fatalf("jobs applied despite error: %+v", *jobs)
			}
		})
	}
}

func TestResync_NullListIsEmpty(t *testing.T) {
	b, jobs, requests := newResyncBouncer(t, `null`, http.StatusOK)
	if err := b.resync(context.Background()); err != nil {
		t.Fatalf("resync: %v", err)
	}
	if *requests != 1 || len(*jobs) != 0 {
		t.Fatalf("requests=%d jobs=%+v", *requests, *jobs)
	}
}

func TestDecodeDecisions_RejectsOversizedBody(t *testing.T) {
	body := strings.NewReader("[" + strings.Repeat(" ", resyncMaxBody) + "]")
	if _, err := decodeDecisions(body); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("err = %v, want size error", err)
	}
}
