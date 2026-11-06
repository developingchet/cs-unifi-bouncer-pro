package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/webhook"
	"github.com/rs/zerolog"
)

// webhookReceiver records the events posted to it.
type webhookReceiver struct {
	mu     sync.Mutex
	events []webhook.Event
	srv    *httptest.Server
}

func newWebhookReceiver(t *testing.T) *webhookReceiver {
	t.Helper()
	r := &webhookReceiver{}
	r.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		var ev webhook.Event
		if err := json.Unmarshal(body, &ev); err != nil {
			t.Errorf("payload is not an event: %s", body)
		}
		r.mu.Lock()
		r.events = append(r.events, ev)
		r.mu.Unlock()
	}))
	t.Cleanup(r.srv.Close)
	return r
}

func (r *webhookReceiver) received() []webhook.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]webhook.Event(nil), r.events...)
}

// deliver runs fire, then stops the notifier and waits for it to drain.
func deliver(t *testing.T, n *webhook.Notifier, fire func()) {
	t.Helper()
	fire()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("notifier did not drain")
	}
}

func TestFirewallHooksSendShardEvents(t *testing.T) {
	rec := newWebhookReceiver(t)
	n := webhook.New(rec.srv.URL, nil, zerolog.Nop())
	_, _, events := firewallHooks(n)
	deliver(t, n, func() {
		failure := firewall.ShardCreateFailure{Site: "default", Family: "v4", Shard: "crowdsec-block-v4-2",
			UnsyncedIPs: 12, ConsecutiveFailures: 3, RetryIn: 2 * time.Minute}
		// A persistent failure raises the event at every retry; one is sent.
		events.CreateFailed(failure)
		events.CreateFailed(failure)
		events.EntryRefused(firewall.RefusedEntry{Site: "default", Family: "v4", Shard: "crowdsec-block-v4-0",
			Entry: "203.0.113.77", RetryIn: time.Hour})
	})

	got := rec.received()
	if len(got) != 2 {
		t.Fatalf("received %d events, want 2: %+v", len(got), got)
	}
	created := got[0].Detail.(map[string]any)
	if got[0].Event != webhook.EventShardCreateFailed || created["shard"] != "crowdsec-block-v4-2" ||
		created["unsynced_ips"] != float64(12) || created["retry_in_seconds"] != float64(120) {
		t.Errorf("shard create event = %+v", got[0])
	}
	refused := got[1].Detail.(map[string]any)
	if got[1].Event != webhook.EventBanEntryRefused || refused["entry"] != "203.0.113.77" || refused["site"] != "default" {
		t.Errorf("refused entry event = %+v", got[1])
	}
}

func TestFirewallHooksWithoutNotifier(t *testing.T) {
	cbOpen, cbClose, events := firewallHooks(nil)
	if cbOpen != nil || cbClose != nil || events.CreateFailed != nil || events.EntryRefused != nil {
		t.Fatal("hooks connected without a notifier")
	}
}

func TestPeriodicReconcileSendsModeChangeEvent(t *testing.T) {
	rec := newWebhookReceiver(t)
	n := webhook.New(rec.srv.URL, nil, zerolog.Nop())
	stub := &modeChangeStub{changed: &firewall.ModeChangeError{Site: "default", Reason: "the site now has firewall zones"}}
	modeChanged := make(chan error, 1)
	deliver(t, n, func() {
		runPeriodicReconcile(context.Background(), stub, []string{"default"}, 5*time.Millisecond, n, modeChanged, zerolog.Nop())
	})
	got := rec.received()
	if len(got) != 1 || got[0].Event != webhook.EventFirewallModeChanged {
		t.Fatalf("events = %+v, want one %s", got, webhook.EventFirewallModeChanged)
	}
	detail := got[0].Detail.(map[string]any)
	if detail["site"] != "default" || detail["reason"] != "the site now has firewall zones" {
		t.Errorf("detail = %v", detail)
	}
}

func TestCloudflareSyncFailureEventIsLimited(t *testing.T) {
	rec := newWebhookReceiver(t)
	n := webhook.New(rec.srv.URL, nil, zerolog.Nop())
	deliver(t, n, func() {
		fireCloudflareSyncFailed(n, "initial")
		fireCloudflareSyncFailed(n, "refresh")
	})
	got := rec.received()
	if len(got) != 1 || got[0].Event != webhook.EventCloudflareSyncFailed {
		t.Fatalf("events = %+v, want one %s", got, webhook.EventCloudflareSyncFailed)
	}
	if phase := got[0].Detail.(map[string]any)["phase"]; phase != "initial" {
		t.Errorf("phase = %v, want initial", phase)
	}
}

func TestWaitDrained(t *testing.T) {
	closed := make(chan struct{})
	close(closed)
	start := time.Now()
	waitDrained(closed, time.Minute)
	waitDrained(make(chan struct{}), 10*time.Millisecond)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("waitDrained took %v", elapsed)
	}
}
