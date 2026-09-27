package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// recorder is a webhook endpoint that captures request bodies.
type recorder struct {
	mu     sync.Mutex
	bodies [][]byte
	status int
}

func (r *recorder) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	body, _ := io.ReadAll(req.Body)
	r.mu.Lock()
	r.bodies = append(r.bodies, body)
	status := r.status
	r.mu.Unlock()
	if status == 0 {
		status = http.StatusOK
	}
	if req.Header.Get("Content-Type") != "application/json" {
		status = http.StatusUnsupportedMediaType
	}
	w.WriteHeader(status)
}

func (r *recorder) events(t *testing.T) []Event {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Event, 0, len(r.bodies))
	for _, b := range r.bodies {
		var ev Event
		if err := json.Unmarshal(b, &ev); err != nil {
			t.Fatalf("payload is not valid JSON: %v (%s)", err, b)
		}
		out = append(out, ev)
	}
	return out
}

// fireAndStop queues events, then cancels Run and waits for it to drain.
func fireAndStop(t *testing.T, n *Notifier, fire func()) {
	t.Helper()
	fire()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

func TestNotifier_Delivery(t *testing.T) {
	tests := []struct {
		name       string
		allowed    []string
		fire       []string
		wantEvents []string
	}{
		{name: "all events allowed", fire: []string{"a", "b"}, wantEvents: []string{"a", "b"}},
		{name: "unregistered event skipped", allowed: []string{"circuit_breaker_open"},
			fire: []string{"ban_spike", "circuit_breaker_open"}, wantEvents: []string{"circuit_breaker_open"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := &recorder{}
			srv := httptest.NewServer(rec)
			defer srv.Close()

			n := New(srv.URL, tt.allowed, zerolog.Nop())
			fireAndStop(t, n, func() {
				for _, e := range tt.fire {
					n.Fire(e, map[string]int{"count": 42})
				}
			})

			got := rec.events(t)
			if len(got) != len(tt.wantEvents) {
				t.Fatalf("delivered %d events, want %d", len(got), len(tt.wantEvents))
			}
			for i, ev := range got {
				if ev.Event != tt.wantEvents[i] {
					t.Errorf("event %d = %q, want %q", i, ev.Event, tt.wantEvents[i])
				}
				if ev.Timestamp.IsZero() {
					t.Errorf("event %d has zero timestamp", i)
				}
				if ev.Detail == nil {
					t.Errorf("event %d missing detail", i)
				}
			}
		})
	}
}

func TestNotifier_DeliversWhileRunning(t *testing.T) {
	got := make(chan struct{}, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		got <- struct{}{}
	}))
	defer srv.Close()

	n := New(srv.URL, nil, zerolog.Nop())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go n.Run(ctx)
	n.Fire("test", nil)
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("event not delivered while running")
	}
}

func TestNotifier_FireDoesNotBlock(t *testing.T) {
	n := New("http://127.0.0.1:1", nil, zerolog.Nop())
	// No Run: the queue fills, and further events are dropped rather than blocking.
	start := time.Now()
	for i := 0; i < queueSize*2; i++ {
		n.Fire("test", nil)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Fire blocked for %v", elapsed)
	}
	if len(n.queue) != queueSize {
		t.Fatalf("queue length = %d, want %d", len(n.queue), queueSize)
	}
}

func TestNotifier_EmptyURLDisabled(t *testing.T) {
	n := New("", nil, zerolog.Nop())
	n.Fire("test", nil)
	if len(n.queue) != 0 {
		t.Fatalf("event queued with empty URL")
	}
	fireAndStop(t, n, func() {})
}

func TestNotifier_ErrorsDoNotLeakURL(t *testing.T) {
	const secretPath = "/services/T000/B000/secret-token"
	tests := []struct {
		name   string
		server bool
		want   string
	}{
		{name: "HTTP error status", server: true, want: "server returned error status"},
		{name: "connect error", want: "delivery failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := "http://127.0.0.1:1"
			if tt.server {
				srv := httptest.NewServer(&recorder{status: http.StatusInternalServerError})
				defer srv.Close()
				base = srv.URL
			}
			var logs bytes.Buffer
			n := New(base+secretPath+"?token=abc", nil, zerolog.New(&logs))
			n.client.Timeout = 500 * time.Millisecond
			fireAndStop(t, n, func() { n.Fire("test", nil) })

			out := logs.String()
			if !strings.Contains(out, tt.want) {
				t.Fatalf("log missing %q: %s", tt.want, out)
			}
			if strings.Contains(out, "secret-token") || strings.Contains(out, "token=abc") {
				t.Fatalf("log leaks webhook URL: %s", out)
			}
		})
	}
}
