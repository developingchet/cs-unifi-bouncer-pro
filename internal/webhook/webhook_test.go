package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

func TestNotifier_FiresOnEvent(t *testing.T) {
	var captured []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(srv.URL, nil, zerolog.Nop())
	n.Fire(context.Background(), "test_event", map[string]string{"key": "val"})

	var payload Event
	if err := json.Unmarshal(captured, &payload); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if payload.Event != "test_event" {
		t.Errorf("event: got %q, want %q", payload.Event, "test_event")
	}
	if payload.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestNotifier_SkipsUnregisteredEvent(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(srv.URL, []string{"circuit_breaker_open"}, zerolog.Nop())
	n.Fire(context.Background(), "ban_spike", nil) // not in allowed set
	if calls != 0 {
		t.Errorf("expected 0 HTTP calls, got %d", calls)
	}
	n.Fire(context.Background(), "circuit_breaker_open", nil) // in allowed set
	if calls != 1 {
		t.Errorf("expected 1 HTTP call, got %d", calls)
	}
}

func TestNotifier_IgnoresHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	n := New(srv.URL, nil, zerolog.Nop())
	// Must not panic
	n.Fire(context.Background(), "test", nil)
}

func TestNotifier_IgnoresConnectError(t *testing.T) {
	// Point to a non-existent server; use short timeout
	n := New("http://127.0.0.1:1", nil, zerolog.Nop())
	n.client.Timeout = 100 * time.Millisecond
	// Must not panic
	n.Fire(context.Background(), "test", nil)
}

func TestNotifier_EmptyURLDisabled(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New("", nil, zerolog.Nop())
	n.Fire(context.Background(), "test", nil)
	if calls != 0 {
		t.Errorf("expected 0 calls with empty URL, got %d", calls)
	}
}

func TestNotifier_PayloadIsValidJSON(t *testing.T) {
	var rawBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rawBody, _ = io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type: got %q, want application/json", r.Header.Get("Content-Type"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := New(srv.URL, nil, zerolog.Nop())
	n.Fire(context.Background(), "test_event", map[string]int{"count": 42})

	var payload map[string]any
	if err := json.Unmarshal(rawBody, &payload); err != nil {
		t.Fatalf("payload is not valid JSON: %v", err)
	}
	if _, ok := payload["event"]; !ok {
		t.Error("payload missing 'event' field")
	}
	if _, ok := payload["timestamp"]; !ok {
		t.Error("payload missing 'timestamp' field")
	}
}
