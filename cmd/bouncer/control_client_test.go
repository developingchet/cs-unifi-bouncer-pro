package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

func TestDaemonRunning(t *testing.T) {
	dir := t.TempDir()
	if daemonRunning(dir) {
		t.Fatal("daemon reported running without a database")
	}
	store, err := storage.NewBboltStore(dir, zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if !daemonRunning(dir) {
		t.Error("daemon not reported running while the database is held")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	if daemonRunning(dir) {
		t.Error("daemon reported running after the database was released")
	}
}

// fakeDaemon is a health server that records control requests.
type fakeDaemon struct {
	mu       sync.Mutex
	requests []recordedRequest
	status   int
	reply    any
	dataDir  string
}

type recordedRequest struct {
	method, path, token, contentType, body string
}

func newFakeDaemon(t *testing.T, status int, reply any) *fakeDaemon {
	t.Helper()
	d := &fakeDaemon{status: status, reply: reply, dataDir: t.TempDir()}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		d.mu.Lock()
		d.requests = append(d.requests, recordedRequest{r.Method, r.URL.Path, r.Header.Get(bouncer.SnapshotTokenHeader),
			r.Header.Get("Content-Type"), string(body)})
		d.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(d.status)
		_ = json.NewEncoder(w).Encode(d.reply)
	}))
	t.Cleanup(srv.Close)
	t.Setenv("HEALTH_ADDR", strings.TrimPrefix(srv.URL, "http://"))
	if err := os.WriteFile(filepath.Join(d.dataDir, bouncer.SnapshotTokenFile), []byte("secret-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return d
}

func (d *fakeDaemon) only(t *testing.T) recordedRequest {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.requests) != 1 {
		t.Fatalf("daemon received %d requests, want 1", len(d.requests))
	}
	return d.requests[0]
}

func TestBanThroughDaemon(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC()
	d := newFakeDaemon(t, http.StatusOK, bouncer.ControlResponse{IP: "198.51.100.7", Sites: 2, ExpiresAt: &expires})
	if err := banThroughDaemon(context.Background(), d.dataDir, "198.51.100.7", 90*time.Minute); err != nil {
		t.Fatal(err)
	}
	req := d.only(t)
	if req.method != http.MethodPost || req.path != bouncer.ControlBanPath || req.token != "secret-token" ||
		req.contentType != "application/json" {
		t.Fatalf("request = %+v", req)
	}
	var body bouncer.ControlBanRequest
	if err := json.Unmarshal([]byte(req.body), &body); err != nil || body.IP != "198.51.100.7" || body.Duration != "1h30m0s" {
		t.Fatalf("body = %s (%v)", req.body, err)
	}
}

func TestBanThroughDaemonZeroDurationUsesBanTTL(t *testing.T) {
	d := newFakeDaemon(t, http.StatusOK, bouncer.ControlResponse{IP: "198.51.100.7", Sites: 1})
	if err := banThroughDaemon(context.Background(), d.dataDir, "198.51.100.7", 0); err != nil {
		t.Fatal(err)
	}
	if body := d.only(t).body; strings.Contains(body, "duration") {
		t.Fatalf("body = %s, want no duration so the daemon applies BAN_TTL", body)
	}
}

func TestControlClientReportsDaemonErrors(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		d := newFakeDaemon(t, http.StatusBadRequest, bouncer.ErrorResponse{Error: "refusing to ban 10.0.0.1: private"})
		err := banThroughDaemon(context.Background(), d.dataDir, "10.0.0.1", 0)
		if err == nil || !strings.Contains(err.Error(), "refusing to ban 10.0.0.1") {
			t.Fatalf("err = %v, want the daemon's message", err)
		}
	})
	t.Run("not written to UniFi", func(t *testing.T) {
		d := newFakeDaemon(t, http.StatusOK, bouncer.ControlResponse{IP: "198.51.100.7", SyncError: "circuit breaker open"})
		err := unbanThroughDaemon(context.Background(), d.dataDir, "198.51.100.7")
		if err == nil || !strings.Contains(err.Error(), "circuit breaker open") {
			t.Fatalf("err = %v, want the sync error", err)
		}
	})
	t.Run("no token file", func(t *testing.T) {
		d := newFakeDaemon(t, http.StatusOK, bouncer.ControlResponse{})
		if err := os.Remove(filepath.Join(d.dataDir, bouncer.SnapshotTokenFile)); err != nil {
			t.Fatal(err)
		}
		if err := banThroughDaemon(context.Background(), d.dataDir, "198.51.100.7", 0); err == nil {
			t.Fatal("request sent without a token")
		}
	})
}

func TestReconcileThroughDaemon(t *testing.T) {
	d := newFakeDaemon(t, http.StatusOK, bouncer.ReconcileResponse{Added: 4, Removed: 2, ElapsedSeconds: 1.5})
	if err := reconcileThroughDaemon(context.Background(), d.dataDir); err != nil {
		t.Fatal(err)
	}
	if req := d.only(t); req.method != http.MethodPost || req.path != bouncer.ControlReconcilePath {
		t.Fatalf("request = %+v", req)
	}

	partial := newFakeDaemon(t, http.StatusOK, bouncer.ReconcileResponse{Added: 1, Error: "site branch: HTTP 500"})
	if err := reconcileThroughDaemon(context.Background(), partial.dataDir); err == nil || !strings.Contains(err.Error(), "HTTP 500") {
		t.Fatalf("err = %v, want the partial reconcile reported", err)
	}
}

func TestStatusSyncReadsDaemon(t *testing.T) {
	last := time.Now().Add(-time.Minute).UTC()
	age := 60.0
	d := newFakeDaemon(t, http.StatusOK, bouncer.SyncStatus{StartupSynced: true, DirtyShards: 2, LastSync: &last, LastSyncAgeSeconds: &age})
	var got bouncer.SyncStatus
	if err := callControl(context.Background(), d.dataDir, http.MethodGet, bouncer.SyncStatusPath, nil, &got); err != nil {
		t.Fatal(err)
	}
	if req := d.only(t); req.method != http.MethodGet || req.path != bouncer.SyncStatusPath || req.body != "" {
		t.Fatalf("request = %+v", req)
	}
	if !got.StartupSynced || got.DirtyShards != 2 || got.LastSync == nil {
		t.Fatalf("status = %+v", got)
	}
	if err := printSyncStatus(got); err != nil {
		t.Fatal(err)
	}
}
