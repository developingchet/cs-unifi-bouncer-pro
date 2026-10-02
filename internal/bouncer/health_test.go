package bouncer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

func newTestHealth(t *testing.T, cfg *config.Config) (*Health, *testutil.MockController) {
	t.Helper()
	ctrl := testutil.NewMockController()
	h, err := NewHealth(cfg, ctrl, testutil.NewMockStore(), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewHealth: %v", err)
	}
	return h, ctrl
}

func TestHealth_Readyz(t *testing.T) {
	for _, tc := range []struct {
		name     string
		synced   bool
		pingErr  error
		want     int
		wantBody string
		wantPing int
	}{
		{"starting until the first batch is synced", false, nil, http.StatusServiceUnavailable, "starting", 0},
		{"ready once synced", true, nil, http.StatusOK, "ready", 1},
		{"controller unreachable", true, errors.New("down"), http.StatusServiceUnavailable, "not ready", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ctrl := newTestHealth(t, &config.Config{HealthCheckLAPI: false})
			if tc.pingErr != nil {
				ctrl.SetError("Ping", tc.pingErr)
			}
			if tc.synced {
				h.MarkSynced()
			}
			rr := httptest.NewRecorder()
			h.ready(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rr.Code != tc.want {
				t.Fatalf("readyz returned %d, want %d", rr.Code, tc.want)
			}
			if got := strings.TrimSpace(rr.Body.String()); got != tc.wantBody {
				t.Fatalf("readyz body = %q, want %q", got, tc.wantBody)
			}
			if got := ctrl.Calls("Ping"); got != tc.wantPing {
				t.Fatalf("controller pinged %d times, want %d", got, tc.wantPing)
			}
		})
	}
}

func TestHealth_ReadyzLAPIStatus(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		want   int
	}{
		{"healthy", http.StatusOK, http.StatusOK},
		{"unauthorized", http.StatusUnauthorized, http.StatusServiceUnavailable},
		{"redirect", http.StatusFound, http.StatusServiceUnavailable},
		{"unavailable", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/decisions" || r.URL.Query().Get("limit") != "1" || r.Header.Get("X-Api-Key") != "test-key" {
					http.Error(w, "bad readiness request", http.StatusBadRequest)
					return
				}
				w.WriteHeader(tc.status)
			}))
			t.Cleanup(srv.Close)
			h, _ := newTestHealth(t, &config.Config{
				CrowdSecLAPIURL: srv.URL,
				CrowdSecLAPIKey: "test-key",
				HealthCheckLAPI: true,
			})
			h.MarkSynced()
			rr := httptest.NewRecorder()
			h.ready(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
			if rr.Code != tc.want {
				t.Fatalf("readyz returned %d, want %d", rr.Code, tc.want)
			}
		})
	}
}

func TestHealth_ServeAnswersHealthzBeforeSync(t *testing.T) {
	h, _ := newTestHealth(t, &config.Config{HealthAddr: "127.0.0.1:0", DryRun: true})
	ln, err := h.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- h.Serve(ctx, ln) }()

	base := "http://" + ln.Addr().String()
	client := &http.Client{Timeout: 5 * time.Second}
	for _, tc := range []struct {
		path string
		want int
	}{
		{"/healthz", http.StatusOK},
		{"/readyz", http.StatusServiceUnavailable},
	} {
		resp, err := client.Get(base + tc.path)
		if err != nil {
			t.Fatalf("GET %s: %v", tc.path, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.StatusCode != tc.want {
			t.Errorf("GET %s = %d, want %d", tc.path, resp.StatusCode, tc.want)
		}
	}

	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Serve = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after cancel")
	}
}

func TestHealth_ListenFailsOnBusyPort(t *testing.T) {
	h, _ := newTestHealth(t, &config.Config{HealthAddr: "127.0.0.1:0"})
	ln, err := h.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	busy, _ := newTestHealth(t, &config.Config{HealthAddr: ln.Addr().String()})
	if second, err := busy.Listen(); err == nil {
		_ = second.Close()
		t.Fatal("Listen on a bound port succeeded, want an error")
	}
}
