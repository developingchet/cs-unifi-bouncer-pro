package bouncer

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

// gatedController blocks Ping until release is closed, so a test can hold a
// readiness check open while more requests arrive.
type gatedController struct {
	*testutil.MockController
	started chan struct{}
	release chan struct{}
}

func (g *gatedController) Ping(ctx context.Context) error {
	select {
	case g.started <- struct{}{}:
	default:
	}
	select {
	case <-g.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return g.MockController.Ping(ctx)
}

// fakeClock is a manually advanced clock for readiness caching.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func readyzStatus(h *Health) int {
	rr := httptest.NewRecorder()
	h.ready(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	return rr.Code
}

func TestHealth_ReadyzCachesResult(t *testing.T) {
	for _, tc := range []struct {
		name    string
		pingErr error
		want    int
	}{
		{"success is reused", nil, http.StatusOK},
		{"failure is reused", errors.New("down"), http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, ctrl := newTestHealth(t, &config.Config{})
			clock := &fakeClock{t: time.Unix(1_000, 0)}
			h.now = clock.now
			if tc.pingErr != nil {
				ctrl.SetError("Ping", tc.pingErr)
			}
			h.MarkSynced()

			for i := 0; i < 20; i++ {
				if got := readyzStatus(h); got != tc.want {
					t.Fatalf("request %d: readyz returned %d, want %d", i, got, tc.want)
				}
			}
			if got := ctrl.Calls("Ping"); got != 1 {
				t.Fatalf("controller pinged %d times within the TTL, want 1", got)
			}

			clock.advance(readyCacheTTL - time.Millisecond)
			readyzStatus(h)
			if got := ctrl.Calls("Ping"); got != 1 {
				t.Fatalf("controller pinged %d times just before the TTL, want 1", got)
			}

			clock.advance(time.Millisecond)
			readyzStatus(h)
			if got := ctrl.Calls("Ping"); got != 2 {
				t.Fatalf("controller pinged %d times after the TTL, want 2", got)
			}
		})
	}
}

func TestHealth_ReadyzRecoversAfterTTL(t *testing.T) {
	h, ctrl := newTestHealth(t, &config.Config{})
	clock := &fakeClock{t: time.Unix(1_000, 0)}
	h.now = clock.now
	h.MarkSynced()

	ctrl.SetError("Ping", errors.New("down"))
	if got := readyzStatus(h); got != http.StatusServiceUnavailable {
		t.Fatalf("readyz returned %d while the controller is down, want 503", got)
	}
	// The mock returns an injected error once, so the controller is healthy
	// again from here on; only the cache keeps readyz at 503.
	if got := readyzStatus(h); got != http.StatusServiceUnavailable {
		t.Fatalf("readyz returned %d inside the TTL, want the cached 503", got)
	}
	clock.advance(readyCacheTTL)
	if got := readyzStatus(h); got != http.StatusOK {
		t.Fatalf("readyz returned %d after the controller recovered, want 200", got)
	}
}

func TestHealth_ReadyzStartingIsNotCached(t *testing.T) {
	h, ctrl := newTestHealth(t, &config.Config{})
	if got := readyzStatus(h); got != http.StatusServiceUnavailable {
		t.Fatalf("readyz returned %d before sync, want 503", got)
	}
	h.MarkSynced()
	if got := readyzStatus(h); got != http.StatusOK {
		t.Fatalf("readyz returned %d right after sync, want 200", got)
	}
	if got := ctrl.Calls("Ping"); got != 1 {
		t.Fatalf("controller pinged %d times, want 1", got)
	}
}

func TestHealth_ReadyzCoalescesConcurrentChecks(t *testing.T) {
	gate := &gatedController{
		MockController: testutil.NewMockController(),
		started:        make(chan struct{}, 1),
		release:        make(chan struct{}),
	}
	h, err := NewHealth(&config.Config{}, gate, testutil.NewMockStore(), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewHealth: %v", err)
	}
	h.MarkSynced()

	const callers = 25
	codes := make(chan int, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- readyzStatus(h)
		}()
	}
	select {
	case <-gate.started:
	case <-time.After(5 * time.Second):
		t.Fatal("no readiness check started")
	}
	// Give the remaining callers time to join the in-flight check.
	time.Sleep(100 * time.Millisecond)
	close(gate.release)
	wg.Wait()
	close(codes)

	for code := range codes {
		if code != http.StatusOK {
			t.Errorf("readyz returned %d, want 200", code)
		}
	}
	if got := gate.Calls("Ping"); got != 1 {
		t.Fatalf("controller pinged %d times for %d concurrent requests, want 1", got, callers)
	}
}

func TestHealth_ReadyzCallerGivesUpWhileCheckRuns(t *testing.T) {
	gate := &gatedController{
		MockController: testutil.NewMockController(),
		started:        make(chan struct{}, 1),
		release:        make(chan struct{}),
	}
	h, err := NewHealth(&config.Config{}, gate, testutil.NewMockStore(), zerolog.Nop())
	if err != nil {
		t.Fatalf("NewHealth: %v", err)
	}
	h.MarkSynced()

	ctx, cancel := context.WithCancel(context.Background())
	rr := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		h.ready(rr, httptest.NewRequest(http.MethodGet, "/readyz", nil).WithContext(ctx))
		close(done)
	}()
	<-gate.started
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("request did not return after its context was cancelled")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("readyz returned %d for a cancelled request, want 503", rr.Code)
	}

	// The shared check keeps running for later callers.
	close(gate.release)
	deadline := time.After(5 * time.Second)
	for {
		if got := readyzStatus(h); got == http.StatusOK {
			break
		}
		select {
		case <-deadline:
			t.Fatal("readyz never recovered after the abandoned check finished")
		case <-time.After(10 * time.Millisecond):
		}
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
