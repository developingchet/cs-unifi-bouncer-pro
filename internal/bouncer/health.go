package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/lapihttp"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
	"golang.org/x/sync/singleflight"
)

// Health serves /healthz, /readyz and the status snapshot. It is started
// before the firewall infrastructure loads, which can take minutes on a large
// ban list, so /healthz answers for the whole startup. /readyz reports
// "starting" until the first LAPI decision batch has been processed.
type Health struct {
	cfg      *config.Config
	ctrl     controller.Controller
	store    storage.Store
	lapiHTTP *http.Client
	log      zerolog.Logger
	synced   atomic.Bool

	// now is the clock readiness caching uses; tests replace it.
	now    func() time.Time
	flight singleflight.Group
	mu     sync.Mutex // guards cached and cachedAt
	// cached is the last dependency check result, taken at cachedAt.
	cached   readyResult
	cachedAt time.Time
}

const (
	// readyCacheTTL is how long a /readyz result is reused. /readyz is
	// reachable by anything that can open the health port, and each check logs
	// in to the controller, so an uncached probe would let a caller drive
	// controller load and UniFi login rate limits.
	readyCacheTTL = 5 * time.Second
	// readyCheckTimeout bounds one dependency check.
	readyCheckTimeout = 10 * time.Second
)

// readyResult is the outcome of a dependency check: the HTTP status and body
// /readyz answers with.
type readyResult struct {
	status int
	body   string
}

// NewHealth builds the health server. Call Listen and Serve to start it.
func NewHealth(cfg *config.Config, ctrl controller.Controller, store storage.Store, log zerolog.Logger) (*Health, error) {
	lapiClient, err := lapihttp.NewClient(cfg.CrowdSecLAPIVerifyTLS, cfg.CrowdSecLAPICACert, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("configure LAPI readiness client: %w", err)
	}
	return &Health{cfg: cfg, ctrl: ctrl, store: store, lapiHTTP: lapiClient, log: log, now: time.Now}, nil
}

// MarkSynced makes /readyz check its dependencies instead of reporting
// "starting". Register it with Bouncer.OnStartupSynced.
func (h *Health) MarkSynced() {
	h.synced.Store(true)
}

// Listen binds HealthAddr, so a port conflict fails startup at once rather
// than after the infrastructure has loaded.
func (h *Health) Listen() (net.Listener, error) {
	ln, err := net.Listen("tcp", h.cfg.HealthAddr)
	if err != nil {
		return nil, fmt.Errorf("health server: %w", err)
	}
	return ln, nil
}

// Serve answers on ln until ctx is cancelled. It closes ln.
func (h *Health) Serve(ctx context.Context, ln net.Listener) error {
	srv := &http.Server{
		Handler:           h.handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	h.log.Info().Str("addr", ln.Addr().String()).Msg("health server started")
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("health server: %w", err)
	}
	return nil
}

func (h *Health) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", h.ready)
	if !h.cfg.DryRun {
		snap, err := newSnapshotServer(h.store, h.cfg.DataDir, h.log)
		if err != nil {
			h.log.Warn().Err(err).Msg("status snapshots disabled")
		} else if snap != nil {
			mux.Handle(DBSnapshotPath, snap)
		}
	}
	return mux
}

func (h *Health) ready(w http.ResponseWriter, r *http.Request) {
	if !h.synced.Load() {
		http.Error(w, "starting", http.StatusServiceUnavailable)
		return
	}
	res, ok := h.readiness(r.Context())
	if !ok {
		http.Error(w, "readiness check interrupted", http.StatusServiceUnavailable)
		return
	}
	if res.status != http.StatusOK {
		http.Error(w, res.body, res.status)
		return
	}
	w.WriteHeader(res.status)
	_, _ = w.Write([]byte(res.body))
}

// readiness returns the cached dependency check result, running the check
// when the cached one has expired. Concurrent callers share one run, so the
// controller and LAPI see at most one probe per readyCacheTTL however often
// /readyz is requested. It reports false when ctx ends before a result exists.
func (h *Health) readiness(ctx context.Context) (readyResult, bool) {
	if res, ok := h.cachedReadiness(); ok {
		return res, true
	}
	ch := h.flight.DoChan("readyz", func() (any, error) {
		// Another caller may have refreshed the cache between the miss above
		// and this run starting.
		if res, ok := h.cachedReadiness(); ok {
			return res, nil
		}
		// The probe outlives the request that triggered it: the result is
		// shared, so one caller disconnecting must not fail the others.
		checkCtx, cancel := context.WithTimeout(context.Background(), readyCheckTimeout)
		defer cancel()
		res := h.checkDependencies(checkCtx)
		h.mu.Lock()
		h.cached, h.cachedAt = res, h.now()
		h.mu.Unlock()
		return res, nil
	})
	select {
	case out := <-ch:
		return out.Val.(readyResult), true
	case <-ctx.Done():
		return readyResult{}, false
	}
}

func (h *Health) cachedReadiness() (readyResult, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.cachedAt.IsZero() || h.now().Sub(h.cachedAt) >= readyCacheTTL {
		return readyResult{}, false
	}
	return h.cached, true
}

// checkDependencies probes the controller and, when enabled, the LAPI.
func (h *Health) checkDependencies(ctx context.Context) readyResult {
	if err := h.ctrl.Ping(ctx); err != nil {
		h.log.Warn().Err(err).Msg("readyz: controller ping failed")
		return readyResult{http.StatusServiceUnavailable, "not ready"}
	}
	if h.cfg.HealthCheckLAPI {
		if res, ok := h.checkLAPI(ctx); !ok {
			return res
		}
	}
	return readyResult{http.StatusOK, "ready"}
}

// checkLAPI reports false, with the response to send, when the LAPI is not
// reachable and healthy.
func (h *Health) checkLAPI(ctx context.Context) (readyResult, bool) {
	lapiURL := strings.TrimRight(h.cfg.CrowdSecLAPIURL, "/") + "/v1/decisions?limit=1"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, lapiURL, nil)
	if err != nil {
		return readyResult{http.StatusServiceUnavailable, "lapi: invalid URL"}, false
	}
	req.Header.Set("X-Api-Key", h.cfg.CrowdSecLAPIKey)
	req.Header.Set("User-Agent", lapihttp.UserAgent(BinaryVersion))
	resp, err := h.lapiHTTP.Do(req)
	if err != nil {
		return readyResult{http.StatusServiceUnavailable, "lapi: unreachable"}, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return readyResult{http.StatusServiceUnavailable, "lapi: unexpected status"}, false
	}
	return readyResult{}, true
}
