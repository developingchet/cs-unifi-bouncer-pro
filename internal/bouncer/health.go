package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/lapihttp"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// Health serves /healthz, /readyz and the status snapshot. It is started
// before the firewall infrastructure loads, which can take minutes on a large
// ban list, so /healthz answers for the whole startup. /readyz reports
// "starting" until the first LAPI decision batch has been applied to UniFi.
type Health struct {
	cfg      *config.Config
	ctrl     controller.Controller
	store    storage.Store
	lapiHTTP *http.Client
	log      zerolog.Logger
	synced   atomic.Bool
}

// NewHealth builds the health server. Call Listen and Serve to start it.
func NewHealth(cfg *config.Config, ctrl controller.Controller, store storage.Store, log zerolog.Logger) (*Health, error) {
	lapiClient, err := lapihttp.NewClient(cfg.CrowdSecLAPIVerifyTLS, cfg.CrowdSecLAPICACert, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("configure LAPI readiness client: %w", err)
	}
	return &Health{cfg: cfg, ctrl: ctrl, store: store, lapiHTTP: lapiClient, log: log}, nil
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
	if err := h.ctrl.Ping(r.Context()); err != nil {
		h.log.Warn().Err(err).Msg("readyz: controller ping failed")
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	if h.cfg.HealthCheckLAPI {
		lapiURL := strings.TrimRight(h.cfg.CrowdSecLAPIURL, "/") + "/v1/decisions?limit=1"
		lapiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, lapiURL, nil)
		if err != nil {
			http.Error(w, "lapi: invalid URL", http.StatusServiceUnavailable)
			return
		}
		lapiReq.Header.Set("X-Api-Key", h.cfg.CrowdSecLAPIKey)
		lapiReq.Header.Set("User-Agent", lapihttp.UserAgent(BinaryVersion))
		lapiResp, err := h.lapiHTTP.Do(lapiReq)
		if err != nil {
			http.Error(w, "lapi: unreachable", http.StatusServiceUnavailable)
			return
		}
		defer lapiResp.Body.Close()
		if lapiResp.StatusCode != http.StatusOK {
			http.Error(w, "lapi: unexpected status", http.StatusServiceUnavailable)
			return
		}
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
