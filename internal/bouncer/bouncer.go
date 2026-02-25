package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// BinaryVersion is set at startup from the -X main.Version ldflags value.
var BinaryVersion = "dev"

// Bouncer wires together the CrowdSec stream, filter pipeline, and firewall manager.
type Bouncer struct {
	cfg       *config.Config
	ctrl      controller.Controller
	store     storage.Store
	fwMgr     firewall.Manager
	handler   JobHandler
	filterCfg decision.FilterConfig
	log       zerolog.Logger
	streamBnc *csbouncer.StreamBouncer
	recorder  MetricsRecorder
}

// New constructs a fully wired Bouncer.
func New(cfg *config.Config, ctrl controller.Controller, store storage.Store,
	fwMgr firewall.Manager, recorder MetricsRecorder, log zerolog.Logger) (*Bouncer, error) {

	whitelist, err := decision.ParseWhitelist(cfg.BlockWhitelist)
	if err != nil {
		return nil, fmt.Errorf("parse whitelist: %w", err)
	}

	filterCfg := decision.NewFilterConfig()
	filterCfg.BlockScenarioExclude = cfg.BlockScenarioExclude
	filterCfg.AllowedOrigins = cfg.CrowdSecOrigins
	filterCfg.Whitelist = whitelist
	filterCfg.MinBanDuration = cfg.BlockMinDuration

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, recorder, log)

	// StreamBouncer.TickerInterval is a string like "30s"
	tickerStr := cfg.CrowdSecPollInterval.String()
	skipVerify := !cfg.CrowdSecLAPIVerifyTLS
	streamBnc := &csbouncer.StreamBouncer{
		APIKey:              cfg.CrowdSecLAPIKey,
		APIUrl:              cfg.CrowdSecLAPIURL,
		TickerInterval:      tickerStr,
		InsecureSkipVerify:  &skipVerify,
		UserAgent:           "crowdsec-unifi-bouncer/v" + BinaryVersion,
		RetryInitialConnect: true,
	}

	return &Bouncer{
		cfg:       cfg,
		ctrl:      ctrl,
		store:     store,
		fwMgr:     fwMgr,
		handler:   handler,
		filterCfg: filterCfg,
		log:       log,
		streamBnc: streamBnc,
		recorder:  recorder,
	}, nil
}

// Run starts all goroutines and blocks until ctx is cancelled or a fatal error occurs.
func (b *Bouncer) Run(ctx context.Context) error {
	if err := b.streamBnc.Init(); err != nil {
		return fmt.Errorf("init CrowdSec stream: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	// CrowdSec stream processor
	g.Go(func() error {
		return b.processStream(gctx)
	})

	// Periodic sync ticker: retries any dirty shards that failed to flush
	// after a decision block. Only launched when SyncInterval > 0.
	if b.cfg.SyncInterval > 0 {
		g.Go(func() error {
			b.runPeriodicSync(gctx)
			return nil
		})
	}

	// Prometheus metrics server
	if b.cfg.MetricsEnabled {
		g.Go(func() error {
			return b.serveMetrics(gctx)
		})
	}

	// Health endpoints
	g.Go(func() error {
		return b.serveHealth(gctx)
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// runPeriodicSync fires SyncDirty at every SyncInterval tick to retry any
// shards that failed to flush after a decision block.
func (b *Bouncer) runPeriodicSync(ctx context.Context) {
	ticker := time.NewTicker(b.cfg.SyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := b.fwMgr.SyncDirty(ctx, b.cfg.UnifiSites); err != nil {
				b.log.Warn().Err(err).Msg("periodic SyncDirty failed")
			}
		}
	}
}

// processStream reads decisions from the CrowdSec LAPI and processes them directly.
// After every decision block it calls SyncDirty to flush in-memory dirty shards to
// the UniFi API. The first flush is logged at Info as the startup sync boundary.
func (b *Bouncer) processStream(ctx context.Context) error {
	go b.streamBnc.Run(ctx)

	startupSynced := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case decisions, ok := <-b.streamBnc.Stream:
			if !ok {
				return fmt.Errorf("CrowdSec stream closed")
			}
			b.handleDecisionBlock(ctx, decisions)
			if err := b.fwMgr.SyncDirty(ctx, b.cfg.UnifiSites); err != nil {
				b.log.Warn().Err(err).Msg("SyncDirty after decision block failed")
			}
			if !startupSynced {
				startupSynced = true
				b.log.Info().Msg("startup stream batch synced to UniFi")
			}
		}
	}
}

func (b *Bouncer) handleDecisionBlock(ctx context.Context, decisions *models.DecisionsStreamResponse) {
	source := "stream"

	for _, d := range decisions.New {
		result := decision.Filter(d, b.filterCfg, b.log)
		if !result.Passed {
			continue
		}
		metrics.DecisionsProcessed.WithLabelValues("ban", source).Inc()

		origin := ""
		if d.Origin != nil {
			origin = *d.Origin
		}
		remType := ""
		if d.Type != nil {
			remType = *d.Type
		}

		if err := b.handler(ctx, SyncJob{
			Action:          "ban",
			IP:              result.Value,
			IPv6:            result.IPv6,
			ExpiresAt:       expiresAt(result.Duration),
			Origin:          origin,
			RemediationType: remType,
			ReceivedAt:      time.Now(),
		}); err != nil {
			b.log.Error().Err(err).Str("ip", result.Value).Msg("failed to apply ban")
		}
	}

	for _, d := range decisions.Deleted {
		result := decision.Filter(d, b.filterCfg, b.log)
		if !result.Passed {
			continue
		}
		metrics.DecisionsProcessed.WithLabelValues("unban", source).Inc()

		if err := b.handler(ctx, SyncJob{
			Action: "delete",
			IP:     result.Value,
			IPv6:   result.IPv6,
		}); err != nil {
			b.log.Error().Err(err).Str("ip", result.Value).Msg("failed to apply unban")
		}
	}
}

// serveMetrics runs the Prometheus HTTP server.
func (b *Bouncer) serveMetrics(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metricsHandler())
	srv := &http.Server{
		Addr:    b.cfg.MetricsAddr,
		Handler: mux,
	}

	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	b.log.Info().Str("addr", b.cfg.MetricsAddr).Msg("Prometheus metrics server started")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("metrics server: %w", err)
	}
	return nil
}

// serveHealth runs the health endpoint.
func (b *Bouncer) serveHealth(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := b.ctrl.Ping(r.Context()); err != nil {
			http.Error(w, "not ready: "+err.Error(), http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	srv := &http.Server{
		Addr:    b.cfg.HealthAddr,
		Handler: mux,
	}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()

	b.log.Info().Str("addr", b.cfg.HealthAddr).Msg("health server started")
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return fmt.Errorf("health server: %w", err)
	}
	return nil
}

func expiresAt(dur time.Duration) time.Time {
	if dur == 0 {
		return time.Time{}
	}
	return time.Now().Add(dur)
}
