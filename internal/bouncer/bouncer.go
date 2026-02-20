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
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/pool"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
)

// BinaryVersion is set at startup from the -X main.Version ldflags value.
var BinaryVersion = "dev"

// Bouncer wires together the CrowdSec stream, filter pipeline, worker pool, and firewall manager.
type Bouncer struct {
	cfg       *config.Config
	ctrl      controller.Controller
	store     storage.Store
	fwMgr     firewall.Manager
	pool      *pool.Pool
	filterCfg decision.FilterConfig
	log       zerolog.Logger
	streamBnc *csbouncer.StreamBouncer
}

// New constructs a fully wired Bouncer.
func New(cfg *config.Config, ctrl controller.Controller, store storage.Store,
	fwMgr firewall.Manager, log zerolog.Logger) (*Bouncer, error) {

	whitelist, err := decision.ParseWhitelist(cfg.BlockWhitelist)
	if err != nil {
		return nil, fmt.Errorf("parse whitelist: %w", err)
	}

	filterCfg := decision.NewFilterConfig()
	filterCfg.BlockScenarioExclude = cfg.BlockScenarioExclude
	filterCfg.AllowedOrigins = cfg.CrowdSecOrigins
	filterCfg.Whitelist = whitelist
	filterCfg.MinBanDuration = cfg.BlockMinDuration

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, log)

	p, err := pool.New(pool.Config{
		Workers:    cfg.PoolWorkers,
		QueueDepth: cfg.PoolQueueDepth,
		MaxRetries: cfg.PoolMaxRetries,
		RetryBase:  cfg.PoolRetryBase,
	}, handler, log)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	// StreamBouncer.TickerInterval is a string like "30s"
	tickerStr := cfg.CrowdSecPollInterval.String()
	skipVerify := !cfg.CrowdSecLAPIVerifyTLS
	streamBnc := &csbouncer.StreamBouncer{
		APIKey:              cfg.CrowdSecLAPIKey,
		APIUrl:              cfg.CrowdSecLAPIURL,
		TickerInterval:      tickerStr,
		InsecureSkipVerify:  &skipVerify,
		UserAgent:           "cs-unifi-bouncer-pro/" + BinaryVersion,
		RetryInitialConnect: true,
	}

	return &Bouncer{
		cfg:       cfg,
		ctrl:      ctrl,
		store:     store,
		fwMgr:     fwMgr,
		pool:      p,
		filterCfg: filterCfg,
		log:       log,
		streamBnc: streamBnc,
	}, nil
}

// Run starts all goroutines and blocks until ctx is cancelled or a fatal error occurs.
func (b *Bouncer) Run(ctx context.Context) error {
	if err := b.streamBnc.Init(); err != nil {
		return fmt.Errorf("init CrowdSec stream: %w", err)
	}

	g, gctx := errgroup.WithContext(ctx)

	// Start worker pool
	b.pool.Start(gctx)

	// CrowdSec stream processor
	g.Go(func() error {
		return b.processStream(gctx)
	})

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

	b.pool.Stop()
	return nil
}

// processStream reads decisions from the CrowdSec LAPI and enqueues them.
func (b *Bouncer) processStream(ctx context.Context) error {
	// Run returns when ctx is cancelled
	go b.streamBnc.Run(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case decisions, ok := <-b.streamBnc.Stream:
			if !ok {
				return fmt.Errorf("CrowdSec stream closed")
			}
			b.handleDecisionBlock(decisions)
		}
	}
}

func (b *Bouncer) handleDecisionBlock(decisions *models.DecisionsStreamResponse) {
	source := "stream"

	for _, d := range decisions.New {
		result := decision.Filter(d, b.filterCfg, b.log)
		if !result.Passed {
			continue
		}
		metrics.DecisionsProcessed.WithLabelValues("ban", source).Inc()
		b.enqueueJob(pool.SyncJob{
			Action:    "ban",
			IP:        result.Value,
			IPv6:      result.IPv6,
			Site:      "", // worker applies to all sites
			ExpiresAt: expiresAt(result.Duration),
		})
	}

	for _, d := range decisions.Deleted {
		result := decision.Filter(d, b.filterCfg, b.log)
		if !result.Passed {
			continue
		}
		metrics.DecisionsProcessed.WithLabelValues("unban", source).Inc()
		b.enqueueJob(pool.SyncJob{
			Action: "delete",
			IP:     result.Value,
			IPv6:   result.IPv6,
		})
	}
}

func (b *Bouncer) enqueueJob(job pool.SyncJob) {
	if !b.pool.Enqueue(job) {
		b.log.Warn().Str("ip", job.IP).Msg("job dropped: queue full")
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
