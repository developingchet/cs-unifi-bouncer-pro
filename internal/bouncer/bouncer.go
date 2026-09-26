package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/lapihttp"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"
)

// BinaryVersion is set at startup from the -X main.Version ldflags value.
var BinaryVersion = "dev"

// userAgent is the LAPI user agent, crowdsec-unifi-bouncer/v<version>.
// Release tags already start with "v", which used to be doubled ("vv1.2.3").
func userAgent(version string) string {
	return "crowdsec-unifi-bouncer/v" + strings.TrimPrefix(version, "v")
}

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
	lapiHTTP  *http.Client
	// lapiResyncHTTP has a longer timeout for the full decision list.
	lapiResyncHTTP *http.Client
	// resyncRejected holds the sources of decisions the filter rejected on
	// the last resync. Only the resync goroutine touches it.
	resyncRejected map[string]struct{}
	recorder       MetricsRecorder
	limiter        *rate.Limiter // nil when rate limiting is disabled
	// onStartupSynced runs once, after the first decision batch is applied.
	onStartupSynced func()
}

// OnStartupSynced registers fn to run once, after the first decision batch
// from the LAPI has been applied. Until then the ban database may be missing
// bans (a fresh or lost volume), so anything that removes IPs the database
// does not know about must wait for it. Call before Run.
func (b *Bouncer) OnStartupSynced(fn func()) {
	b.onStartupSynced = fn
}

// New constructs a fully wired Bouncer.
func New(cfg *config.Config, ctrl controller.Controller, store storage.Store,
	fwMgr firewall.Manager, claims *banstate.Manager, recorder MetricsRecorder, log zerolog.Logger) (*Bouncer, error) {

	whitelist, err := decision.ParseWhitelist(cfg.BlockWhitelist)
	if err != nil {
		return nil, fmt.Errorf("parse whitelist: %w", err)
	}

	filterCfg := decision.NewFilterConfig()
	filterCfg.BlockScenarioExclude = cfg.BlockScenarioExclude
	filterCfg.AllowedOrigins = cfg.CrowdSecOrigins
	filterCfg.Whitelist = whitelist
	filterCfg.MinBanDuration = cfg.BlockMinDuration
	filterCfg.ScenarioDurationMap = cfg.BlockScenarioDurationMap

	handler := makeJobHandler(store, claims, cfg, recorder, log)
	lapiClient, err := lapihttp.NewClient(cfg.CrowdSecLAPIVerifyTLS, cfg.CrowdSecLAPICACert, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("configure LAPI HTTP client: %w", err)
	}
	resyncClient, err := lapihttp.NewClient(cfg.CrowdSecLAPIVerifyTLS, cfg.CrowdSecLAPICACert, resyncHTTPTimeout)
	if err != nil {
		return nil, fmt.Errorf("configure LAPI resync client: %w", err)
	}

	// StreamBouncer.TickerInterval is a string like "30s"
	tickerStr := cfg.CrowdSecPollInterval.String()
	skipVerify := !cfg.CrowdSecLAPIVerifyTLS
	streamBnc := &csbouncer.StreamBouncer{
		APIKey:              cfg.CrowdSecLAPIKey,
		APIUrl:              cfg.CrowdSecLAPIURL,
		CAPath:              cfg.CrowdSecLAPICACert,
		TickerInterval:      tickerStr,
		InsecureSkipVerify:  &skipVerify,
		UserAgent:           userAgent(BinaryVersion),
		RetryInitialConnect: true,
	}

	b := &Bouncer{
		cfg:       cfg,
		ctrl:      ctrl,
		store:     store,
		fwMgr:     fwMgr,
		handler:   handler,
		filterCfg: filterCfg,
		log:       log,
		streamBnc: streamBnc,
		lapiHTTP:  lapiClient,
		recorder:  recorder,

		lapiResyncHTTP: resyncClient,
	}
	if cfg.DecisionRateLimit > 0 {
		b.limiter = rate.NewLimiter(rate.Limit(cfg.DecisionRateLimit), cfg.DecisionBurstSize)
	}
	return b, nil
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

	// Periodic full decision re-read: recovers bans the stream skipped.
	// Dry-run records no claims, so every decision would look missing.
	if b.cfg.CrowdSecResyncInterval > 0 && !b.cfg.DryRun {
		g.Go(func() error {
			b.runPeriodicResync(gctx)
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
	runErr := make(chan error, 1)
	go func() { runErr <- b.streamBnc.Run(ctx) }()
	return b.consumeStream(ctx, b.streamBnc.Stream, runErr)
}

// consumeStream applies decision blocks until ctx ends or the stream fails.
func (b *Bouncer) consumeStream(ctx context.Context, stream <-chan *models.DecisionsStreamResponse, runErr <-chan error) error {
	startupSynced := false
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-runErr:
			if errors.Is(err, context.Canceled) {
				return nil
			}
			return streamError(err)
		case decisions, ok := <-stream:
			if !ok {
				// Run closes the stream immediately before returning its error.
				return streamError(<-runErr)
			}
			b.handleDecisionBlock(ctx, decisions, "stream")
			if err := b.fwMgr.SyncDirty(ctx, b.cfg.UnifiSites); err != nil {
				b.log.Warn().Err(err).Msg("SyncDirty after decision block failed")
			}
			if !startupSynced {
				startupSynced = true
				b.log.Info().Msg("startup stream batch synced to UniFi")
				if b.onStartupSynced != nil {
					b.onStartupSynced()
				}
			}
		}
	}
}

func streamError(err error) error {
	if err == nil {
		return fmt.Errorf("CrowdSec stream closed")
	}
	return fmt.Errorf("CrowdSec stream closed: %w", err)
}

// handleDecisionBlock applies one batch of decisions. source labels the
// decisions_processed metric: "stream" for the LAPI stream, "resync" for the
// periodic full pull.
func (b *Bouncer) handleDecisionBlock(ctx context.Context, decisions *models.DecisionsStreamResponse, source string) {
	if decisions == nil {
		b.log.Warn().Msg("ignoring empty CrowdSec decision block")
		return
	}
	for _, d := range decisions.New {
		if !b.applyDecision(ctx, d, "ban", source) {
			return
		}
	}
	for _, d := range decisions.Deleted {
		if !b.applyDecision(ctx, d, "delete", source) {
			return
		}
	}
}

// applyDecision filters d and hands it to the job handler. It returns false
// only when ctx was cancelled while waiting on the rate limiter.
func (b *Bouncer) applyDecision(ctx context.Context, d *models.Decision, action, source string) bool {
	result := decision.Filter(d, b.filterCfg, b.log)
	if !result.Passed {
		return true
	}
	decisionID := decisionSource(d)
	if decisionID == "" {
		b.log.Warn().Str("ip", result.Value).Str("action", action).Msg("skipping CrowdSec decision without ID or UUID")
		return true
	}
	metricAction := "ban"
	if action == "delete" {
		metricAction = "unban"
	}
	metrics.DecisionsProcessed.WithLabelValues(metricAction, source).Inc()

	if b.limiter != nil {
		if err := b.limiter.Wait(ctx); err != nil {
			return false
		}
	}

	job := SyncJob{
		Action:   action,
		Source:   decisionID,
		IP:       result.Value,
		IPv6:     result.IPv6,
		Scenario: deref(d.Scenario),
	}
	if action == "ban" {
		job.ExpiresAt = expiresAt(result.Duration)
		job.DurationOverride = result.DurationOverride
		job.Origin = deref(d.Origin)
		job.RemediationType = deref(d.Type)
		job.ReceivedAt = time.Now()
	}

	metrics.DecisionsInFlight.Inc()
	err := b.handler(ctx, job)
	metrics.DecisionsInFlight.Dec()
	if err != nil {
		b.log.Error().Err(err).Str("ip", result.Value).Str("action", action).Msg("failed to apply decision")
	}
	return true
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func decisionSource(d *models.Decision) string {
	if d.ID != 0 {
		return fmt.Sprintf("crowdsec:id:%d", d.ID)
	}
	if d.UUID != "" {
		return "crowdsec:uuid:" + d.UUID
	}
	return ""
}

// serveMetrics runs the Prometheus HTTP server.
func (b *Bouncer) serveMetrics(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", metricsHandler())
	srv := &http.Server{
		Addr:              b.cfg.MetricsAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
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
	mux.HandleFunc("/readyz", b.ready)

	srv := &http.Server{
		Addr:              b.cfg.HealthAddr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
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

func (b *Bouncer) ready(w http.ResponseWriter, r *http.Request) {
	if err := b.ctrl.Ping(r.Context()); err != nil {
		b.log.Warn().Err(err).Msg("readyz: controller ping failed")
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	if b.cfg.HealthCheckLAPI {
		lapiURL := strings.TrimRight(b.cfg.CrowdSecLAPIURL, "/") + "/v1/decisions?limit=1"
		lapiReq, err := http.NewRequestWithContext(r.Context(), http.MethodGet, lapiURL, nil)
		if err != nil {
			http.Error(w, "lapi: invalid URL", http.StatusServiceUnavailable)
			return
		}
		lapiReq.Header.Set("X-Api-Key", b.cfg.CrowdSecLAPIKey)
		lapiResp, err := b.lapiHTTP.Do(lapiReq)
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

func expiresAt(dur time.Duration) time.Time {
	if dur == 0 {
		return time.Time{}
	}
	return time.Now().Add(dur)
}
