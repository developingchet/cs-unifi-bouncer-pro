package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/rs/zerolog"
)

// ClientConfig holds parameters for constructing a UniFi HTTP client.
type ClientConfig struct {
	BaseURL      string
	Username     string
	Password     string
	APIKey       string
	VerifyTLS    bool
	CACertPath   string
	Timeout      time.Duration
	Debug        bool
	ReauthMinGap time.Duration // thundering-herd guard: skip re-auth if last one was < this ago
}

// unifiClient implements Controller using direct HTTPS calls to the UniFi Network API.
type unifiClient struct {
	cfg          ClientConfig
	http         *http.Client
	session      *sessionManager
	featureCache map[string]map[string]bool // site -> feature -> bool
	log          zerolog.Logger
}

// NewClient constructs a new Controller client and performs initial login.
func NewClient(ctx context.Context, cfg ClientConfig, log zerolog.Logger) (Controller, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: !cfg.VerifyTLS, //nolint:gosec // user-opted-in
	}
	if cfg.CACertPath != "" {
		pem, err := os.ReadFile(cfg.CACertPath)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %s: %w", cfg.CACertPath, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no valid certificates in %s", cfg.CACertPath)
		}
		tlsCfg.RootCAs = pool
	}

	// Build transport based on DefaultTransport to inherit all production-safe
	// defaults (DialContext with keepalive, TLSHandshakeTimeout, IdleConnTimeout,
	// etc.) while applying custom TLS configuration.
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ForceAttemptHTTP2:     false, // UniFi controllers do not support HTTP/2
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
	}

	c := &unifiClient{
		cfg:          cfg,
		http:         httpClient,
		featureCache: make(map[string]map[string]bool),
		log:          log,
	}

	authCfg := AuthConfig{
		BaseURL:       cfg.BaseURL,
		Username:      cfg.Username,
		Password:      cfg.Password,
		APIKey:        cfg.APIKey,
		ReauthTimeout: cfg.Timeout,
		ReauthMinGap:  cfg.ReauthMinGap,
	}
	c.session = newSessionManager(authCfg, httpClient, log)

	if err := c.session.EnsureAuth(ctx); err != nil {
		return nil, fmt.Errorf("initial login: %w", err)
	}
	return c, nil
}

// apiDo executes an HTTP request, handling auth, metrics, and typed error translation.
func (c *unifiClient) apiDo(ctx context.Context, req *http.Request, endpoint string) (*http.Response, error) {
	start := time.Now()
	c.session.SetAuthHeader(req)

	if c.cfg.Debug {
		c.log.Debug().Str("method", req.Method).Str("url", req.URL.String()).Msg("unifi api request")
	}

	resp, err := c.http.Do(req.WithContext(ctx))
	elapsed := time.Since(start)

	if err != nil {
		if c.cfg.Debug {
			c.log.Debug().Str("method", req.Method).Str("url", req.URL.String()).
				Err(err).Dur("elapsed", elapsed).Msg("unifi api request failed")
		}
		metrics.APICalls.WithLabelValues(endpoint, "error").Inc()
		return nil, err
	}

	statusLabel := fmt.Sprintf("%dxx", resp.StatusCode/100)
	metrics.APICalls.WithLabelValues(endpoint, statusLabel).Inc()
	metrics.APIDuration.WithLabelValues(endpoint).Observe(elapsed.Seconds())

	if c.cfg.Debug {
		c.log.Debug().Str("method", req.Method).Str("url", req.URL.String()).
			Int("status", resp.StatusCode).Dur("elapsed", elapsed).Msg("unifi api response")
	}

	switch resp.StatusCode {
	case http.StatusUnauthorized:
		_ = resp.Body.Close()
		return nil, &ErrUnauthorized{Msg: "HTTP 401"}
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return nil, &ErrNotFound{}
	case http.StatusTooManyRequests:
		retryAfter := 10 * time.Second
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if d, err := time.ParseDuration(ra + "s"); err == nil {
				retryAfter = d
			}
		}
		_ = resp.Body.Close()
		return nil, &ErrRateLimit{RetryAfter: retryAfter}
	case http.StatusConflict:
		_ = resp.Body.Close()
		return nil, &ErrConflict{Msg: "HTTP 409 conflict"}
	}
	return resp, nil
}

// withReauth executes fn, and on ErrUnauthorized calls EnsureAuth then retries once.
func (c *unifiClient) withReauth(ctx context.Context, fn func() error) error {
	err := fn()
	if err == nil {
		return nil
	}
	if _, ok := err.(*ErrUnauthorized); !ok {
		return err
	}
	if authErr := c.session.EnsureAuth(ctx); authErr != nil {
		return fmt.Errorf("re-auth failed: %w", authErr)
	}
	return fn()
}

// Ping verifies the controller is reachable.
func (c *unifiClient) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.BaseURL+"/api/self", nil)
	if err != nil {
		return err
	}
	return c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, "ping")
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	})
}

// Close is a no-op for stateless HTTP clients (session cookies expire server-side).
func (c *unifiClient) Close() error {
	return nil
}

// ---- Firewall Groups -------------------------------------------------------

func (c *unifiClient) ListFirewallGroups(ctx context.Context, site string) ([]FirewallGroup, error) {
	return listFirewallGroups(ctx, c, site)
}

func (c *unifiClient) CreateFirewallGroup(ctx context.Context, site string, g FirewallGroup) (FirewallGroup, error) {
	return createFirewallGroup(ctx, c, site, g)
}

func (c *unifiClient) UpdateFirewallGroup(ctx context.Context, site string, g FirewallGroup) error {
	return updateFirewallGroup(ctx, c, site, g)
}

func (c *unifiClient) DeleteFirewallGroup(ctx context.Context, site string, id string) error {
	return deleteFirewallGroup(ctx, c, site, id)
}

// ---- Firewall Rules --------------------------------------------------------

func (c *unifiClient) ListFirewallRules(ctx context.Context, site string) ([]FirewallRule, error) {
	return listFirewallRules(ctx, c, site)
}

func (c *unifiClient) CreateFirewallRule(ctx context.Context, site string, r FirewallRule) (FirewallRule, error) {
	return createFirewallRule(ctx, c, site, r)
}

func (c *unifiClient) UpdateFirewallRule(ctx context.Context, site string, r FirewallRule) error {
	return updateFirewallRule(ctx, c, site, r)
}

func (c *unifiClient) DeleteFirewallRule(ctx context.Context, site string, id string) error {
	return deleteFirewallRule(ctx, c, site, id)
}

// ---- Zone Policies ---------------------------------------------------------

func (c *unifiClient) ListZonePolicies(ctx context.Context, site string) ([]ZonePolicy, error) {
	return listZonePolicies(ctx, c, site)
}

func (c *unifiClient) CreateZonePolicy(ctx context.Context, site string, p ZonePolicy) (ZonePolicy, error) {
	return createZonePolicy(ctx, c, site, p)
}

func (c *unifiClient) UpdateZonePolicy(ctx context.Context, site string, p ZonePolicy) error {
	return updateZonePolicy(ctx, c, site, p)
}

func (c *unifiClient) DeleteZonePolicy(ctx context.Context, site string, id string) error {
	return deleteZonePolicy(ctx, c, site, id)
}

func (c *unifiClient) ReorderZonePolicies(ctx context.Context, site string, req ZonePolicyReorderRequest) error {
	return reorderZonePolicies(ctx, c, site, req)
}

// ---- Zones -----------------------------------------------------------------

func (c *unifiClient) ListZones(ctx context.Context, site string) ([]Zone, error) {
	return listZones(ctx, c, site)
}

// ---- Feature Detection -----------------------------------------------------

func (c *unifiClient) HasFeature(ctx context.Context, site string, feature string) (bool, error) {
	return hasFeature(ctx, c, site, feature)
}
