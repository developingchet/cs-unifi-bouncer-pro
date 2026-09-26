package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/rs/zerolog"
	"golang.org/x/net/publicsuffix"
)

// ClientConfig holds parameters for constructing a UniFi HTTP client.
type ClientConfig struct {
	BaseURL       string
	Username      string
	Password      string
	APIKey        string
	VerifyTLS     bool
	CACertPath    string
	Timeout       time.Duration
	Debug         bool
	ReauthMinGap  time.Duration // thundering-herd guard: skip re-auth if last one was < this ago
	ReauthTimeout time.Duration
	DryRun        bool
	EnableIPv6    bool // dial IPv6 — false by default, set true only with working IPv6 path
}

// unifiClient implements Controller using direct HTTPS calls to the UniFi Network API.
type unifiClient struct {
	cfg          ClientConfig
	http         *http.Client
	layout       apiLayout
	session      *sessionManager
	featureCache map[string]map[string]bool // site -> feature -> bool
	cacheMu      sync.RWMutex
	zoneIDCache  map[string]map[string]string // site key -> zone input -> zone UUID
	siteIDCache  map[string]string            // site internalReference -> integration v1 UUID
	log          zerolog.Logger
}

// NewClient constructs a new Controller client and performs initial login.
func NewClient(ctx context.Context, cfg ClientConfig, log zerolog.Logger) (Controller, error) {
	tlsCfg := &tls.Config{
		InsecureSkipVerify: !cfg.VerifyTLS, //nolint:gosec // user-opted-in
		MinVersion:         tls.VersionTLS12,
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

	// dialNetwork is "tcp4" by default to avoid happy eyeballs stalls where IPv6
	// attempts to the UniFi controller blackhole silently for 15 seconds.
	// Set EnableIPv6 = true (ENABLE_IPV6=true) only if your controller is
	// reachable over IPv6 with a working path.
	dialNetwork := "tcp4"
	if cfg.EnableIPv6 {
		dialNetwork = "tcp"
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return (&net.Dialer{
				Timeout:   30 * time.Second,
				KeepAlive: 30 * time.Second,
			}).DialContext(ctx, dialNetwork, addr)
		},
		TLSClientConfig:       tlsCfg,
		TLSHandshakeTimeout:   10 * time.Second,
		ForceAttemptHTTP2:     true, // enable HTTP/2 ALPN negotiation; server falls back to HTTP/1.1 if unsupported
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableKeepAlives:     false,
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, fmt.Errorf("create cookie jar: %w", err)
	}

	httpClient := &http.Client{
		Transport: transport,
		Timeout:   cfg.Timeout,
		Jar:       jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	layout, err := detectLayout(ctx, httpClient, cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	log.Info().Str("layout", layout.name).Msg("detected UniFi controller layout")

	c := &unifiClient{
		cfg:          cfg,
		http:         httpClient,
		layout:       layout,
		featureCache: make(map[string]map[string]bool),
		zoneIDCache:  make(map[string]map[string]string),
		siteIDCache:  make(map[string]string),
		log:          log,
	}

	authCfg := AuthConfig{
		BaseURL:       cfg.BaseURL,
		LoginPath:     layout.loginPath,
		Username:      cfg.Username,
		Password:      cfg.Password,
		APIKey:        cfg.APIKey,
		ReauthTimeout: cfg.ReauthTimeout,
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
	if c.cfg.DryRun && req.Method != http.MethodGet && req.Method != http.MethodHead {
		return nil, fmt.Errorf("dry run: refusing %s %s", req.Method, req.URL.Path)
	}
	start := time.Now()
	c.session.SetAuthHeader(req)

	// UniFi Network API requires these headers on every request.
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	req.Header.Set("User-Agent", "cs-unifi-bouncer-pro")

	if c.cfg.Debug {
		c.log.Debug().Str("method", req.Method).Str("url", req.URL.String()).Msg("unifi api request")
		ctx = attachDebugTrace(ctx, c.log)
	}

	resp, err := c.http.Do(req.WithContext(ctx))
	elapsed := time.Since(start)

	if err != nil {
		if c.cfg.Debug {
			c.log.Debug().Str("method", req.Method).Str("url", req.URL.String()).
				Err(err).Stringer("elapsed", elapsed).Msg("unifi api request failed")
		}
		metrics.APICalls.WithLabelValues(endpoint, "error").Inc()
		return nil, err
	}

	// Extract CSRF token from response header for cookie-based auth.
	c.session.UpdateFromResponse(resp)

	statusLabel := fmt.Sprintf("%dxx", resp.StatusCode/100)
	metrics.APICalls.WithLabelValues(endpoint, statusLabel).Inc()
	metrics.APIDuration.WithLabelValues(endpoint).Observe(elapsed.Seconds())

	if c.cfg.Debug {
		c.log.Debug().Str("method", req.Method).Str("url", req.URL.String()).
			Int("status", resp.StatusCode).Stringer("elapsed", elapsed).Msg("unifi api response")
	}

	if err := responseStatusError(resp, req); err != nil {
		return nil, err
	}
	return resp, nil
}

// responseStatusError translates a non-2xx UniFi API response into a typed
// error, closing the response body in the process. It returns nil for 2xx
// responses, leaving the body open for the caller to read.
func responseStatusError(resp *http.Response, req *http.Request) error {
	switch resp.StatusCode {
	case http.StatusBadRequest:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		bodyStr := string(body)
		if len(body) == 4096 {
			bodyStr += "...(truncated)"
		}
		if msg := classicErrorMsg(body); strings.HasSuffix(msg, "Existed") {
			// The classic API reports duplicate names as 400, not 409.
			return &ErrConflict{Msg: msg}
		}
		return &ErrBadRequest{Body: bodyStr, Arg: classicErrorArg(body)}
	case http.StatusUnauthorized:
		_ = resp.Body.Close()
		return &ErrUnauthorized{Msg: "HTTP 401"}
	case http.StatusNotFound:
		_ = resp.Body.Close()
		return &ErrNotFound{URL: req.URL.Path}
	case http.StatusTooManyRequests:
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"), time.Now())
		_ = resp.Body.Close()
		return &ErrRateLimit{RetryAfter: retryAfter}
	case http.StatusConflict:
		_ = resp.Body.Close()
		return &ErrConflict{Msg: "HTTP 409 conflict"}
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		_ = resp.Body.Close()
		return fmt.Errorf("UniFi API returned HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return nil
}

// attachDebugTrace attaches an httptrace.ClientTrace to ctx that logs
// connection lifecycle events at debug level. Must be called before
// req.WithContext so the trace is not overwritten; all callbacks fire on the
// goroutine that calls Do.
func attachDebugTrace(ctx context.Context, log zerolog.Logger) context.Context {
	trace := &httptrace.ClientTrace{
		GetConn: func(hostPort string) {
			log.Debug().Str("hostport", hostPort).Msg("httptrace: GetConn")
		},
		GotConn: func(i httptrace.GotConnInfo) {
			log.Debug().Bool("reused", i.Reused).Bool("was_idle", i.WasIdle).Msg("httptrace: GotConn")
		},
		ConnectStart: func(network, addr string) {
			log.Debug().Str("network", network).Str("addr", addr).Msg("httptrace: ConnectStart")
		},
		ConnectDone: func(network, addr string, err error) {
			log.Debug().Str("addr", addr).Err(err).Msg("httptrace: ConnectDone")
		},
		TLSHandshakeStart: func() {
			log.Debug().Msg("httptrace: TLSHandshakeStart")
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			log.Debug().Err(err).Msg("httptrace: TLSHandshakeDone")
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			log.Debug().Err(info.Err).Msg("httptrace: WroteRequest")
		},
		GotFirstResponseByte: func() {
			log.Debug().Msg("httptrace: GotFirstResponseByte")
		},
	}
	return httptrace.WithClientTrace(ctx, trace)
}

// withReauth executes fn, and on ErrUnauthorized calls EnsureAuth then retries once.
func (c *unifiClient) withReauth(ctx context.Context, fn func() error) error {
	err := fn()
	if err == nil {
		return nil
	}
	var unauthorized *ErrUnauthorized
	if !errors.As(err, &unauthorized) {
		return err
	}
	if authErr := c.session.EnsureAuth(ctx); authErr != nil {
		return fmt.Errorf("re-auth failed: %w", authErr)
	}
	return fn()
}

// Ping verifies the controller is reachable and accepts the credentials. An
// API key only authorizes the integration API; the classic /api/self answers
// 404 to it on UniFi OS, so key-based clients ping the integration site list.
func (c *unifiClient) Ping(ctx context.Context) error {
	url := c.networkURL("/api/self")
	if c.cfg.APIKey != "" {
		url = c.networkURL("/integration/v1/sites")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
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

// InvalidateZoneCache evicts all cached zone IDs, site IDs, and feature flags for site.
// Call before re-resolving zone names so the next GetZoneID/GetSiteID/HasFeature fetch fresh data.
func (c *unifiClient) InvalidateZoneCache(site string) {
	c.cacheMu.Lock()
	defer c.cacheMu.Unlock()
	delete(c.zoneIDCache, site)
	delete(c.featureCache, site)
	// siteIDCache is keyed by internalReference, display name, and UUID — all of which may
	// map to this site. We can't cheaply identify which keys belong to one site, so we
	// clear the whole siteIDCache. It is small (one entry per site) and will be repopulated on
	// the next call to GetSiteID.
	c.siteIDCache = make(map[string]string)
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

// ---- Site and Zone Resolution (integration v1) -----------------------------

func (c *unifiClient) GetSiteID(ctx context.Context, siteName string) (string, error) {
	return getSiteID(ctx, c, siteName)
}

func (c *unifiClient) GetZoneID(ctx context.Context, site, zoneName string) (string, error) {
	return getZoneID(ctx, c, site, zoneName)
}

func (c *unifiClient) DiscoverZones(ctx context.Context, site string) ([]Zone, error) {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return nil, err
	}
	return listFirewallZones(ctx, c, siteID)
}

func (c *unifiClient) DiscoverSites(ctx context.Context) ([]string, error) {
	return discoverSites(ctx, c)
}

// ---- Zone Policies (integration v1) ----------------------------------------

func (c *unifiClient) ListZonePolicies(ctx context.Context, site string) ([]ZonePolicy, error) {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return nil, err
	}
	return listZonePoliciesV1(ctx, c, siteID)
}

func (c *unifiClient) CreateZonePolicy(ctx context.Context, site string, p ZonePolicy) (ZonePolicy, error) {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return ZonePolicy{}, err
	}
	return createZonePolicyV1(ctx, c, siteID, p)
}

func (c *unifiClient) UpdateZonePolicy(ctx context.Context, site string, p ZonePolicy) error {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return err
	}
	return updateZonePolicyV1(ctx, c, siteID, p)
}

func (c *unifiClient) DeleteZonePolicy(ctx context.Context, site string, id string) error {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return err
	}
	return deleteZonePolicyV1(ctx, c, siteID, id)
}

// ---- Traffic Matching Lists (integration v1) --------------------------------

func (c *unifiClient) ListTrafficMatchingLists(ctx context.Context, site string) ([]TrafficMatchingList, error) {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return nil, err
	}
	return listTMLs(ctx, c, siteID)
}

func (c *unifiClient) CreateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) (TrafficMatchingList, error) {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return TrafficMatchingList{}, err
	}
	return createTML(ctx, c, siteID, list)
}

func (c *unifiClient) UpdateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) error {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return err
	}
	return updateTML(ctx, c, siteID, list)
}

func (c *unifiClient) DeleteTrafficMatchingList(ctx context.Context, site string, id string) error {
	siteID, err := getSiteID(ctx, c, site)
	if err != nil {
		return err
	}
	return deleteTML(ctx, c, siteID, id)
}

// ---- Feature Detection -----------------------------------------------------

func (c *unifiClient) HasFeature(ctx context.Context, site string, feature string) (bool, error) {
	return hasFeature(ctx, c, site, feature)
}
