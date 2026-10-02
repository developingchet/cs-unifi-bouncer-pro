package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/rs/zerolog"
)

// AuthConfig holds credentials for session management.
type AuthConfig struct {
	BaseURL       string
	LoginPath     string
	Username      string
	Password      string
	APIKey        string
	ReauthTimeout time.Duration
	ReauthMinGap  time.Duration
}

// A controller that is still starting fails logins it would otherwise accept,
// so failed attempts are spaced out rather than repeated on every request
// that gets a 401.
//
// UniFi OS answers 429 without Retry-After in two cases that look the same:
// more than five successful logins in a minute, which clears within the
// minute, and a handful of failed logins, after which it refuses even the
// right password until it has seen no attempts for well over ten minutes.
// Consecutive 429s therefore wait from loginLimitWaitInitial up to
// loginLimitWaitMax, which outlasts the lockout.
const (
	loginBackoffInitial   = 15 * time.Second
	loginBackoffMax       = 5 * time.Minute
	loginLimitWaitInitial = time.Minute
	loginLimitWaitMax     = 16 * time.Minute
)

// sessionManager guards re-authentication with a mutex to prevent thundering herd.
type sessionManager struct {
	mu         sync.Mutex
	cfg        AuthConfig
	http       *http.Client
	csrfToken  string // cached from X-Csrf-Token response header
	lastReauth time.Time
	// loginFailures counts consecutive failed logins and loginLimited the
	// 429s among them; no login is attempted before retryLoginAt, and
	// EnsureAuth returns lastLoginErr instead.
	loginFailures int
	loginLimited  int
	retryLoginAt  time.Time
	lastLoginErr  error
	now           func() time.Time
	sleep         func(context.Context, time.Duration) error
	log           zerolog.Logger
}

func newSessionManager(cfg AuthConfig, httpClient *http.Client, log zerolog.Logger) *sessionManager {
	if cfg.LoginPath == "" {
		cfg.LoginPath = layoutUniFiOS.loginPath
	}
	return &sessionManager{
		cfg:   cfg,
		http:  httpClient,
		now:   time.Now,
		sleep: sleepContext,
		log:   log,
	}
}

func sleepContext(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// InitialAuth logs in for a new client. Short-lived commands log in on every
// run, so they can meet the controller's limit on successful logins; a wait
// of up to loginLimitWaitInitial is taken once rather than failing.
func (s *sessionManager) InitialAuth(ctx context.Context) error {
	err := s.EnsureAuth(ctx)
	var rateLimited *ErrRateLimit
	if !errors.As(err, &rateLimited) || rateLimited.RetryAfter > loginLimitWaitInitial {
		return err
	}
	s.log.Warn().Stringer("retry_in", rateLimited.RetryAfter).
		Msg("UniFi login rate limited; waiting before one more attempt")
	if err := s.sleep(ctx, rateLimited.RetryAfter); err != nil {
		return fmt.Errorf("wait for login rate limit: %w", err)
	}
	return s.EnsureAuth(ctx)
}

// EnsureAuth is called by client.go only when a 401 response is detected.
// The mutex ensures only one of N workers executes Login concurrently.
func (s *sessionManager) EnsureAuth(ctx context.Context) error {
	// API key auth requires no login — key is sent per-request via SetAuthHeader.
	if s.cfg.APIKey != "" {
		return nil
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Thundering-herd guard: if another worker already re-authed recently, skip.
	if s.now().Sub(s.lastReauth) < s.cfg.ReauthMinGap {
		return nil
	}
	if s.loginFailures > 0 && s.now().Before(s.retryLoginAt) {
		return fmt.Errorf("re-auth deferred until %s after a failed login: %w",
			s.retryLoginAt.Format(time.RFC3339), s.lastLoginErr)
	}

	timeout := s.cfg.ReauthTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := s.login(tctx); err != nil {
		metrics.AuthErrors.Inc()
		wait := s.recordLoginFailure(err)
		s.log.Warn().Err(err).Int("consecutive_failures", s.loginFailures).Stringer("next_attempt_in", wait).
			Msg("UniFi login failed")
		return fmt.Errorf("re-auth failed: %w", err)
	}
	metrics.ReauthTotal.Inc()
	s.lastReauth = s.now()
	s.loginFailures = 0
	s.loginLimited = 0
	s.lastLoginErr = nil
	s.log.Debug().Msg("re-authenticated with UniFi controller")
	return nil
}

// recordLoginFailure must be called with s.mu held. It schedules the next
// login attempt and returns how long until then: doubling from
// loginBackoffInitial up to loginBackoffMax, or longer for a 429, by its
// Retry-After or, without one, by the loginLimitWait schedule. The
// ErrRateLimit is updated to carry the wait.
func (s *sessionManager) recordLoginFailure(err error) time.Duration {
	s.loginFailures++
	wait := doubling(loginBackoffInitial, loginBackoffMax, s.loginFailures)
	var rateLimited *ErrRateLimit
	if errors.As(err, &rateLimited) {
		s.loginLimited++
		if rateLimited.RetryAfter <= 0 {
			rateLimited.RetryAfter = doubling(loginLimitWaitInitial, loginLimitWaitMax, s.loginLimited)
		}
		rateLimited.RetryAfter = max(rateLimited.RetryAfter, wait)
		wait = rateLimited.RetryAfter
	}
	s.retryLoginAt = s.now().Add(wait)
	s.lastLoginErr = err
	return wait
}

// doubling returns initial doubled for each attempt after the first, capped
// at limit.
func doubling(initial, limit time.Duration, attempt int) time.Duration {
	if shift := attempt - 1; shift < 16 {
		return min(initial<<shift, limit)
	}
	return limit
}

// SetAuthHeader applies auth credentials to an outgoing request.
func (s *sessionManager) SetAuthHeader(req *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cfg.APIKey != "" {
		req.Header.Set("X-Api-Key", s.cfg.APIKey)
		return
	}
	// For cookie-based auth, send the CSRF token from the last response header.
	// The cookie jar automatically sends cookies set during login.
	if s.csrfToken != "" {
		req.Header.Set("X-Csrf-Token", s.csrfToken)
	}
}

// UpdateFromResponse stores a rotated CSRF token from an API response.
func (s *sessionManager) UpdateFromResponse(resp *http.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.storeCSRFToken(resp.Header)
}

// storeCSRFToken must be called with s.mu held. UniFi OS returns the token as
// X-Csrf-Token on login and as X-Updated-Csrf-Token when it rotates.
func (s *sessionManager) storeCSRFToken(h http.Header) {
	for _, name := range []string{"X-Updated-Csrf-Token", "X-Csrf-Token"} {
		if token := h.Get(name); token != "" {
			s.csrfToken = token
			return
		}
	}
}

// login performs the UniFi login POST and stores the session cookie.
func (s *sessionManager) login(ctx context.Context) error {
	if s.cfg.APIKey != "" {
		// API key auth: no login needed, key is sent per-request.
		s.lastReauth = time.Now()
		return nil
	}

	body, err := json.Marshal(map[string]string{
		"username": s.cfg.Username,
		"password": s.cfg.Password,
	})
	if err != nil {
		return fmt.Errorf("marshal login body: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.BaseURL+s.cfg.LoginPath, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	// UniFi OS answers 403 to a login that carries a session cookie it still
	// accepts but no CSRF token, and counts it toward the failed-login limit.
	// Sessions survive a controller restart, so the login is sent without
	// cookies and the new ones are stored in the jar afterwards.
	noCookies := *s.http
	noCookies.Jar = nil
	resp, err := noCookies.Do(req)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		// Without Retry-After the wait is left to recordLoginFailure.
		var wait time.Duration
		if h := resp.Header.Get("Retry-After"); h != "" {
			wait = parseRetryAfter(h, s.now())
		}
		return &ErrRateLimit{RetryAfter: wait}
	case resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated:
		return &ErrUnauthorized{Msg: fmt.Sprintf("login at %s returned HTTP %d; check UNIFI_USERNAME and UNIFI_PASSWORD", s.cfg.LoginPath, resp.StatusCode)}
	}

	if s.http.Jar != nil {
		s.http.Jar.SetCookies(req.URL, resp.Cookies())
	}
	// Write requests also need the CSRF token issued with the session. A
	// token from the previous session is invalid.
	s.csrfToken = ""
	s.storeCSRFToken(resp.Header)
	return nil
}
