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
//
// Rejected credentials will not start working on their own, and every
// attempt counts toward that lockout, so they back off up to
// loginRejectedWaitMax instead.
const (
	loginBackoffInitial   = 15 * time.Second
	loginBackoffMax       = 5 * time.Minute
	loginRejectedWaitMax  = 30 * time.Minute
	loginLimitWaitInitial = time.Minute
	loginLimitWaitMax     = 16 * time.Minute
)

// sessionManager serialises logins so that N workers hitting a 401 at once
// cause one login, not N.
type sessionManager struct {
	// loginSlot is held for the whole of a login. mu guards the fields below
	// and is never held across a request, so requests that only read the
	// CSRF token are not stalled behind a slow login.
	loginSlot  chan struct{}
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
		loginSlot: make(chan struct{}, 1),
		cfg:       cfg,
		http:      httpClient,
		now:       time.Now,
		sleep:     sleepContext,
		log:       log,
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
// Workers that arrive while a login is in progress wait for it and then
// find the session fresh.
func (s *sessionManager) EnsureAuth(ctx context.Context) error {
	// API key auth requires no login — key is sent per-request via SetAuthHeader.
	if s.cfg.APIKey != "" {
		return nil
	}

	select {
	case s.loginSlot <- struct{}{}:
	case <-ctx.Done():
		return fmt.Errorf("wait for UniFi login in progress: %w", ctx.Err())
	}
	defer func() { <-s.loginSlot }()

	if due, err := s.loginDue(); !due {
		return err
	}

	timeout := s.cfg.ReauthTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	err := s.login(tctx)
	if err != nil && ctx.Err() != nil {
		// The caller gave up; the controller has said nothing about the
		// credentials, so the next caller may try straight away.
		return fmt.Errorf("re-auth abandoned: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if err != nil {
		metrics.AuthErrors.Inc()
		wait := s.recordLoginFailure(err)
		event := s.log.Warn()
		var rejected *ErrUnauthorized
		if errors.As(err, &rejected) {
			event = s.log.Error()
		}
		event.Err(err).Int("consecutive_failures", s.loginFailures).Stringer("next_attempt_in", wait).
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

// loginDue reports whether a login should be attempted now. When it should
// not, the error is nil if another worker logged in a moment ago, or explains
// why the attempt is deferred.
func (s *sessionManager) loginDue() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.lastReauth) < s.cfg.ReauthMinGap {
		return false, nil
	}
	if s.loginFailures > 0 && s.now().Before(s.retryLoginAt) {
		return false, fmt.Errorf("re-auth deferred until %s after a failed login: %w",
			s.retryLoginAt.Format(time.RFC3339), s.lastLoginErr)
	}
	return true, nil
}

// recordLoginFailure must be called with s.mu held. It schedules the next
// login attempt and returns how long until then: doubling from
// loginBackoffInitial up to loginBackoffMax, or loginRejectedWaitMax when the
// credentials were rejected. A 429 waits at least its Retry-After or,
// without one, the loginLimitWait schedule, and the ErrRateLimit is updated
// to carry the wait.
func (s *sessionManager) recordLoginFailure(err error) time.Duration {
	s.loginFailures++
	limit := loginBackoffMax
	var rejected *ErrUnauthorized
	if errors.As(err, &rejected) {
		limit = loginRejectedWaitMax
	}
	wait := doubling(loginBackoffInitial, limit, s.loginFailures)
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

// login performs the UniFi login POST and stores the session cookie. The
// caller holds loginSlot, not mu.
func (s *sessionManager) login(ctx context.Context) error {
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

	if err := loginStatusError(resp, s.cfg.LoginPath, s.now()); err != nil {
		return err
	}

	if s.http.Jar != nil {
		s.http.Jar.SetCookies(req.URL, resp.Cookies())
	}
	// Write requests also need the CSRF token issued with the session. A
	// token from the previous session is invalid.
	s.mu.Lock()
	defer s.mu.Unlock()
	s.csrfToken = ""
	s.storeCSRFToken(resp.Header)
	return nil
}

// loginStatusError maps a login response to an error, or nil on success.
// Only a refusal of the credentials is an ErrUnauthorized: the Network
// Application answers a wrong password with 400, UniFi OS with 401 or 403.
// Anything else, such as UniFi OS answering 404 while it starts, says
// nothing about the credentials.
func loginStatusError(resp *http.Response, loginPath string, now time.Time) error {
	switch resp.StatusCode {
	case http.StatusOK, http.StatusCreated:
		return nil
	case http.StatusTooManyRequests:
		// Without Retry-After the wait is left to recordLoginFailure.
		var wait time.Duration
		if h := resp.Header.Get("Retry-After"); h != "" {
			wait = parseRetryAfter(h, now)
		}
		return &ErrRateLimit{RetryAfter: wait}
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return &ErrUnauthorized{Msg: fmt.Sprintf("login at %s returned HTTP %d; check UNIFI_USERNAME and UNIFI_PASSWORD", loginPath, resp.StatusCode)}
	default:
		return fmt.Errorf("login at %s returned HTTP %d", loginPath, resp.StatusCode)
	}
}
