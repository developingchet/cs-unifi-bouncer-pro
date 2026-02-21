package controller

import (
	"bytes"
	"context"
	"encoding/json"
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
	Username      string
	Password      string
	APIKey        string
	ReauthTimeout time.Duration
	ReauthMinGap  time.Duration
}

// sessionManager guards re-authentication with a mutex to prevent thundering herd.
type sessionManager struct {
	mu         sync.Mutex
	cfg        AuthConfig
	http       *http.Client
	csrfToken  string // cached from X-Csrf-Token response header
	lastReauth time.Time
	log        zerolog.Logger
}

func newSessionManager(cfg AuthConfig, httpClient *http.Client, log zerolog.Logger) *sessionManager {
	return &sessionManager{
		cfg:  cfg,
		http: httpClient,
		log:  log,
	}
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
	if time.Since(s.lastReauth) < s.cfg.ReauthMinGap {
		return nil
	}

	timeout := s.cfg.ReauthTimeout
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	tctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := s.login(tctx); err != nil {
		metrics.AuthErrors.Inc()
		return fmt.Errorf("re-auth failed: %w", err)
	}
	metrics.ReauthTotal.Inc()
	s.lastReauth = time.Now()
	s.log.Debug().Msg("re-authenticated with UniFi controller")
	return nil
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

// UpdateFromResponse extracts the CSRF token from the response header and stores it.
// This is called after every API response to handle CSRF token rotation.
func (s *sessionManager) UpdateFromResponse(resp *http.Response) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token := resp.Header.Get("X-Csrf-Token"); token != "" {
		s.csrfToken = token
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
		s.cfg.BaseURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build login request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("login request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return &ErrUnauthorized{Msg: fmt.Sprintf("login returned HTTP %d", resp.StatusCode)}
	}

	// Cookies are automatically managed by the cookie jar (set via Set-Cookie headers).
	// SetAuthHeader extracts the csrf_token from the jar and sends it as X-CSRF-Token header.
	return nil
}
