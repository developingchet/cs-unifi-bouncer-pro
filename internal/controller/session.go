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
	cookie     string // session cookie value (username/password auth)
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
		req.Header.Set("X-API-Key", s.cfg.APIKey)
		return
	}
	if s.cookie != "" {
		req.Header.Set("Cookie", s.cookie)
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

	// Extract the session cookie (reset first so re-auth doesn't accumulate stale values)
	s.cookie = ""
	for _, c := range resp.Cookies() {
		if c.Name == "TOKEN" || c.Name == "unifises" || c.Name == "csrf_token" {
			if s.cookie == "" {
				s.cookie = c.Name + "=" + c.Value
			} else {
				s.cookie += "; " + c.Name + "=" + c.Value
			}
		}
	}
	return nil
}
