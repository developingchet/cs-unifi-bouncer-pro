package controller

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

// fakeClock is a settable time source for the session manager.
type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time          { return c.t }
func (c *fakeClock) advance(d time.Duration) { c.t = c.t.Add(d) }

// loginServer answers /api/auth/login with whatever status() returns and
// counts the attempts.
func loginServer(t *testing.T, status func(r *http.Request) (int, http.Header)) (*httptest.Server, *int32) {
	t.Helper()
	var logins int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/auth/login" {
			w.WriteHeader(http.StatusOK)
			return
		}
		atomic.AddInt32(&logins, 1)
		code, h := status(r)
		for k, v := range h {
			w.Header()[k] = v
		}
		w.WriteHeader(code)
	}))
	t.Cleanup(srv.Close)
	return srv, &logins
}

func newBackoffSession(t *testing.T, srv *httptest.Server, clock *fakeClock) *sessionManager {
	t.Helper()
	httpClient := srv.Client()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	httpClient.Jar = jar
	sm := newSessionManager(AuthConfig{BaseURL: srv.URL, Username: "admin", Password: "pw"}, httpClient, zerolog.Nop())
	sm.now = clock.now
	return sm
}

// UniFi OS answers 403 to a login that carries a session cookie it still
// accepts but no CSRF token. A re-login must therefore not send the cookie.
func TestEnsureAuthLogsInWithoutSessionCookie(t *testing.T) {
	srv, logins := loginServer(t, func(r *http.Request) (int, http.Header) {
		if _, err := r.Cookie("TOKEN"); err == nil {
			return http.StatusForbidden, nil
		}
		return http.StatusOK, http.Header{"Set-Cookie": {"TOKEN=session; Path=/"}}
	})
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	sm := newBackoffSession(t, srv, clock)

	for i := 1; i <= 2; i++ {
		if err := sm.EnsureAuth(context.Background()); err != nil {
			t.Fatalf("login %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(logins); got != 2 {
		t.Fatalf("logins = %d, want 2", got)
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/proxy/network/api/self", nil)
	cookies := sm.http.Jar.Cookies(req.URL)
	if len(cookies) != 1 || cookies[0].Name != "TOKEN" {
		t.Fatalf("jar after login = %v, want the TOKEN session cookie", cookies)
	}
}

func TestEnsureAuthSpacesOutFailedLogins(t *testing.T) {
	var accept atomic.Bool
	srv, logins := loginServer(t, func(*http.Request) (int, http.Header) {
		if accept.Load() {
			return http.StatusOK, nil
		}
		return http.StatusForbidden, nil
	})
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	sm := newBackoffSession(t, srv, clock)
	ctx := context.Background()

	steps := []struct {
		advance    time.Duration
		wantLogins int32
	}{
		{0, 1},                // first failure
		{0, 1},                // retried at once: deferred
		{14 * time.Second, 1}, // still inside the 15 s backoff
		{time.Second, 2},      // 15 s: second failure, backoff now 30 s
		{29 * time.Second, 2}, // inside 30 s
		{time.Second, 3},      // third failure, backoff now 60 s
		{60 * time.Second, 4}, // fourth failure, backoff now 120 s
		{loginBackoffMax, 5},  // fifth failure
		{loginBackoffMax, 6},  // backoff capped
	}
	for i, s := range steps {
		clock.advance(s.advance)
		err := sm.EnsureAuth(ctx)
		var unauthorized *ErrUnauthorized
		if !errors.As(err, &unauthorized) {
			t.Fatalf("step %d: error = %v, want ErrUnauthorized", i, err)
		}
		if got := atomic.LoadInt32(logins); got != s.wantLogins {
			t.Fatalf("step %d: logins = %d, want %d", i, got, s.wantLogins)
		}
	}

	accept.Store(true)
	clock.advance(loginBackoffMax)
	if err := sm.EnsureAuth(ctx); err != nil {
		t.Fatalf("login after the backoff: %v", err)
	}
	accept.Store(false)
	before := atomic.LoadInt32(logins)
	clock.advance(time.Second)
	_ = sm.EnsureAuth(ctx)
	clock.advance(loginBackoffInitial - time.Second)
	_ = sm.EnsureAuth(ctx)
	if got := atomic.LoadInt32(logins) - before; got != 1 {
		t.Fatalf("logins after a success and a new failure = %d, want 1 (backoff restarts at %s)", got, loginBackoffInitial)
	}
}

func TestEnsureAuthWaitsOutLoginLockout(t *testing.T) {
	tests := []struct {
		name     string
		header   http.Header
		wantWait time.Duration
	}{
		{"no Retry-After, as UniFi OS sends", nil, loginLockoutWait},
		{"Retry-After in seconds", http.Header{"Retry-After": {"120"}}, 120 * time.Second},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, logins := loginServer(t, func(*http.Request) (int, http.Header) {
				return http.StatusTooManyRequests, tt.header
			})
			clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
			sm := newBackoffSession(t, srv, clock)

			err := sm.EnsureAuth(context.Background())
			var rateLimited *ErrRateLimit
			if !errors.As(err, &rateLimited) {
				t.Fatalf("error = %v, want ErrRateLimit", err)
			}
			if rateLimited.RetryAfter != tt.wantWait {
				t.Fatalf("RetryAfter = %s, want %s", rateLimited.RetryAfter, tt.wantWait)
			}

			clock.advance(tt.wantWait - time.Second)
			err = sm.EnsureAuth(context.Background())
			if !errors.As(err, &rateLimited) {
				t.Fatalf("deferred error = %v, want the ErrRateLimit kept", err)
			}
			if got := atomic.LoadInt32(logins); got != 1 {
				t.Fatalf("logins inside the lockout = %d, want 1", got)
			}
			clock.advance(time.Second)
			_ = sm.EnsureAuth(context.Background())
			if got := atomic.LoadInt32(logins); got != 2 {
				t.Fatalf("logins after the lockout = %d, want 2", got)
			}
		})
	}
}
