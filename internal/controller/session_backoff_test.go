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
		return http.StatusServiceUnavailable, nil
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
		if err == nil || errors.As(err, &unauthorized) {
			t.Fatalf("step %d: error = %v, want a non-credential failure", i, err)
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

func TestEnsureAuthBacksOffRejectedCredentials(t *testing.T) {
	srv, logins := loginServer(t, func(*http.Request) (int, http.Header) {
		return http.StatusUnauthorized, nil
	})
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	sm := newBackoffSession(t, srv, clock)
	ctx := context.Background()

	waits := []time.Duration{15 * time.Second, 30 * time.Second, time.Minute, 2 * time.Minute,
		4 * time.Minute, 8 * time.Minute, 16 * time.Minute, loginRejectedWaitMax, loginRejectedWaitMax}
	for i, want := range waits {
		var unauthorized *ErrUnauthorized
		if err := sm.EnsureAuth(ctx); !errors.As(err, &unauthorized) {
			t.Fatalf("attempt %d: error = %v, want ErrUnauthorized", i+1, err)
		}
		clock.advance(want - time.Second)
		if err := sm.EnsureAuth(ctx); !errors.As(err, &unauthorized) {
			t.Fatalf("attempt %d: deferred error = %v, want the ErrUnauthorized kept", i+1, err)
		}
		if got := atomic.LoadInt32(logins); got != int32(i+1) {
			t.Fatalf("attempt %d: logins inside the %s wait = %d, want %d", i+1, want, got, i+1)
		}
		clock.advance(time.Second)
	}
}

func TestLoginStatusError(t *testing.T) {
	tests := []struct {
		status       int
		wantNil      bool
		wantRejected bool
		wantLimited  bool
	}{
		{http.StatusOK, true, false, false},
		{http.StatusCreated, true, false, false},
		{http.StatusBadRequest, false, true, false},
		{http.StatusUnauthorized, false, true, false},
		{http.StatusForbidden, false, true, false},
		{http.StatusTooManyRequests, false, false, true},
		{http.StatusNotFound, false, false, false},
		{http.StatusBadGateway, false, false, false},
		{http.StatusServiceUnavailable, false, false, false},
	}
	for _, tt := range tests {
		t.Run(http.StatusText(tt.status), func(t *testing.T) {
			err := loginStatusError(&http.Response{StatusCode: tt.status, Header: http.Header{}},
				"/api/auth/login", time.Unix(1_700_000_000, 0))
			if (err == nil) != tt.wantNil {
				t.Fatalf("error = %v, want nil %v", err, tt.wantNil)
			}
			var rejected *ErrUnauthorized
			if got := errors.As(err, &rejected); got != tt.wantRejected {
				t.Errorf("ErrUnauthorized = %v, want %v (error %v)", got, tt.wantRejected, err)
			}
			var limited *ErrRateLimit
			if got := errors.As(err, &limited); got != tt.wantLimited {
				t.Errorf("ErrRateLimit = %v, want %v (error %v)", got, tt.wantLimited, err)
			}
		})
	}
}

// A caller that gives up mid-login has learnt nothing about the credentials,
// so the next caller logs in at once rather than waiting out a backoff.
func TestEnsureAuthCancelledLoginIsNotAFailure(t *testing.T) {
	release := make(chan struct{})
	var hang atomic.Bool
	hang.Store(true)
	srv, logins := loginServer(t, func(r *http.Request) (int, http.Header) {
		if hang.Load() {
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}
		return http.StatusOK, nil
	})
	t.Cleanup(func() { close(release) })
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	sm := newBackoffSession(t, srv, clock)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := sm.EnsureAuth(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancelled login error = %v, want context.DeadlineExceeded", err)
	}

	hang.Store(false)
	if err := sm.EnsureAuth(context.Background()); err != nil {
		t.Fatalf("login after a cancelled one: %v", err)
	}
	if got := atomic.LoadInt32(logins); got != 2 {
		t.Fatalf("logins = %d, want 2", got)
	}
}

// Requests keep setting their headers while a login waits on a slow
// controller.
func TestSetAuthHeaderDoesNotWaitForLogin(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	srv, _ := loginServer(t, func(*http.Request) (int, http.Header) {
		close(entered)
		<-release
		return http.StatusOK, nil
	})
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	sm := newBackoffSession(t, srv, clock)

	done := make(chan error, 1)
	go func() { done <- sm.EnsureAuth(context.Background()) }()
	<-entered

	headerSet := make(chan struct{})
	go func() {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		sm.SetAuthHeader(req)
		close(headerSet)
	}()
	select {
	case <-headerSet:
	case <-time.After(5 * time.Second):
		t.Fatal("SetAuthHeader blocked behind an in-flight login")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("login: %v", err)
	}
}

func TestEnsureAuthWaitsOutLoginLimit(t *testing.T) {
	tests := []struct {
		name      string
		header    http.Header
		wantWaits []time.Duration // per consecutive 429
	}{
		{
			"no Retry-After, as UniFi OS sends", nil,
			[]time.Duration{time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute,
				loginLimitWaitMax, loginLimitWaitMax},
		},
		{
			"Retry-After in seconds", http.Header{"Retry-After": {"120"}},
			// The failed-login backoff overtakes Retry-After from the fifth.
			[]time.Duration{120 * time.Second, 120 * time.Second, 120 * time.Second, 120 * time.Second,
				4 * time.Minute, loginBackoffMax},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv, logins := loginServer(t, func(*http.Request) (int, http.Header) {
				return http.StatusTooManyRequests, tt.header
			})
			clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
			sm := newBackoffSession(t, srv, clock)
			ctx := context.Background()

			for i, want := range tt.wantWaits {
				err := sm.EnsureAuth(ctx)
				var rateLimited *ErrRateLimit
				if !errors.As(err, &rateLimited) {
					t.Fatalf("429 %d: error = %v, want ErrRateLimit", i+1, err)
				}
				if rateLimited.RetryAfter != want {
					t.Fatalf("429 %d: RetryAfter = %s, want %s", i+1, rateLimited.RetryAfter, want)
				}
				clock.advance(want - time.Second)
				if err := sm.EnsureAuth(ctx); !errors.As(err, &rateLimited) {
					t.Fatalf("429 %d: deferred error = %v, want the ErrRateLimit kept", i+1, err)
				}
				if got := atomic.LoadInt32(logins); got != int32(i+1) {
					t.Fatalf("429 %d: logins inside the wait = %d, want %d", i+1, got, i+1)
				}
				clock.advance(time.Second)
			}
		})
	}
}

func TestInitialAuthWaitsOnceForLoginLimit(t *testing.T) {
	var limited atomic.Int32
	srv, logins := loginServer(t, func(*http.Request) (int, http.Header) {
		if limited.Add(-1) >= 0 {
			return http.StatusTooManyRequests, nil
		}
		return http.StatusOK, nil
	})

	tests := []struct {
		name       string
		limited    int32
		wantErr    bool
		wantLogins int32
		wantSlept  time.Duration
	}{
		{"accepted at once", 0, false, 1, 0},
		{"limited once, then accepted", 1, false, 2, loginLimitWaitInitial},
		{"still limited after the wait", 2, true, 2, loginLimitWaitInitial},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limited.Store(tt.limited)
			atomic.StoreInt32(logins, 0)
			clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
			sm := newBackoffSession(t, srv, clock)
			var slept time.Duration
			sm.sleep = func(_ context.Context, d time.Duration) error {
				slept += d
				clock.advance(d)
				return nil
			}

			err := sm.InitialAuth(context.Background())
			if (err != nil) != tt.wantErr {
				t.Fatalf("InitialAuth error = %v, wantErr %v", err, tt.wantErr)
			}
			if got := atomic.LoadInt32(logins); got != tt.wantLogins {
				t.Fatalf("logins = %d, want %d", got, tt.wantLogins)
			}
			if slept != tt.wantSlept {
				t.Fatalf("slept %s, want %s", slept, tt.wantSlept)
			}
		})
	}
}

func TestInitialAuthDoesNotWaitOutLongLimits(t *testing.T) {
	srv, logins := loginServer(t, func(*http.Request) (int, http.Header) {
		return http.StatusTooManyRequests, http.Header{"Retry-After": {"600"}}
	})
	clock := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	sm := newBackoffSession(t, srv, clock)
	sm.sleep = func(context.Context, time.Duration) error {
		t.Fatal("InitialAuth slept for a ten-minute Retry-After")
		return nil
	}

	var rateLimited *ErrRateLimit
	if err := sm.InitialAuth(context.Background()); !errors.As(err, &rateLimited) {
		t.Fatalf("error = %v, want ErrRateLimit", err)
	}
	if got := atomic.LoadInt32(logins); got != 1 {
		t.Fatalf("logins = %d, want 1", got)
	}
}
