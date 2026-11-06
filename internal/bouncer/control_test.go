package bouncer

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

const controlTestToken = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// fakeSyncer records SyncDirty and Reconcile calls.
type fakeSyncer struct {
	mu           sync.Mutex
	syncs        int
	syncErr      error
	reconciles   int
	reconcileRes *firewall.ReconcileResult
	reconcileErr error
}

func (f *fakeSyncer) SyncDirty(context.Context, []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.syncs++
	return f.syncErr
}

func (f *fakeSyncer) Reconcile(context.Context, []string) (*firewall.ReconcileResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reconciles++
	return f.reconcileRes, f.reconcileErr
}

type controlFixture struct {
	control  *control
	mux      *http.ServeMux
	store    *testutil.MockStore
	fw       *mockFirewallManager
	syncer   *fakeSyncer
	allowRec bool
}

func newControlFixture(t *testing.T) *controlFixture {
	t.Helper()
	whitelist, err := decision.ParseWhitelist([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	f := &controlFixture{
		control:  &control{log: zerolog.Nop(), synced: func() bool { return true }},
		mux:      http.NewServeMux(),
		store:    testutil.NewMockStore(),
		fw:       &mockFirewallManager{},
		syncer:   &fakeSyncer{reconcileRes: &firewall.ReconcileResult{Added: 3, Removed: 1, Elapsed: 2 * time.Second}},
		allowRec: true,
	}
	sites := []string{"default", "branch"}
	f.control.state.Store(&controlState{
		actions: &ManualActions{
			Claims:    banstate.New(f.store, f.fw, sites, false),
			Firewall:  f.syncer,
			History:   f.store,
			Sites:     sites,
			BanTTL:    48 * time.Hour,
			Whitelist: whitelist,
			Log:       zerolog.Nop(),
		},
		reconcileAllowed: func() bool { return f.allowRec },
	})
	f.control.register(f.mux, controlTestToken)
	return f
}

// call sends a request as a same-host caller with the token unless the
// options say otherwise.
type callOpts struct {
	method      string
	remote      string
	token       string
	contentType string
}

func (f *controlFixture) call(path, body string, opts callOpts) *httptest.ResponseRecorder {
	if opts.method == "" {
		opts.method = http.MethodPost
	}
	if opts.remote == "" {
		opts.remote = "127.0.0.1:40000"
	}
	if opts.token == "" {
		opts.token = controlTestToken
	}
	if opts.contentType == "" {
		opts.contentType = "application/json"
	}
	r := httptest.NewRequest(opts.method, path, strings.NewReader(body))
	r.RemoteAddr = opts.remote
	local := &net.TCPAddr{IP: net.ParseIP("172.18.0.5"), Port: 8081}
	r = r.WithContext(context.WithValue(r.Context(), http.LocalAddrContextKey, net.Addr(local)))
	if opts.token != "-" {
		r.Header.Set(SnapshotTokenHeader, opts.token)
	}
	r.Header.Set("Content-Type", opts.contentType)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	return w
}

func TestControlEndpointsRequireSameHostAndToken(t *testing.T) {
	f := newControlFixture(t)
	paths := []struct {
		path   string
		method string
	}{
		{ControlBanPath, http.MethodPost},
		{ControlUnbanPath, http.MethodPost},
		{ControlReconcilePath, http.MethodPost},
		{SyncStatusPath, http.MethodGet},
	}
	body := `{"ip":"198.51.100.7"}`
	for _, p := range paths {
		t.Run(p.path, func(t *testing.T) {
			cases := []struct {
				name string
				opts callOpts
				want int
			}{
				{"no token", callOpts{method: p.method, token: "-"}, http.StatusForbidden},
				{"wrong token", callOpts{method: p.method, token: controlTestToken[:63] + "x"}, http.StatusForbidden},
				{"other host with token", callOpts{method: p.method, remote: "192.0.2.50:40000"}, http.StatusForbidden},
				{"own address with token", callOpts{method: p.method, remote: "172.18.0.5:40000"}, http.StatusOK},
				{"wrong method", callOpts{method: http.MethodPut}, http.StatusMethodNotAllowed},
			}
			for _, c := range cases {
				if got := f.call(p.path, body, c.opts).Code; got != c.want {
					t.Errorf("%s: status = %d, want %d", c.name, got, c.want)
				}
			}
		})
	}
	if f.fw.applyBanCalls != len([]string{"default", "branch"}) {
		t.Errorf("ApplyBan called %d times, want one per site from the one authorized ban", f.fw.applyBanCalls)
	}
}

func TestControlEndpointsBeforeStartup(t *testing.T) {
	c := &control{log: zerolog.Nop()}
	mux := http.NewServeMux()
	c.register(mux, controlTestToken)
	f := &controlFixture{control: c, mux: mux}
	if got := f.call(ControlBanPath, `{"ip":"198.51.100.7"}`, callOpts{}).Code; got != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 before EnableControl", got)
	}
}

func TestControlBan(t *testing.T) {
	f := newControlFixture(t)
	before := time.Now()
	w := f.call(ControlBanPath, `{"ip":"198.51.100.7/32","duration":"2h"}`, callOpts{})
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", w.Code, w.Body)
	}
	var resp ControlResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.IP != "198.51.100.7" || resp.Sites != 2 || resp.ExpiresAt == nil || resp.SyncError != "" {
		t.Fatalf("response = %+v", resp)
	}
	if d := resp.ExpiresAt.Sub(before); d < 2*time.Hour || d > 2*time.Hour+time.Minute {
		t.Errorf("expires in %v, want 2h", d)
	}
	entry, _ := f.store.BanGet("198.51.100.7")
	if entry == nil || len(entry.Claims) != 1 {
		t.Fatalf("stored ban = %+v, want one claim", entry)
	}
	if _, ok := entry.Claims[ManualOrigin]; !ok {
		t.Errorf("claims = %v, want a %q claim", entry.Claims, ManualOrigin)
	}
	events, _ := f.store.ListEventsForIP("198.51.100.7", 10)
	if len(events) != 1 || events[0].Action != "ban" || events[0].Origin != ManualOrigin {
		t.Errorf("history = %+v, want one manual ban", events)
	}
	if f.syncer.syncs != 1 {
		t.Errorf("SyncDirty called %d times, want 1", f.syncer.syncs)
	}
}

func TestControlBanDuration(t *testing.T) {
	for _, tt := range []struct {
		duration string
		want     time.Duration
	}{
		{"", 48 * time.Hour},
		{"0s", 48 * time.Hour},
		{"720h", 48 * time.Hour},
		{"30m", 30 * time.Minute},
	} {
		f := newControlFixture(t)
		before := time.Now()
		w := f.call(ControlBanPath, `{"ip":"198.51.100.8","duration":"`+tt.duration+`"}`, callOpts{})
		var resp ControlResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || resp.ExpiresAt == nil {
			t.Fatalf("duration %q: status %d body %s", tt.duration, w.Code, w.Body)
		}
		if d := resp.ExpiresAt.Sub(before); d < tt.want || d > tt.want+time.Minute {
			t.Errorf("duration %q: expires in %v, want %v", tt.duration, d, tt.want)
		}
	}
}

func TestControlBanRefusesGuardedAndInvalidInput(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		contentType string
		want        int
		wantErr     string
	}{
		{"private address", `{"ip":"10.0.0.1"}`, "", http.StatusBadRequest, "private"},
		{"loopback", `{"ip":"127.0.0.1"}`, "", http.StatusBadRequest, "private"},
		{"whitelisted", `{"ip":"203.0.113.9"}`, "", http.StatusBadRequest, "BLOCK_WHITELIST"},
		{"broader than /8", `{"ip":"64.0.0.0/7"}`, "", http.StatusBadRequest, "too broad"},
		{"IPv6 broader than /32", `{"ip":"2001:db8::/31"}`, "", http.StatusBadRequest, "too broad"},
		{"not an address", `{"ip":"gateway"}`, "", http.StatusBadRequest, "invalid IP"},
		{"missing address", `{}`, "", http.StatusBadRequest, ""},
		{"negative duration", `{"ip":"198.51.100.7","duration":"-1h"}`, "", http.StatusBadRequest, "negative"},
		{"unparsable duration", `{"ip":"198.51.100.7","duration":"soon"}`, "", http.StatusBadRequest, "invalid duration"},
		{"unknown field", `{"ip":"198.51.100.7","source":"crowdsec"}`, "", http.StatusBadRequest, "unknown field"},
		{"trailing data", `{"ip":"198.51.100.7"}{"ip":"198.51.100.8"}`, "", http.StatusBadRequest, "trailing"},
		{"not JSON", `ip=198.51.100.7`, "", http.StatusBadRequest, "invalid request body"},
		{"oversized body", `{"ip":"198.51.100.7","duration":"` + strings.Repeat("1", maxControlBody) + `"}`, "", http.StatusBadRequest, ""},
		{"wrong content type", `{"ip":"198.51.100.7"}`, "text/plain", http.StatusUnsupportedMediaType, "application/json"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newControlFixture(t)
			w := f.call(ControlBanPath, tt.body, callOpts{contentType: tt.contentType})
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tt.want, w.Body)
			}
			var e ErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil || e.Error == "" {
				t.Fatalf("body %s is not an error response", w.Body)
			}
			if !strings.Contains(e.Error, tt.wantErr) {
				t.Errorf("error = %q, want it to contain %q", e.Error, tt.wantErr)
			}
			if f.fw.applyBanCalls != 0 {
				t.Errorf("refused request reached the firewall")
			}
			if bans, _ := f.store.BanList(); len(bans) != 0 {
				t.Errorf("refused request stored bans: %v", bans)
			}
		})
	}
}

func TestControlBanReportsFailures(t *testing.T) {
	t.Run("sync error", func(t *testing.T) {
		f := newControlFixture(t)
		f.syncer.syncErr = errors.New("circuit breaker open")
		w := f.call(ControlBanPath, `{"ip":"198.51.100.7"}`, callOpts{})
		var resp ControlResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status %d body %s", w.Code, w.Body)
		}
		if !strings.Contains(resp.SyncError, "circuit breaker open") {
			t.Errorf("sync_error = %q", resp.SyncError)
		}
	})
	t.Run("claim error", func(t *testing.T) {
		f := newControlFixture(t)
		f.fw.applyBanErr = errors.New("controller unreachable")
		w := f.call(ControlBanPath, `{"ip":"198.51.100.7"}`, callOpts{})
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500 (body %s)", w.Code, w.Body)
		}
	})
}

func TestControlUnban(t *testing.T) {
	f := newControlFixture(t)
	ctx := context.Background()
	claims := f.control.state.Load().actions.Claims
	if _, err := claims.Claim(ctx, "198.51.100.7", false, "crowdsec:id:1", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	w := f.call(ControlUnbanPath, `{"ip":"198.51.100.7"}`, callOpts{})
	var resp ControlResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("status %d body %s", w.Code, w.Body)
	}
	if resp.Lifted == nil || !*resp.Lifted || resp.IP != "198.51.100.7" {
		t.Fatalf("response = %+v, want the ban lifted", resp)
	}
	if entry, _ := f.store.BanGet("198.51.100.7"); entry != nil {
		t.Errorf("ban still stored: %+v", entry)
	}
	events, _ := f.store.ListEventsForIP("198.51.100.7", 10)
	if len(events) != 1 || events[0].Action != "unban" || events[0].Origin != ManualOrigin {
		t.Errorf("history = %+v, want one manual unban", events)
	}

	w = f.call(ControlUnbanPath, `{"ip":"not-an-ip"}`, callOpts{})
	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid address: status = %d, want 400", w.Code)
	}
}

func TestControlReconcile(t *testing.T) {
	t.Run("before the startup gate opens", func(t *testing.T) {
		f := newControlFixture(t)
		f.allowRec = false
		if w := f.call(ControlReconcilePath, "", callOpts{}); w.Code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", w.Code)
		}
		if f.syncer.reconciles != 0 {
			t.Fatal("reconcile ran before the startup gate opened")
		}
	})
	t.Run("runs", func(t *testing.T) {
		f := newControlFixture(t)
		f.syncer.reconcileErr = errors.New("site branch: list groups: HTTP 500")
		w := f.call(ControlReconcilePath, "", callOpts{})
		var resp ReconcileResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
			t.Fatalf("status %d body %s", w.Code, w.Body)
		}
		if resp.Added != 3 || resp.Removed != 1 || resp.ElapsedSeconds != 2 || !strings.Contains(resp.Error, "HTTP 500") {
			t.Fatalf("response = %+v", resp)
		}
	})
	t.Run("one at a time", func(t *testing.T) {
		f := newControlFixture(t)
		f.control.reconciling.Lock()
		defer f.control.reconciling.Unlock()
		if w := f.call(ControlReconcilePath, "", callOpts{}); w.Code != http.StatusConflict {
			t.Fatalf("status = %d, want 409", w.Code)
		}
	})
	t.Run("failed without a result", func(t *testing.T) {
		f := newControlFixture(t)
		f.syncer.reconcileRes = nil
		f.syncer.reconcileErr = context.DeadlineExceeded
		if w := f.call(ControlReconcilePath, "", callOpts{}); w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", w.Code)
		}
	})
}
