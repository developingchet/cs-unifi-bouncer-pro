package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// mockFWManager is a minimal firewall.Manager stub for blocklist tests.
type mockFWManager struct {
	mu       sync.Mutex
	banCalls int
	banErr   error
}

func (m *mockFWManager) BanCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.banCalls
}

func (m *mockFWManager) ApplyBan(_ context.Context, _, _ string, _ bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.banErr != nil {
		return m.banErr
	}
	m.banCalls++
	return nil
}

func (m *mockFWManager) ApplyBanWithZones(_ context.Context, _, _ string, _ bool, _ []config.ZonePair) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.banErr != nil {
		return m.banErr
	}
	m.banCalls++
	return nil
}
func (m *mockFWManager) ApplyUnban(_ context.Context, _, _ string, _ bool) error { return nil }
func (m *mockFWManager) EnsureInfrastructure(_ context.Context, _ []string) error { return nil }
func (m *mockFWManager) Reconcile(_ context.Context, _ []string) (*firewall.ReconcileResult, error) {
	return &firewall.ReconcileResult{}, nil
}
func (m *mockFWManager) SyncDirty(_ context.Context, _ []string) error  { return nil }
func (m *mockFWManager) Drain(_ context.Context, _ []string) error       { return nil }
func (m *mockFWManager) ZoneManager() *firewall.ZoneManager              { return nil }

func newTestManager(url string) (*Manager, *testutil.MockStore, *mockFWManager) {
	store := testutil.NewMockStore()
	fwMgr := &mockFWManager{}
	mgr := NewManager([]string{url}, 24*time.Hour, "test", fwMgr, store, []string{"default"}, zerolog.Nop())
	return mgr, store, fwMgr
}

func TestManager_FetchAndApply(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("1.2.3.4\n5.6.7.8\n203.0.113.1\n"))
	}))
	defer srv.Close()

	mgr, store, fwMgr := newTestManager(srv.URL)
	mgr.fetchAndApply(context.Background())

	bans, _ := store.BanList()
	if len(bans) != 3 {
		t.Errorf("expected 3 bans in store, got %d", len(bans))
	}
	if fwMgr.BanCount() != 3 {
		t.Errorf("expected 3 ApplyBan calls, got %d", fwMgr.BanCount())
	}
}

func TestManager_SkipsInvalidLines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("# comment\n\n1.2.3.4\nnot-an-ip\n255.255.255.256\n"))
	}))
	defer srv.Close()

	mgr, store, _ := newTestManager(srv.URL)
	mgr.fetchAndApply(context.Background())

	bans, _ := store.BanList()
	if len(bans) != 1 {
		t.Errorf("expected 1 valid ban, got %d", len(bans))
	}
	if _, ok := bans["1.2.3.4"]; !ok {
		t.Error("expected 1.2.3.4 to be banned")
	}
}

func TestManager_ParsesCIDR(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("203.0.113.0/24\n"))
	}))
	defer srv.Close()

	mgr, store, _ := newTestManager(srv.URL)
	mgr.fetchAndApply(context.Background())

	bans, _ := store.BanList()
	if len(bans) != 1 {
		t.Errorf("expected 1 ban for CIDR, got %d", len(bans))
	}
}

func TestManager_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	mgr, store, fwMgr := newTestManager(srv.URL)
	mgr.fetchAndApply(context.Background())

	bans, _ := store.BanList()
	if len(bans) != 0 {
		t.Errorf("expected 0 bans after server error, got %d", len(bans))
	}
	if fwMgr.BanCount() != 0 {
		t.Errorf("expected 0 ApplyBan calls after server error, got %d", fwMgr.BanCount())
	}
}

func TestManager_HTTPTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()

	mgr, _, _ := newTestManager(srv.URL)
	mgr.client.Timeout = 50 * time.Millisecond
	mgr.fetchAndApply(context.Background())
}

func TestParseEntry(t *testing.T) {
	tests := []struct {
		input  string
		wantIP string
		wantV6 bool
		wantOK bool
	}{
		{"1.2.3.4", "1.2.3.4", false, true},
		{"203.0.113.0/24", "203.0.113.0/24", false, true},
		{"2001:db8::1", "2001:db8::1", true, true},
		{"not-an-ip", "", false, false},
		{"", "", false, false},
		{strings.Repeat("x", 100), "", false, false},
	}
	for _, tc := range tests {
		ip, ipv6, ok := parseEntry(tc.input)
		if ok != tc.wantOK {
			t.Errorf("parseEntry(%q): ok got %v, want %v", tc.input, ok, tc.wantOK)
			continue
		}
		if ok {
			if ip != tc.wantIP {
				t.Errorf("parseEntry(%q): ip got %q, want %q", tc.input, ip, tc.wantIP)
			}
			if ipv6 != tc.wantV6 {
				t.Errorf("parseEntry(%q): ipv6 got %v, want %v", tc.input, ipv6, tc.wantV6)
			}
		}
	}
}
