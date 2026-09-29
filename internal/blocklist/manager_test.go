package blocklist

import (
	"bytes"
	"context"
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

func (m *mockFWManager) ApplyUnban(_ context.Context, _, _ string, _ bool) error  { return nil }
func (m *mockFWManager) EnsureInfrastructure(_ context.Context, _ []string) error { return nil }
func (m *mockFWManager) LoadInfrastructure(_ context.Context, _ []string) error   { return nil }
func (m *mockFWManager) RepairInfrastructure(_ context.Context, _ []string) error { return nil }
func (m *mockFWManager) PrepareDrain(_ context.Context, _ []string) error         { return nil }
func (m *mockFWManager) Reconcile(_ context.Context, _ []string) (*firewall.ReconcileResult, error) {
	return &firewall.ReconcileResult{}, nil
}
func (m *mockFWManager) SyncDirty(_ context.Context, _ []string) error { return nil }
func (m *mockFWManager) Drain(_ context.Context, _ []string) error     { return nil }
func (m *mockFWManager) ZoneManager() *firewall.ZoneManager            { return nil }

func newTestManager(url string) (*Manager, *testutil.MockStore, *mockFWManager) {
	store := testutil.NewMockStore()
	fwMgr := &mockFWManager{}
	mgr := NewManager([]string{url}, 24*time.Hour, 7*24*time.Hour, banstate.New(store, fwMgr, []string{"default"}, false), nil, false, zerolog.Nop())
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

func TestManager_PathTokenAbsentFromClaimsAndLogs(t *testing.T) {
	const token = "private-path-token"
	for _, tc := range []struct {
		name   string
		status int
		closed bool
	}{
		{"successful fetch", http.StatusOK, false},
		{"failed fetch", http.StatusInternalServerError, false},
		{"transport failure", http.StatusOK, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte("203.0.113.9\n"))
			}))
			defer srv.Close()
			feed := Feed{URL: srv.URL + "/" + token + "/list?key=query-secret"}
			mgr, store := newFeedTestManager(feed)
			var logs bytes.Buffer
			mgr.log = zerolog.New(&logs)
			if tc.closed {
				srv.Close()
			}
			fetchErr := mgr.fetchFeed(context.Background(), feed)
			if tc.status == http.StatusOK && !tc.closed && fetchErr != nil {
				t.Fatal(fetchErr)
			}
			if tc.status != http.StatusOK || tc.closed {
				if fetchErr == nil || strings.Contains(fetchErr.Error(), token) || strings.Contains(fetchErr.Error(), "query-secret") {
					t.Fatalf("unsafe feed error: %v", fetchErr)
				}
			}
			mgr.fetchAndApply(context.Background())
			if strings.Contains(logs.String(), token) || strings.Contains(logs.String(), "query-secret") {
				t.Fatalf("feed URL secret in logs: %s", logs.String())
			}
			bans, err := store.BanList()
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range bans {
				for source := range entry.Claims {
					if strings.Contains(source, token) || strings.Contains(source, "query-secret") {
						t.Fatalf("feed URL secret in claim source: %s", source)
					}
				}
			}
		})
	}
}

func TestManager_LogsOpaqueFeedSourceAtStartup(t *testing.T) {
	const token = "private-path-token"
	feed := Feed{URL: "https://feed.example/" + token + "/list?key=query-secret", SourceKind: SourceKindAbuseIPDB}
	var logs bytes.Buffer
	mgr := NewFeedManager([]Feed{feed}, time.Hour, 24*time.Hour, nil, nil, true, zerolog.New(&logs))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	mgr.Run(ctx)
	got := logs.String()
	if !strings.Contains(got, `"source":"`+feed.sourceKey()+`"`) || !strings.Contains(got, `"url":"https://feed.example"`) {
		t.Fatalf("startup log omits the opaque source and host: %s", got)
	}
	if strings.Contains(got, token) || strings.Contains(got, "query-secret") {
		t.Fatalf("startup log exposed a URL credential: %s", got)
	}
}

func TestManager_ProtectsPrivateAndWhitelistedRanges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("10.0.0.0/8\n0.0.0.0/0\n198.51.100.0/24\n203.0.113.2\n"))
	}))
	defer srv.Close()
	manager, store, fw := newTestManager(srv.URL)
	whitelist, err := decision.ParseWhitelist([]string{"198.51.100.1"})
	if err != nil {
		t.Fatal(err)
	}
	manager.protected = whitelist
	manager.fetchAndApply(context.Background())
	bans, err := store.BanList()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || fw.BanCount() != 1 {
		t.Fatalf("protected addresses reached firewall: bans=%v calls=%d", bans, fw.BanCount())
	}
	if _, ok := bans["203.0.113.2"]; !ok {
		t.Fatal("public control address was not imported")
	}
}

func TestManager_RejectsOversizedFeedBeforeApplying(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("203.0.113.2\n"))
		_, _ = w.Write([]byte(strings.Repeat("#", maxFeedBytes)))
	}))
	defer srv.Close()
	manager, store, fw := newTestManager(srv.URL)
	if err := manager.fetchFeed(context.Background(), Feed{URL: srv.URL}); err == nil {
		t.Fatal("oversized feed was accepted")
	}
	bans, err := store.BanList()
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 0 || fw.BanCount() != 0 {
		t.Fatalf("oversized feed was partially applied: bans=%d calls=%d", len(bans), fw.BanCount())
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
		{"203.0.113.99/32", "203.0.113.99", false, true},
		{"2001:db8::7/128", "2001:db8::7", true, true},
		{"2001:db8:5::/64", "2001:db8:5::/64", true, true},
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
