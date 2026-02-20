package bouncer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/pool"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// mockFirewallManager satisfies firewall.Manager for handler tests.
type mockFirewallManager struct {
	applyBanErr     error
	applyUnbanErr   error
	applyBanCalls   int
	applyUnbanCalls int
}

func (m *mockFirewallManager) ApplyBan(_ context.Context, site, ip string, ipv6 bool) error {
	m.applyBanCalls++
	return m.applyBanErr
}

func (m *mockFirewallManager) ApplyUnban(_ context.Context, site, ip string, ipv6 bool) error {
	m.applyUnbanCalls++
	return m.applyUnbanErr
}

func (m *mockFirewallManager) Reconcile(_ context.Context, sites []string) (*firewall.ReconcileResult, error) {
	return &firewall.ReconcileResult{}, nil
}

func (m *mockFirewallManager) EnsureInfrastructure(_ context.Context, sites []string) error {
	return nil
}

// testCfg returns a minimal config suitable for handler tests.
func testCfg(sites ...string) *config.Config {
	if len(sites) == 0 {
		sites = []string{"default"}
	}
	return &config.Config{
		UnifiSites:        sites,
		RateLimitMaxCalls: 0, // unlimited by default
		RateLimitWindow:   time.Minute,
		BanTTL:            24 * time.Hour,
	}
}

func TestJobHandler_BanAlreadyExists(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg()
	fwMgr := &mockFirewallManager{}

	// Pre-record a ban
	_ = store.BanRecord("1.2.3.4", time.Now().Add(time.Hour), false)

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	err := handler(context.Background(), pool.SyncJob{Action: "ban", IP: "1.2.3.4"})
	if err != nil {
		t.Errorf("expected nil error for already-banned IP, got %v", err)
	}
	if fwMgr.applyBanCalls != 0 {
		t.Errorf("expected 0 ApplyBan calls for already-banned IP, got %d", fwMgr.applyBanCalls)
	}
}

func TestJobHandler_UnbanNotBanned(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg()
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	// IP not in ban list — delete should be skipped
	err := handler(context.Background(), pool.SyncJob{Action: "delete", IP: "5.6.7.8"})
	if err != nil {
		t.Errorf("expected nil error for unban of non-banned IP, got %v", err)
	}
	if fwMgr.applyUnbanCalls != 0 {
		t.Errorf("expected 0 ApplyUnban calls, got %d", fwMgr.applyUnbanCalls)
	}
}

func TestJobHandler_RateLimited(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites:        []string{"default"},
		RateLimitMaxCalls: 1,
		RateLimitWindow:   time.Hour,
		BanTTL:            24 * time.Hour,
	}
	fwMgr := &mockFirewallManager{}

	// Use up the rate budget
	_, _ = store.APIRateGate("unifi-group-update", cfg.RateLimitWindow, cfg.RateLimitMaxCalls)

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	err := handler(context.Background(), pool.SyncJob{Action: "ban", IP: "9.9.9.9"})
	if err == nil {
		t.Error("expected rate-limit error, got nil")
	}
}

func TestJobHandler_ApplyBanSuccess(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg("default", "site2")
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	job := pool.SyncJob{
		Action:    "ban",
		IP:        "203.0.113.1",
		IPv6:      false,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	// ApplyBan called once per site (2 sites)
	if fwMgr.applyBanCalls != 2 {
		t.Errorf("expected 2 ApplyBan calls (one per site), got %d", fwMgr.applyBanCalls)
	}
	// Ban recorded in store
	exists, _ := store.BanExists("203.0.113.1")
	if !exists {
		t.Error("expected ban to be recorded in store")
	}
}

func TestJobHandler_ApplyUnbanSuccess(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg()
	fwMgr := &mockFirewallManager{}

	_ = store.BanRecord("10.20.30.40", time.Now().Add(time.Hour), false)

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	if err := handler(context.Background(), pool.SyncJob{Action: "delete", IP: "10.20.30.40"}); err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if fwMgr.applyUnbanCalls != 1 {
		t.Errorf("expected 1 ApplyUnban call, got %d", fwMgr.applyUnbanCalls)
	}
	exists, _ := store.BanExists("10.20.30.40")
	if exists {
		t.Error("expected ban to be removed from store")
	}
}

func TestJobHandler_UnauthorizedRetriable(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg()
	fwMgr := &mockFirewallManager{applyBanErr: &controller.ErrUnauthorized{Msg: "test"}}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	err := handler(context.Background(), pool.SyncJob{Action: "ban", IP: "1.1.1.1"})
	if err == nil {
		t.Fatal("expected ErrUnauthorized, got nil")
	}
	var unauth *controller.ErrUnauthorized
	if !errors.As(err, &unauth) {
		t.Errorf("expected *ErrUnauthorized, got %T: %v", err, err)
	}
}

func TestJobHandler_StorageError_NonFatal(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg()
	fwMgr := &mockFirewallManager{}

	// Inject BanRecord error — should be non-fatal (warns, returns nil)
	store.SetError("BanRecord", errors.New("storage failure"))

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	job := pool.SyncJob{
		Action:    "ban",
		IP:        "2.2.2.2",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := handler(context.Background(), job); err != nil {
		t.Errorf("storage error should be non-fatal, got %v", err)
	}
}

func TestJobHandler_DryRun(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites:        []string{"default"},
		RateLimitMaxCalls: 0,
		RateLimitWindow:   time.Minute,
		BanTTL:            24 * time.Hour,
		DryRun:            true,
	}
	// When DryRun=true, the manager's ApplyBan returns nil without doing anything.
	// But our mock doesn't check DryRun — the handler passes DryRun via ManagerConfig.
	// Handler itself doesn't check DryRun; that's in the manager. So just verify no error.
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, zerolog.Nop())
	job := pool.SyncJob{
		Action:    "ban",
		IP:        "3.3.3.3",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := handler(context.Background(), job); err != nil {
		t.Errorf("DryRun mode should not return error, got %v", err)
	}
}
