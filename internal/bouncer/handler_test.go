package bouncer

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// nopRecorder is a MetricsRecorder that discards all recordings.
type nopRecorder struct{}

func (nopRecorder) RecordBan(_, _ string) {}
func (nopRecorder) RecordDeletion()       {}

// mockFirewallManager satisfies firewall.Manager for handler tests.
// siteErrors allows per-site error injection; if empty, applyBanErr/applyUnbanErr is used.
type mockFirewallManager struct {
	applyBanErr     error
	applyUnbanErr   error
	applyBanCalls   int
	applyUnbanCalls int
	// per-site errors: if a site key exists in the map, that error is returned.
	siteErrors map[string]error
	// bannedSites tracks which sites had ApplyBan called.
	bannedSites []string
	// lastZonePairs records the zone pairs from the most recent ApplyBanWithZones call.
	lastZonePairs []config.ZonePair
}

func (m *mockFirewallManager) ApplyBan(_ context.Context, site, ip string, ipv6 bool) error {
	m.applyBanCalls++
	m.bannedSites = append(m.bannedSites, site)
	if m.siteErrors != nil {
		if err, ok := m.siteErrors[site]; ok {
			return err
		}
		return nil
	}
	return m.applyBanErr
}

func (m *mockFirewallManager) ApplyBanWithZones(_ context.Context, site, _ string, _ bool, zonePairs []config.ZonePair) error {
	m.applyBanCalls++
	m.bannedSites = append(m.bannedSites, site)
	m.lastZonePairs = zonePairs
	if m.siteErrors != nil {
		if err, ok := m.siteErrors[site]; ok {
			return err
		}
		return nil
	}
	return m.applyBanErr
}

func (m *mockFirewallManager) ApplyUnban(_ context.Context, site, ip string, ipv6 bool) error {
	m.applyUnbanCalls++
	if m.siteErrors != nil {
		if err, ok := m.siteErrors[site]; ok {
			return err
		}
		return nil
	}
	return m.applyUnbanErr
}

func (m *mockFirewallManager) Reconcile(_ context.Context, sites []string) (*firewall.ReconcileResult, error) {
	return &firewall.ReconcileResult{}, nil
}

func (m *mockFirewallManager) EnsureInfrastructure(_ context.Context, sites []string) error {
	return nil
}

func (m *mockFirewallManager) SyncDirty(_ context.Context, sites []string) error {
	return nil
}

func (m *mockFirewallManager) Drain(_ context.Context, sites []string) error {
	return nil
}

func (m *mockFirewallManager) ZoneManager() *firewall.ZoneManager {
	return nil
}

// testCfg returns a minimal config suitable for handler tests.
func testCfg(sites ...string) *config.Config {
	if len(sites) == 0 {
		sites = []string{"default"}
	}
	return &config.Config{
		UnifiSites: sites,
		BanTTL:     24 * time.Hour,
	}
}

func TestJobHandler_BanAlreadyExists(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg()
	fwMgr := &mockFirewallManager{}

	// Pre-record a ban
	_ = store.BanRecord("1.2.3.4", time.Now().Add(time.Hour), false)

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	err := handler(context.Background(), SyncJob{Action: "ban", IP: "1.2.3.4"})
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

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	// IP not in ban list — delete should be skipped
	err := handler(context.Background(), SyncJob{Action: "delete", IP: "5.6.7.8"})
	if err != nil {
		t.Errorf("expected nil error for unban of non-banned IP, got %v", err)
	}
	if fwMgr.applyUnbanCalls != 0 {
		t.Errorf("expected 0 ApplyUnban calls, got %d", fwMgr.applyUnbanCalls)
	}
}

func TestJobHandler_ApplyBanSuccess(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg("default", "site2")
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
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

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	if err := handler(context.Background(), SyncJob{Action: "delete", IP: "10.20.30.40"}); err != nil {
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

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	err := handler(context.Background(), SyncJob{Action: "ban", IP: "1.1.1.1"})
	if err == nil {
		t.Fatal("expected ErrUnauthorized, got nil")
	}
	var unauth *controller.ErrUnauthorized
	if !errors.As(err, &unauth) {
		t.Errorf("expected *ErrUnauthorized, got %T: %v", err, err)
	}
}

func TestJobHandler_StorageError_Fatal(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg()
	fwMgr := &mockFirewallManager{}

	// Inject BanRecord error â bbolt-first ordering means a write failure must
	// abort the job so the UniFi write is never attempted without a bbolt record.
	store.SetError("BanRecord", errors.New("storage failure"))

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "2.2.2.2",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := handler(context.Background(), job); err == nil {
		t.Error("expected error from bbolt write failure, got nil")
	}
}

func TestJobHandler_DryRun(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites: []string{"default"},
		BanTTL:     24 * time.Hour,
		DryRun:     true,
	}
	// When DryRun=true, the manager's ApplyBan returns nil without doing anything.
	// But our mock doesn't check DryRun — the handler passes DryRun via ManagerConfig.
	// Handler itself doesn't check DryRun; that's in the manager. So just verify no error.
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "3.3.3.3",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := handler(context.Background(), job); err != nil {
		t.Errorf("DryRun mode should not return error, got %v", err)
	}
}

func TestHandler_ContinuesOnPerSiteFailure(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg("site-a", "site-b")
	fwMgr := &mockFirewallManager{
		siteErrors: map[string]error{
			"site-a": errors.New("transient network error"),
		},
	}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "1.2.3.4",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := handler(context.Background(), job)
	// Should return an error (site-a failed) but site-b should also be called.
	if err == nil {
		t.Error("expected error from site-a failure, got nil")
	}
	if fwMgr.applyBanCalls != 2 {
		t.Errorf("expected ApplyBan called for both sites, got %d calls", fwMgr.applyBanCalls)
	}
	siteB := false
	for _, s := range fwMgr.bannedSites {
		if s == "site-b" {
			siteB = true
		}
	}
	if !siteB {
		t.Error("site-b should have received the ban even though site-a failed")
	}
}

func TestHandler_AuthErrorStopsAllSites(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := testCfg("site-a", "site-b")
	fwMgr := &mockFirewallManager{
		siteErrors: map[string]error{
			"site-a": &controller.ErrUnauthorized{Msg: "401"},
		},
	}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "5.6.7.8",
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	err := handler(context.Background(), job)
	if err == nil {
		t.Fatal("expected ErrUnauthorized to be returned")
	}
	var unauth *controller.ErrUnauthorized
	if !errors.As(err, &unauth) {
		t.Errorf("expected *ErrUnauthorized, got %T: %v", err, err)
	}
	// site-b should NOT have been called
	if fwMgr.applyBanCalls != 1 {
		t.Errorf("expected only site-a to be called (1 call), got %d", fwMgr.applyBanCalls)
	}
	for _, s := range fwMgr.bannedSites {
		if s == "site-b" {
			t.Error("site-b should not have been called after auth error")
		}
	}
}

func TestJobHandler_BanTTLCapApplied(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites: []string{"default"},
		BanTTL:     24 * time.Hour,
	}
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	// job.ExpiresAt is zero (permanent ban)
	job := SyncJob{
		Action: "ban",
		IP:     "10.0.0.1",
		IPv6:   false,
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bans, _ := store.BanList()
	entry, ok := bans["10.0.0.1"]
	if !ok {
		t.Fatal("expected ban to be recorded")
	}
	// ExpiresAt should be approximately now+24h (not zero)
	if entry.ExpiresAt.IsZero() {
		t.Error("ExpiresAt should not be zero after BAN_TTL cap")
	}
	maxExpiry := time.Now().Add(cfg.BanTTL + time.Minute)
	if entry.ExpiresAt.After(maxExpiry) {
		t.Errorf("ExpiresAt %v exceeds BAN_TTL cap %v", entry.ExpiresAt, maxExpiry)
	}
}

func TestJobHandler_BanTTLCapAppliedWhenTooLong(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites: []string{"default"},
		BanTTL:     24 * time.Hour,
	}
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "10.0.0.2",
		ExpiresAt: time.Now().Add(10 * 24 * time.Hour), // 10x BanTTL
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bans, _ := store.BanList()
	entry := bans["10.0.0.2"]
	maxExpiry := time.Now().Add(cfg.BanTTL + time.Minute)
	if entry.ExpiresAt.After(maxExpiry) {
		t.Errorf("ExpiresAt %v should be capped to BAN_TTL, got %v", entry.ExpiresAt, cfg.BanTTL)
	}
}

func TestJobHandler_BanTTLCapNotAppliedWhenShort(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites: []string{"default"},
		BanTTL:     24 * time.Hour,
	}
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	shortExpiry := time.Now().Add(cfg.BanTTL / 2) // 12 hours
	job := SyncJob{
		Action:    "ban",
		IP:        "10.0.0.3",
		ExpiresAt: shortExpiry,
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	bans, _ := store.BanList()
	entry := bans["10.0.0.3"]
	// ExpiresAt should NOT be extended; should be close to shortExpiry
	// Allow 5 seconds tolerance
	if entry.ExpiresAt.After(shortExpiry.Add(5 * time.Second)) {
		t.Errorf("ExpiresAt %v should not be extended beyond shortExpiry %v", entry.ExpiresAt, shortExpiry)
	}
}

// TestHandler_ScenarioZoneOverride_Applied verifies that when job.Scenario matches
// a key in ZonePairsScenarioMap, the handler calls ApplyBanWithZones with the
// override zone pairs rather than ApplyBan.
func TestHandler_ScenarioZoneOverride_Applied(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	override := []config.ZonePair{{Src: "WAN", Dst: "LAN"}}
	cfg := &config.Config{
		UnifiSites: []string{"default"},
		BanTTL:     24 * time.Hour,
		ZonePairsScenarioMap: map[string][]config.ZonePair{
			"ssh-bf": override,
		},
	}
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "10.10.0.1",
		ExpiresAt: time.Now().Add(time.Hour),
		Scenario:  "crowdsec/ssh-bf",
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fwMgr.applyBanCalls != 1 {
		t.Errorf("expected 1 ban call, got %d", fwMgr.applyBanCalls)
	}
	if len(fwMgr.lastZonePairs) != 1 || fwMgr.lastZonePairs[0].Src != "WAN" {
		t.Errorf("expected override zone pairs {WAN->LAN}, got %v", fwMgr.lastZonePairs)
	}
}

// TestHandler_ScenarioZoneOverride_NoMatch verifies that when job.Scenario does
// not match any key in ZonePairsScenarioMap, ApplyBan is called (no override).
func TestHandler_ScenarioZoneOverride_NoMatch(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites: []string{"default"},
		BanTTL:     24 * time.Hour,
		ZonePairsScenarioMap: map[string][]config.ZonePair{
			"ssh-bf": {{Src: "WAN", Dst: "LAN"}},
		},
	}
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "10.10.0.2",
		ExpiresAt: time.Now().Add(time.Hour),
		Scenario:  "crowdsec/http-probing",
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fwMgr.applyBanCalls != 1 {
		t.Errorf("expected 1 ban call, got %d", fwMgr.applyBanCalls)
	}
	// lastZonePairs should be nil — ApplyBan was called, not ApplyBanWithZones.
	if fwMgr.lastZonePairs != nil {
		t.Errorf("expected no zone pair override, got %v", fwMgr.lastZonePairs)
	}
}

// TestHandler_ScenarioZoneOverride_EmptyMap verifies that a nil
// ZonePairsScenarioMap results in normal ApplyBan behavior (no override).
func TestHandler_ScenarioZoneOverride_EmptyMap(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites:           []string{"default"},
		BanTTL:               24 * time.Hour,
		ZonePairsScenarioMap: nil,
	}
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())
	job := SyncJob{
		Action:    "ban",
		IP:        "10.10.0.3",
		ExpiresAt: time.Now().Add(time.Hour),
		Scenario:  "crowdsec/ssh-bf",
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fwMgr.applyBanCalls != 1 {
		t.Errorf("expected 1 ban call, got %d", fwMgr.applyBanCalls)
	}
	if fwMgr.lastZonePairs != nil {
		t.Errorf("expected no zone pair override for nil map, got %v", fwMgr.lastZonePairs)
	}
}

// TestJobHandler_DryRunNoBboltWrites verifies that in DRY_RUN mode, the handler
// does not write bans to bbolt (store.BanRecord/BanDelete are skipped).
func TestJobHandler_DryRunNoBboltWrites(t *testing.T) {
	store := testutil.NewMockStore()
	ctrl := testutil.NewMockController()
	cfg := &config.Config{
		UnifiSites: []string{"default"},
		BanTTL:     24 * time.Hour,
		DryRun:     true,
	}
	fwMgr := &mockFirewallManager{}

	handler := makeJobHandler(ctrl, store, fwMgr, cfg, nopRecorder{}, zerolog.Nop())

	// Execute a ban job in dry run
	job := SyncJob{
		Action:    "ban",
		IP:        "203.0.113.100",
		IPv6:      false,
		ExpiresAt: time.Now().Add(24 * time.Hour),
	}
	if err := handler(context.Background(), job); err != nil {
		t.Fatalf("handler in dry run: %v", err)
	}

	// Verify the IP is NOT in bbolt (DRY_RUN skips BanRecord)
	exists, err := store.BanExists("203.0.113.100")
	if err != nil {
		t.Fatalf("BanExists: %v", err)
	}
	if exists {
		t.Error("DRY_RUN should not write to bbolt; ban should not exist")
	}

	// Also test a delete job (unban)
	// First, manually put something in bbolt to simulate a pre-existing ban
	if err := store.BanRecord("198.51.100.1", time.Now().Add(time.Hour), false); err != nil {
		t.Fatalf("BanRecord setup: %v", err)
	}

	deleteJob := SyncJob{
		Action: "delete",
		IP:     "198.51.100.1",
		IPv6:   false,
	}
	if err := handler(context.Background(), deleteJob); err != nil {
		t.Fatalf("delete handler in dry run: %v", err)
	}

	// Verify the IP is still in bbolt (DRY_RUN skips BanDelete)
	exists, err = store.BanExists("198.51.100.1")
	if err != nil {
		t.Fatalf("BanExists after delete attempt: %v", err)
	}
	if !exists {
		t.Error("DRY_RUN should not delete from bbolt; ban should still exist")
	}
}
