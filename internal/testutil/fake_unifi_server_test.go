package testutil_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
	"github.com/rs/zerolog"
)

// newFakeClient creates a real controller.Controller pointed at the fake server.
func newFakeClient(t *testing.T, s *testutil.FakeUnifiServer) controller.Controller {
	t.Helper()
	cfg := controller.ClientConfig{
		BaseURL:   s.URL(),
		APIKey:    s.APIKey(),
		VerifyTLS: false,
		Timeout:   5 * time.Second,
	}
	c, err := controller.NewClient(context.Background(), cfg, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

// newFakeClientWithAuth creates a controller using username/password auth.
func newFakeClientWithAuth(t *testing.T, s *testutil.FakeUnifiServer, username, password string) controller.Controller {
	t.Helper()
	cfg := controller.ClientConfig{
		BaseURL:   s.URL(),
		Username:  username,
		Password:  password,
		VerifyTLS: false,
		Timeout:   5 * time.Second,
	}
	c, err := controller.NewClient(context.Background(), cfg, zerolog.Nop())
	if err != nil {
		t.Fatalf("NewClient with auth: %v", err)
	}
	return c
}

// TestFakeServer_GroupCRUDRoundtrip verifies full Create→List→Update→Delete
// cycle for firewall groups via the real client.
func TestFakeServer_GroupCRUDRoundtrip(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)
	ctx := context.Background()

	// Create
	g, err := c.CreateFirewallGroup(ctx, "default", controller.FirewallGroup{
		Name:         "test-group",
		GroupType:    "address-group",
		GroupMembers: []string{"1.2.3.4"},
	})
	if err != nil {
		t.Fatalf("CreateFirewallGroup: %v", err)
	}
	if g.ID == "" {
		t.Fatal("expected non-empty ID after create")
	}

	// List
	groups, err := c.ListFirewallGroups(ctx, "default")
	if err != nil {
		t.Fatalf("ListFirewallGroups: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("expected 1 group, got %d", len(groups))
	}

	// Update
	g.Name = "updated-group"
	if err := c.UpdateFirewallGroup(ctx, "default", g); err != nil {
		t.Fatalf("UpdateFirewallGroup: %v", err)
	}
	groups, _ = c.ListFirewallGroups(ctx, "default")
	if groups[0].Name != "updated-group" {
		t.Errorf("expected updated name, got %q", groups[0].Name)
	}

	// Delete
	if err := c.DeleteFirewallGroup(ctx, "default", g.ID); err != nil {
		t.Fatalf("DeleteFirewallGroup: %v", err)
	}
	groups, _ = c.ListFirewallGroups(ctx, "default")
	if len(groups) != 0 {
		t.Errorf("expected 0 groups after delete, got %d", len(groups))
	}
}

// TestFakeServer_RuleCRUDRoundtrip verifies full CRUD for firewall rules.
func TestFakeServer_RuleCRUDRoundtrip(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)
	ctx := context.Background()

	r, err := c.CreateFirewallRule(ctx, "default", controller.FirewallRule{
		Name:    "block-bad",
		Action:  "drop",
		Ruleset: "WAN_IN",
		Enabled: true,
	})
	if err != nil {
		t.Fatalf("CreateFirewallRule: %v", err)
	}
	if r.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	rules, err := c.ListFirewallRules(ctx, "default")
	if err != nil {
		t.Fatalf("ListFirewallRules: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}

	r.Enabled = false
	if err := c.UpdateFirewallRule(ctx, "default", r); err != nil {
		t.Fatalf("UpdateFirewallRule: %v", err)
	}

	if err := c.DeleteFirewallRule(ctx, "default", r.ID); err != nil {
		t.Fatalf("DeleteFirewallRule: %v", err)
	}
	rules, _ = c.ListFirewallRules(ctx, "default")
	if len(rules) != 0 {
		t.Errorf("expected 0 rules after delete, got %d", len(rules))
	}
}

// TestFakeServer_TMLCRUDRoundtrip verifies Create→List→Update→Delete for TMLs.
func TestFakeServer_TMLCRUDRoundtrip(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	c := newFakeClient(t, s)
	ctx := context.Background()

	tml, err := c.CreateTrafficMatchingList(ctx, "default", controller.TrafficMatchingList{
		Type: "IPV4_ADDRESSES",
		Name: "block-list",
	})
	if err != nil {
		t.Fatalf("CreateTrafficMatchingList: %v", err)
	}
	if tml.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	tmls, err := c.ListTrafficMatchingLists(ctx, "default")
	if err != nil {
		t.Fatalf("ListTrafficMatchingLists: %v", err)
	}
	if len(tmls) != 1 {
		t.Fatalf("expected 1 TML, got %d", len(tmls))
	}

	// Update: add items
	tml.Items = []controller.TrafficMatchingListItem{
		{Type: "IP_ADDRESS", Value: "10.0.0.1"},
	}
	if err := c.UpdateTrafficMatchingList(ctx, "default", tml); err != nil {
		t.Fatalf("UpdateTrafficMatchingList: %v", err)
	}

	tmls, _ = c.ListTrafficMatchingLists(ctx, "default")
	if len(tmls[0].Items) != 1 {
		t.Errorf("expected 1 item after update, got %d", len(tmls[0].Items))
	}

	if err := c.DeleteTrafficMatchingList(ctx, "default", tml.ID); err != nil {
		t.Fatalf("DeleteTrafficMatchingList: %v", err)
	}
	tmls, _ = c.ListTrafficMatchingLists(ctx, "default")
	if len(tmls) != 0 {
		t.Errorf("expected 0 TMLs after delete, got %d", len(tmls))
	}
}

// TestFakeServer_TMLPutBodyExcludesID is the primary regression guard.
// The fake server rejects PUT body containing "id"; the client must NOT include it.
func TestFakeServer_TMLPutBodyExcludesID(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	c := newFakeClient(t, s)
	ctx := context.Background()

	tml, err := c.CreateTrafficMatchingList(ctx, "default", controller.TrafficMatchingList{
		Type: "IPV4_ADDRESSES",
		Name: "regression-guard",
	})
	if err != nil {
		t.Fatalf("create TML: %v", err)
	}

	tml.Name = "regression-guard-updated"
	if err := c.UpdateTrafficMatchingList(ctx, "default", tml); err != nil {
		t.Fatalf("UpdateTrafficMatchingList returned error (did client include 'id' in PUT body?): %v", err)
	}
}

// TestFakeServer_PolicyCRUDRoundtrip verifies full ZonePolicy lifecycle.
func TestFakeServer_PolicyCRUDRoundtrip(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	c := newFakeClient(t, s)
	ctx := context.Background()

	pol, err := c.CreateZonePolicy(ctx, "default", controller.ZonePolicy{
		Name:    "test-policy",
		Enabled: true,
		Action:  "BLOCK",
		SrcZone: "zone-ext",
		DstZone: "zone-int",
	})
	if err != nil {
		t.Fatalf("CreateZonePolicy: %v", err)
	}
	if pol.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	pols, err := c.ListZonePolicies(ctx, "default")
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}
	if len(pols) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(pols))
	}

	pol.Enabled = false
	if err := c.UpdateZonePolicy(ctx, "default", pol); err != nil {
		t.Fatalf("UpdateZonePolicy: %v", err)
	}

	if err := c.DeleteZonePolicy(ctx, "default", pol.ID); err != nil {
		t.Fatalf("DeleteZonePolicy: %v", err)
	}
	pols, _ = c.ListZonePolicies(ctx, "default")
	if len(pols) != 0 {
		t.Errorf("expected 0 policies after delete, got %d", len(pols))
	}
}

// TestFakeServer_PolicyPutBodyExcludesID ensures policy PUT does not include "id".
func TestFakeServer_PolicyPutBodyExcludesID(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	c := newFakeClient(t, s)
	ctx := context.Background()

	pol, err := c.CreateZonePolicy(ctx, "default", controller.ZonePolicy{
		Name:    "policy-id-test",
		Enabled: true,
		Action:  "ALLOW",
		SrcZone: "zone-a",
		DstZone: "zone-b",
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}
	pol.Name = "policy-id-test-updated"
	if err := c.UpdateZonePolicy(ctx, "default", pol); err != nil {
		t.Fatalf("UpdateZonePolicy returned error (did client include 'id' in PUT body?): %v", err)
	}
}

// TestFakeServer_PolicyOrdering verifies GetPolicyOrdering/SetPolicyOrdering roundtrip.
func TestFakeServer_PolicyOrdering(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	c := newFakeClient(t, s)
	ctx := context.Background()

	want := controller.PolicyOrdering{
		BeforeSystemDefined: []string{"pol-1", "pol-2"},
		AfterSystemDefined:  []string{"pol-3"},
	}
	if err := c.SetPolicyOrdering(ctx, "default", "zone-src", "zone-dst", want); err != nil {
		t.Fatalf("SetPolicyOrdering: %v", err)
	}

	got, err := c.GetPolicyOrdering(ctx, "default", "zone-src", "zone-dst")
	if err != nil {
		t.Fatalf("GetPolicyOrdering: %v", err)
	}
	if len(got.BeforeSystemDefined) != 2 || got.BeforeSystemDefined[0] != "pol-1" {
		t.Errorf("BeforeSystemDefined mismatch: %v", got.BeforeSystemDefined)
	}
	if len(got.AfterSystemDefined) != 1 || got.AfterSystemDefined[0] != "pol-3" {
		t.Errorf("AfterSystemDefined mismatch: %v", got.AfterSystemDefined)
	}
}

// TestFakeServer_DiscoverSites verifies DiscoverSites returns pre-populated sites.
func TestFakeServer_DiscoverSites(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("site-a", "uuid-a", "Site A")
	s.AddSite("site-b", "uuid-b", "Site B")
	c := newFakeClient(t, s)

	sites, err := c.DiscoverSites(context.Background())
	if err != nil {
		t.Fatalf("DiscoverSites: %v", err)
	}
	if len(sites) != 2 {
		t.Fatalf("expected 2 sites, got %d: %v", len(sites), sites)
	}
}

// TestFakeServer_DiscoverZones verifies DiscoverZones returns pre-populated zones.
func TestFakeServer_DiscoverZones(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	s.AddZone("site-uuid-1", "zone-ext-id", "External")
	s.AddZone("site-uuid-1", "zone-int-id", "Internal")
	c := newFakeClient(t, s)

	zones, err := c.DiscoverZones(context.Background(), "default")
	if err != nil {
		t.Fatalf("DiscoverZones: %v", err)
	}
	if len(zones) != 2 {
		t.Fatalf("expected 2 zones, got %d", len(zones))
	}
}

// TestFakeServer_Pagination pre-populates 250 TMLs and verifies ListTrafficMatchingLists
// fetches all via pagination (client uses pages of 200).
func TestFakeServer_Pagination(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")

	for i := 0; i < 250; i++ {
		s.AddTML("site-uuid-1", fmt.Sprintf("tml-%d", i), "IPV4_ADDRESSES",
			fmt.Sprintf("list-%d", i), nil)
	}

	c := newFakeClient(t, s)
	tmls, err := c.ListTrafficMatchingLists(context.Background(), "default")
	if err != nil {
		t.Fatalf("ListTrafficMatchingLists: %v", err)
	}
	if len(tmls) != 250 {
		t.Errorf("expected 250 TMLs via pagination, got %d", len(tmls))
	}
}

// TestFakeServer_AuthAPIKey verifies NewClient with API key can call endpoints.
func TestFakeServer_AuthAPIKey(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with API key: %v", err)
	}
}

// TestFakeServer_AuthCookieCSRF verifies NewClient with username/password
// performs login and can use the API.
func TestFakeServer_AuthCookieCSRF(t *testing.T) {
	s := testutil.NewFakeUnifiServerWithAuth("admin", "secret")
	defer s.Close()
	c := newFakeClientWithAuth(t, s, "admin", "secret")
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping with cookie auth: %v", err)
	}
}

// TestFakeServer_AuthCookieCSRF_WrongPassword verifies that wrong credentials fail.
func TestFakeServer_AuthCookieCSRF_WrongPassword(t *testing.T) {
	s := testutil.NewFakeUnifiServerWithAuth("admin", "secret")
	defer s.Close()
	cfg := controller.ClientConfig{
		BaseURL:   s.URL(),
		Username:  "admin",
		Password:  "wrong",
		VerifyTLS: false,
		Timeout:   5 * time.Second,
	}
	_, err := controller.NewClient(context.Background(), cfg, zerolog.Nop())
	if err == nil {
		t.Fatal("expected error on wrong password, got nil")
	}
}

// TestFakeServer_ReauthOn401 injects a 401 fault; the client re-auths (no-op
// for API key) and the retry succeeds because the fault is consumed.
func TestFakeServer_ReauthOn401(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)

	// Inject a 401 on the next GET /api/self
	s.InjectFault(http.MethodGet, "/api/self", http.StatusUnauthorized)

	// Ping calls GET /api/self; the first attempt gets 401, client re-auths,
	// second attempt succeeds (fault consumed).
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping after re-auth: %v", err)
	}
}

// TestFakeServer_RateLimit injects a 429 and verifies ErrRateLimit is returned.
func TestFakeServer_RateLimit(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)

	s.InjectFault(http.MethodGet, "/api/self", http.StatusTooManyRequests)

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected ErrRateLimit, got nil")
	}
	var rl *controller.ErrRateLimit
	if !errors.As(err, &rl) {
		t.Fatalf("expected *ErrRateLimit, got %T: %v", err, err)
	}
}

// TestFakeServer_NotFound verifies that deleting a nonexistent resource returns nil
// (client ignores 404 on DELETE).
func TestFakeServer_NotFound(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)

	if err := c.DeleteFirewallGroup(context.Background(), "default", "nonexistent-id"); err != nil {
		t.Fatalf("expected nil (ignoreNotFound), got: %v", err)
	}
}

// TestFakeServer_MultiSite verifies two sites have independent TML state.
func TestFakeServer_MultiSite(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("site-a", "uuid-a", "Site A")
	s.AddSite("site-b", "uuid-b", "Site B")
	s.AddTML("uuid-a", "tml-a-1", "IPV4_ADDRESSES", "list-a", nil)
	s.AddTML("uuid-b", "tml-b-1", "IPV4_ADDRESSES", "list-b-1", nil)
	s.AddTML("uuid-b", "tml-b-2", "IPV4_ADDRESSES", "list-b-2", nil)
	c := newFakeClient(t, s)
	ctx := context.Background()

	aList, err := c.ListTrafficMatchingLists(ctx, "site-a")
	if err != nil {
		t.Fatalf("ListTrafficMatchingLists site-a: %v", err)
	}
	bList, err := c.ListTrafficMatchingLists(ctx, "site-b")
	if err != nil {
		t.Fatalf("ListTrafficMatchingLists site-b: %v", err)
	}

	if len(aList) != 1 {
		t.Errorf("site-a: expected 1 TML, got %d", len(aList))
	}
	if len(bList) != 2 {
		t.Errorf("site-b: expected 2 TMLs, got %d", len(bList))
	}
}

// TestFakeServer_Ping verifies Ping succeeds.
func TestFakeServer_Ping(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("Ping: %v", err)
	}
}

// TestFakeServer_Reset verifies that Reset clears all data state while
// preserving auth credentials.
func TestFakeServer_Reset(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	ctx := context.Background()

	// Pre-populate data.
	s.AddSite("default", "site-uuid-1", "Default")
	s.AddZone("site-uuid-1", "zone-1", "External")
	s.AddTML("site-uuid-1", "tml-1", "IPV4_ADDRESSES", "list-1", nil)
	s.AddGroup("default", "grp-1", "g1", "address-group", nil)
	s.InjectFault(http.MethodGet, "/api/self", http.StatusInternalServerError)

	c := newFakeClient(t, s)
	// Touch the server so requests are captured.
	_ = c.Ping(ctx)

	s.Reset()

	// Requests slice should be empty immediately after Reset.
	if reqs := s.Requests(); len(reqs) != 0 {
		t.Errorf("expected 0 requests after Reset, got %d", len(reqs))
	}

	// All list endpoints should now return empty.
	sites, err := c.DiscoverSites(ctx)
	if err != nil {
		t.Fatalf("DiscoverSites after Reset: %v", err)
	}
	if len(sites) != 0 {
		t.Errorf("expected 0 sites after Reset, got %d", len(sites))
	}

	groups, err := c.ListFirewallGroups(ctx, "default")
	if err != nil {
		t.Fatalf("ListFirewallGroups after Reset: %v", err)
	}
	if len(groups) != 0 {
		t.Errorf("expected 0 groups after Reset, got %d", len(groups))
	}

	// Fault injected before Reset should not trigger.
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("Ping after Reset (fault should be cleared): %v", err)
	}
}

// TestFakeServer_RateLimitInject verifies InjectRateLimit returns ErrRateLimit
// with the exact Retry-After value.
func TestFakeServer_RateLimitInject(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	c := newFakeClient(t, s)

	s.InjectRateLimit(http.MethodGet, "/api/self", 30)

	err := c.Ping(context.Background())
	if err == nil {
		t.Fatal("expected ErrRateLimit, got nil")
	}
	var rl *controller.ErrRateLimit
	if !errors.As(err, &rl) {
		t.Fatalf("expected *ErrRateLimit, got %T: %v", err, err)
	}
	want := 30 * time.Second
	if rl.RetryAfter != want {
		t.Errorf("RetryAfter = %v, want %v", rl.RetryAfter, want)
	}
}

// TestFakeServer_OrderingSetup verifies SetOrdering pre-populates ordering
// that GetPolicyOrdering returns correctly.
func TestFakeServer_OrderingSetup(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	c := newFakeClient(t, s)
	ctx := context.Background()

	want := controller.PolicyOrdering{
		BeforeSystemDefined: []string{"pol-a", "pol-b"},
		AfterSystemDefined:  []string{"pol-c"},
	}
	s.SetOrdering("site-uuid-1", "zone-src", "zone-dst", want)

	got, err := c.GetPolicyOrdering(ctx, "default", "zone-src", "zone-dst")
	if err != nil {
		t.Fatalf("GetPolicyOrdering: %v", err)
	}
	if len(got.BeforeSystemDefined) != 2 ||
		got.BeforeSystemDefined[0] != "pol-a" ||
		got.BeforeSystemDefined[1] != "pol-b" {
		t.Errorf("BeforeSystemDefined = %v, want %v", got.BeforeSystemDefined, want.BeforeSystemDefined)
	}
	if len(got.AfterSystemDefined) != 1 || got.AfterSystemDefined[0] != "pol-c" {
		t.Errorf("AfterSystemDefined = %v, want %v", got.AfterSystemDefined, want.AfterSystemDefined)
	}
}

// TestFakeServer_CSRFTokenRotation verifies that each response carries a fresh
// X-Csrf-Token value (LastCSRFToken changes between calls).
func TestFakeServer_CSRFTokenRotation(t *testing.T) {
	s := testutil.NewFakeUnifiServerWithAuth("admin", "secret")
	defer s.Close()
	c := newFakeClientWithAuth(t, s, "admin", "secret")
	ctx := context.Background()

	// First Ping: records a CSRF token.
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("first Ping: %v", err)
	}
	first := s.LastCSRFToken()

	// Second Ping: server should have rotated to a different token.
	if err := c.Ping(ctx); err != nil {
		t.Fatalf("second Ping: %v", err)
	}
	second := s.LastCSRFToken()

	if first == second {
		t.Errorf("CSRF token did not rotate: both calls returned %q", first)
	}
}

// TestFakeServer_PolicyWithTrafficFilter verifies that a ZonePolicy created
// with a TrafficMatchingListID survives a full Create→List round-trip
// (validates Phase B fakePolicy TrafficFilter preservation).
func TestFakeServer_PolicyWithTrafficFilter(t *testing.T) {
	s := testutil.NewFakeUnifiServer()
	defer s.Close()
	s.AddSite("default", "site-uuid-1", "Default")
	c := newFakeClient(t, s)
	ctx := context.Background()

	const tmlID = "tml-abc-123"
	pol, err := c.CreateZonePolicy(ctx, "default", controller.ZonePolicy{
		Name:                   "tml-policy",
		Enabled:                true,
		Action:                 "BLOCK",
		SrcZone:                "zone-ext",
		DstZone:                "zone-int",
		TrafficMatchingListIDs: []string{tmlID},
	})
	if err != nil {
		t.Fatalf("CreateZonePolicy: %v", err)
	}
	if pol.ID == "" {
		t.Fatal("expected non-empty ID")
	}

	pols, err := c.ListZonePolicies(ctx, "default")
	if err != nil {
		t.Fatalf("ListZonePolicies: %v", err)
	}
	if len(pols) != 1 {
		t.Fatalf("expected 1 policy, got %d", len(pols))
	}
	got := pols[0]
	if len(got.TrafficMatchingListIDs) != 1 || got.TrafficMatchingListIDs[0] != tmlID {
		t.Errorf("TrafficMatchingListIDs = %v, want [%s]", got.TrafficMatchingListIDs, tmlID)
	}
}
