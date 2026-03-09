package testutil_test

import (
	"context"
	"errors"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// TestMockController_Groups covers the full CRUD cycle for firewall groups.
func TestMockController_Groups(t *testing.T) {
	ctx := context.Background()
	const site = "default"

	t.Run("list empty by default", func(t *testing.T) {
		m := testutil.NewMockController()
		groups, err := m.ListFirewallGroups(ctx, site)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(groups) != 0 {
			t.Fatalf("expected empty slice, got %d groups", len(groups))
		}
	})

	t.Run("preset groups are returned", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetGroups(site, []controller.FirewallGroup{
			{ID: "g1", Name: "blocklist", GroupType: "address-group"},
		})
		groups, err := m.ListFirewallGroups(ctx, site)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(groups) != 1 || groups[0].ID != "g1" {
			t.Fatalf("unexpected groups: %+v", groups)
		}
	})

	t.Run("list returns a copy not an alias", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetGroups(site, []controller.FirewallGroup{{ID: "g1"}})
		first, _ := m.ListFirewallGroups(ctx, site)
		first[0].ID = "mutated"
		second, _ := m.ListFirewallGroups(ctx, site)
		if second[0].ID != "g1" {
			t.Fatal("list returned an alias of the internal slice")
		}
	})

	t.Run("create assigns non-empty ID", func(t *testing.T) {
		m := testutil.NewMockController()
		g, err := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{Name: "new"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if g.ID == "" {
			t.Fatal("expected a non-empty ID after create")
		}
		groups, _ := m.ListFirewallGroups(ctx, site)
		if len(groups) != 1 || groups[0].ID != g.ID {
			t.Fatalf("created group not found in list: %+v", groups)
		}
	})

	t.Run("create IDs are unique across calls", func(t *testing.T) {
		m := testutil.NewMockController()
		g1, _ := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{})
		g2, _ := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{})
		if g1.ID == g2.ID {
			t.Fatalf("duplicate IDs assigned: %q", g1.ID)
		}
	})

	t.Run("update modifies in-place", func(t *testing.T) {
		m := testutil.NewMockController()
		g, _ := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{Name: "original"})
		g.Name = "updated"
		if err := m.UpdateFirewallGroup(ctx, site, g); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		groups, _ := m.ListFirewallGroups(ctx, site)
		if groups[0].Name != "updated" {
			t.Fatalf("expected updated name, got %q", groups[0].Name)
		}
	})

	t.Run("update unknown ID is a no-op", func(t *testing.T) {
		m := testutil.NewMockController()
		err := m.UpdateFirewallGroup(ctx, site, controller.FirewallGroup{ID: "nonexistent"})
		if err != nil {
			t.Fatalf("expected no error for unknown ID, got: %v", err)
		}
	})

	t.Run("delete removes by ID", func(t *testing.T) {
		m := testutil.NewMockController()
		g, _ := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{Name: "todelete"})
		if err := m.DeleteFirewallGroup(ctx, site, g.ID); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		groups, _ := m.ListFirewallGroups(ctx, site)
		if len(groups) != 0 {
			t.Fatalf("expected empty after delete, got %d groups", len(groups))
		}
	})

	t.Run("delete leaves other groups intact", func(t *testing.T) {
		m := testutil.NewMockController()
		g1, _ := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{Name: "keep"})
		g2, _ := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{Name: "remove"})
		_ = m.DeleteFirewallGroup(ctx, site, g2.ID)
		groups, _ := m.ListFirewallGroups(ctx, site)
		if len(groups) != 1 || groups[0].ID != g1.ID {
			t.Fatalf("unexpected groups after delete: %+v", groups)
		}
	})
}

// TestMockController_Rules covers the full CRUD cycle for firewall rules.
func TestMockController_Rules(t *testing.T) {
	ctx := context.Background()
	const site = "default"

	t.Run("preset rules are returned", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetRules(site, []controller.FirewallRule{{ID: "r1", Name: "block"}})
		rules, err := m.ListFirewallRules(ctx, site)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 || rules[0].ID != "r1" {
			t.Fatalf("unexpected rules: %+v", rules)
		}
	})

	t.Run("create assigns ID", func(t *testing.T) {
		m := testutil.NewMockController()
		r, err := m.CreateFirewallRule(ctx, site, controller.FirewallRule{Name: "new"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if r.ID == "" {
			t.Fatal("expected non-empty ID")
		}
	})

	t.Run("update changes field", func(t *testing.T) {
		m := testutil.NewMockController()
		r, _ := m.CreateFirewallRule(ctx, site, controller.FirewallRule{Name: "rule"})
		r.Enabled = true
		if err := m.UpdateFirewallRule(ctx, site, r); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rules, _ := m.ListFirewallRules(ctx, site)
		if !rules[0].Enabled {
			t.Fatal("expected Enabled=true after update")
		}
	})

	t.Run("delete removes rule", func(t *testing.T) {
		m := testutil.NewMockController()
		r, _ := m.CreateFirewallRule(ctx, site, controller.FirewallRule{})
		_ = m.DeleteFirewallRule(ctx, site, r.ID)
		rules, _ := m.ListFirewallRules(ctx, site)
		if len(rules) != 0 {
			t.Fatalf("expected 0 rules after delete, got %d", len(rules))
		}
	})
}

// TestMockController_ZonePolicies covers the full CRUD cycle for zone policies.
func TestMockController_ZonePolicies(t *testing.T) {
	ctx := context.Background()
	const site = "default"

	t.Run("preset policies are returned", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetPolicies(site, []controller.ZonePolicy{{ID: "p1", Name: "pol"}})
		pols, err := m.ListZonePolicies(ctx, site)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(pols) != 1 || pols[0].ID != "p1" {
			t.Fatalf("unexpected policies: %+v", pols)
		}
	})

	t.Run("create update delete", func(t *testing.T) {
		m := testutil.NewMockController()
		p, err := m.CreateZonePolicy(ctx, site, controller.ZonePolicy{Name: "pol"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		p.Enabled = true
		if err := m.UpdateZonePolicy(ctx, site, p); err != nil {
			t.Fatalf("update: %v", err)
		}
		pols, _ := m.ListZonePolicies(ctx, site)
		if len(pols) != 1 || !pols[0].Enabled {
			t.Fatalf("unexpected policies after update: %+v", pols)
		}
		if err := m.DeleteZonePolicy(ctx, site, p.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		pols, _ = m.ListZonePolicies(ctx, site)
		if len(pols) != 0 {
			t.Fatalf("expected 0 policies after delete, got %d", len(pols))
		}
	})
}

// TestMockController_GetZoneID covers zone ID lookup behavior.
func TestMockController_GetZoneID(t *testing.T) {
	ctx := context.Background()
	const site = "default"

	t.Run("zone name resolves to ID", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetZones(site, []controller.Zone{{ID: "z1", Name: "WAN"}})
		id, err := m.GetZoneID(ctx, site, "WAN")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "z1" {
			t.Fatalf("expected z1, got %q", id)
		}
	})

	t.Run("fallback returns input when unknown", func(t *testing.T) {
		m := testutil.NewMockController()
		id, err := m.GetZoneID(ctx, "other", "67a8cc9efe6c6350dfa4dcc7")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "67a8cc9efe6c6350dfa4dcc7" {
			t.Fatalf("expected passthrough ID, got %q", id)
		}
	})
}

// TestMockController_HasFeature covers feature detection.
func TestMockController_HasFeature(t *testing.T) {
	ctx := context.Background()

	t.Run("unknown feature returns false", func(t *testing.T) {
		m := testutil.NewMockController()
		ok, err := m.HasFeature(ctx, "default", "zone-based-firewall")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if ok {
			t.Fatal("expected false for unknown feature")
		}
	})

	t.Run("preset true is returned", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetHasFeature("default", "zone-based-firewall", true)
		ok, err := m.HasFeature(ctx, "default", "zone-based-firewall")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !ok {
			t.Fatal("expected true for preset feature")
		}
	})

	t.Run("preset false is returned", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetHasFeature("default", "zone-based-firewall", false)
		ok, _ := m.HasFeature(ctx, "default", "zone-based-firewall")
		if ok {
			t.Fatal("expected false for preset false feature")
		}
	})

	t.Run("feature scoped to site", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetHasFeature("site-a", "feat", true)
		ok, _ := m.HasFeature(ctx, "site-b", "feat")
		if ok {
			t.Fatal("feature from site-a should not appear on site-b")
		}
	})
}

// TestMockController_ErrorInjection verifies that SetError returns the error
// once and clears it so subsequent calls succeed.
func TestMockController_ErrorInjection(t *testing.T) {
	ctx := context.Background()
	const site = "default"
	sentinel := errors.New("injected")

	cases := []struct {
		method string
		call   func(m *testutil.MockController) error
	}{
		{
			"ListFirewallGroups",
			func(m *testutil.MockController) error { _, err := m.ListFirewallGroups(ctx, site); return err },
		},
		{
			"CreateFirewallGroup",
			func(m *testutil.MockController) error {
				_, err := m.CreateFirewallGroup(ctx, site, controller.FirewallGroup{})
				return err
			},
		},
		{
			"UpdateFirewallGroup",
			func(m *testutil.MockController) error {
				return m.UpdateFirewallGroup(ctx, site, controller.FirewallGroup{})
			},
		},
		{
			"DeleteFirewallGroup",
			func(m *testutil.MockController) error { return m.DeleteFirewallGroup(ctx, site, "id") },
		},
		{
			"ListFirewallRules",
			func(m *testutil.MockController) error { _, err := m.ListFirewallRules(ctx, site); return err },
		},
		{
			"CreateFirewallRule",
			func(m *testutil.MockController) error {
				_, err := m.CreateFirewallRule(ctx, site, controller.FirewallRule{})
				return err
			},
		},
		{
			"UpdateFirewallRule",
			func(m *testutil.MockController) error {
				return m.UpdateFirewallRule(ctx, site, controller.FirewallRule{})
			},
		},
		{
			"DeleteFirewallRule",
			func(m *testutil.MockController) error { return m.DeleteFirewallRule(ctx, site, "id") },
		},
		{
			"ListZonePolicies",
			func(m *testutil.MockController) error { _, err := m.ListZonePolicies(ctx, site); return err },
		},
		{
			"CreateZonePolicy",
			func(m *testutil.MockController) error {
				_, err := m.CreateZonePolicy(ctx, site, controller.ZonePolicy{})
				return err
			},
		},
		{
			"UpdateZonePolicy",
			func(m *testutil.MockController) error {
				return m.UpdateZonePolicy(ctx, site, controller.ZonePolicy{})
			},
		},
		{
			"DeleteZonePolicy",
			func(m *testutil.MockController) error { return m.DeleteZonePolicy(ctx, site, "id") },
		},
		{
			"GetZoneID",
			func(m *testutil.MockController) error { _, err := m.GetZoneID(ctx, site, "zone"); return err },
		},
		{
			"HasFeature",
			func(m *testutil.MockController) error { _, err := m.HasFeature(ctx, site, "f"); return err },
		},
		{
			"Ping",
			func(m *testutil.MockController) error { return m.Ping(ctx) },
		},
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			m := testutil.NewMockController()
			m.SetError(tc.method, sentinel)

			// First call must return the injected error.
			if err := tc.call(m); !errors.Is(err, sentinel) {
				t.Fatalf("expected sentinel error, got: %v", err)
			}
			// Error is consumed; second call must succeed.
			if err := tc.call(m); err != nil {
				t.Fatalf("expected no error on second call, got: %v", err)
			}
		})
	}
}

// TestMockController_CallCounting verifies that the Calls counter increments
// correctly across multiple invocations.
func TestMockController_CallCounting(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockController()

	for i := 0; i < 4; i++ {
		_, _ = m.ListFirewallGroups(ctx, "default")
	}
	if n := m.Calls("ListFirewallGroups"); n != 4 {
		t.Fatalf("expected 4 calls, got %d", n)
	}

	// Verify an uncalled method returns 0.
	if n := m.Calls("DeleteFirewallGroup"); n != 0 {
		t.Fatalf("expected 0 for uncalled method, got %d", n)
	}
}

// TestMockController_PingAndClose verifies session-level methods.
func TestMockController_PingAndClose(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockController()

	if err := m.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if m.Calls("Ping") != 1 {
		t.Fatalf("expected 1 Ping call, got %d", m.Calls("Ping"))
	}
	if m.Calls("Close") != 1 {
		t.Fatalf("expected 1 Close call, got %d", m.Calls("Close"))
	}
}

// TestMockController_MultiSite confirms that preset data is scoped to sites.
func TestMockController_MultiSite(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockController()

	m.SetGroups("site-a", []controller.FirewallGroup{{ID: "ga"}})
	m.SetGroups("site-b", []controller.FirewallGroup{{ID: "gb"}})

	a, _ := m.ListFirewallGroups(ctx, "site-a")
	b, _ := m.ListFirewallGroups(ctx, "site-b")

	if len(a) != 1 || a[0].ID != "ga" {
		t.Fatalf("unexpected site-a groups: %+v", a)
	}
	if len(b) != 1 || b[0].ID != "gb" {
		t.Fatalf("unexpected site-b groups: %+v", b)
	}
}

// TestMockController_TMLs covers the full TML CRUD cycle.
func TestMockController_TMLs(t *testing.T) {
	ctx := context.Background()
	const site = "default"

	t.Run("empty by default", func(t *testing.T) {
		m := testutil.NewMockController()
		tmls, err := m.ListTrafficMatchingLists(ctx, site)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tmls) != 0 {
			t.Fatalf("expected empty, got %d", len(tmls))
		}
	})

	t.Run("preset is returned", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetTMLs(site, []controller.TrafficMatchingList{{ID: "t1", Name: "list-1", Type: "IPV4_ADDRESSES"}})
		tmls, err := m.ListTrafficMatchingLists(ctx, site)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(tmls) != 1 || tmls[0].ID != "t1" {
			t.Fatalf("unexpected TMLs: %+v", tmls)
		}
	})

	t.Run("list returns a copy not an alias", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetTMLs(site, []controller.TrafficMatchingList{{ID: "t1"}})
		first, _ := m.ListTrafficMatchingLists(ctx, site)
		first[0].ID = "mutated"
		second, _ := m.ListTrafficMatchingLists(ctx, site)
		if second[0].ID != "t1" {
			t.Fatal("list returned alias of internal slice")
		}
	})

	t.Run("create assigns ID and persists", func(t *testing.T) {
		m := testutil.NewMockController()
		tml, err := m.CreateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{Name: "new-list"})
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if tml.ID == "" {
			t.Fatal("expected non-empty ID")
		}
		tmls, _ := m.ListTrafficMatchingLists(ctx, site)
		if len(tmls) != 1 || tmls[0].ID != tml.ID {
			t.Fatalf("created TML not found: %+v", tmls)
		}
	})

	t.Run("update modifies in-place", func(t *testing.T) {
		m := testutil.NewMockController()
		tml, _ := m.CreateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{Name: "orig"})
		tml.Name = "updated"
		if err := m.UpdateTrafficMatchingList(ctx, site, tml); err != nil {
			t.Fatalf("update: %v", err)
		}
		tmls, _ := m.ListTrafficMatchingLists(ctx, site)
		if tmls[0].Name != "updated" {
			t.Errorf("expected updated name, got %q", tmls[0].Name)
		}
	})

	t.Run("delete removes and leaves others intact", func(t *testing.T) {
		m := testutil.NewMockController()
		t1, _ := m.CreateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{Name: "keep"})
		t2, _ := m.CreateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{Name: "remove"})
		if err := m.DeleteTrafficMatchingList(ctx, site, t2.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		tmls, _ := m.ListTrafficMatchingLists(ctx, site)
		if len(tmls) != 1 || tmls[0].ID != t1.ID {
			t.Fatalf("unexpected TMLs after delete: %+v", tmls)
		}
	})
}

// TestMockController_PolicyOrdering covers SetOrdering/GetPolicyOrdering/SetPolicyOrdering.
func TestMockController_PolicyOrdering(t *testing.T) {
	ctx := context.Background()
	m := testutil.NewMockController()

	// SetOrdering (test helper) then GetPolicyOrdering.
	m.SetOrdering("default", "src-zone", "dst-zone", controller.PolicyOrdering{
		BeforeSystemDefined: []string{"pol-1"},
		AfterSystemDefined:  []string{"pol-2"},
	})
	ord, err := m.GetPolicyOrdering(ctx, "default", "src-zone", "dst-zone")
	if err != nil {
		t.Fatalf("GetPolicyOrdering: %v", err)
	}
	if len(ord.BeforeSystemDefined) != 1 || ord.BeforeSystemDefined[0] != "pol-1" {
		t.Errorf("BeforeSystemDefined = %v", ord.BeforeSystemDefined)
	}

	// SetPolicyOrdering via Controller interface then verify.
	if err := m.SetPolicyOrdering(ctx, "default", "src-zone", "dst-zone", controller.PolicyOrdering{
		BeforeSystemDefined: []string{"pol-x", "pol-y"},
	}); err != nil {
		t.Fatalf("SetPolicyOrdering: %v", err)
	}
	ord2, _ := m.GetPolicyOrdering(ctx, "default", "src-zone", "dst-zone")
	if len(ord2.BeforeSystemDefined) != 2 {
		t.Errorf("expected 2 before, got %v", ord2.BeforeSystemDefined)
	}

	// Different zone pair is independent.
	ord3, _ := m.GetPolicyOrdering(ctx, "default", "other-src", "other-dst")
	if len(ord3.BeforeSystemDefined) != 0 {
		t.Errorf("expected empty for different zone pair, got %v", ord3.BeforeSystemDefined)
	}
}

// TestMockController_DiscoverSites verifies DiscoverSites returns a copy.
func TestMockController_DiscoverSites(t *testing.T) {
	ctx := context.Background()

	t.Run("empty by default", func(t *testing.T) {
		m := testutil.NewMockController()
		sites, err := m.DiscoverSites(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(sites) != 0 {
			t.Fatalf("expected empty, got %v", sites)
		}
	})

	t.Run("returns preset sites as copy", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetDiscoveredSites([]string{"site-a", "site-b"})
		got, _ := m.DiscoverSites(ctx)
		if len(got) != 2 {
			t.Fatalf("expected 2 sites, got %v", got)
		}
		got[0] = "mutated"
		got2, _ := m.DiscoverSites(ctx)
		if got2[0] != "site-a" {
			t.Fatal("DiscoverSites returned alias of internal slice")
		}
	})
}

// TestMockController_DiscoverZones verifies DiscoverZones returns a copy.
func TestMockController_DiscoverZones(t *testing.T) {
	ctx := context.Background()

	t.Run("empty by default", func(t *testing.T) {
		m := testutil.NewMockController()
		zones, err := m.DiscoverZones(ctx, "default")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(zones) != 0 {
			t.Fatalf("expected empty, got %v", zones)
		}
	})

	t.Run("returns preset zones as copy", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetZones("default", []controller.Zone{{ID: "z1", Name: "WAN"}, {ID: "z2", Name: "LAN"}})
		zones, _ := m.DiscoverZones(ctx, "default")
		if len(zones) != 2 {
			t.Fatalf("expected 2 zones, got %d", len(zones))
		}
		zones[0].ID = "mutated"
		zones2, _ := m.DiscoverZones(ctx, "default")
		if zones2[0].ID != "z1" {
			t.Fatal("DiscoverZones returned alias")
		}
	})
}

// TestMockController_GetSiteID covers lookup, passthrough, and cross-site isolation.
func TestMockController_GetSiteID(t *testing.T) {
	ctx := context.Background()

	t.Run("preset lookup", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetSiteID("default", "uuid-default")
		id, err := m.GetSiteID(ctx, "default")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "uuid-default" {
			t.Errorf("expected uuid-default, got %q", id)
		}
	})

	t.Run("passthrough for unknown site", func(t *testing.T) {
		m := testutil.NewMockController()
		id, err := m.GetSiteID(ctx, "some-uuid-direct")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != "some-uuid-direct" {
			t.Errorf("expected passthrough, got %q", id)
		}
	})

	t.Run("cross-site isolation", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetSiteID("site-a", "uuid-a")
		id, _ := m.GetSiteID(ctx, "site-b")
		// site-b not preset, so it passthrough-returns "site-b" not "uuid-a"
		if id == "uuid-a" {
			t.Error("site-a mapping leaked to site-b")
		}
	})
}

// TestMockController_InvalidateZoneCache verifies the call counter increments.
func TestMockController_InvalidateZoneCache(t *testing.T) {
	m := testutil.NewMockController()
	m.InvalidateZoneCache("default")
	m.InvalidateZoneCache("default")
	if n := m.Calls("InvalidateZoneCache"); n != 2 {
		t.Errorf("expected 2 InvalidateZoneCache calls, got %d", n)
	}
}

// TestMockController_Concurrent hammers Create/List/Delete from 10 goroutines.
// Must not data-race under `go test -race`.
func TestMockController_Concurrent(t *testing.T) {
	m := testutil.NewMockController()
	ctx := context.Background()

	const workers = 10
	done := make(chan struct{}, workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer func() { done <- struct{}{} }()
			g, _ := m.CreateFirewallGroup(ctx, "default", controller.FirewallGroup{Name: "g"})
			_, _ = m.ListFirewallGroups(ctx, "default")
			_ = m.DeleteFirewallGroup(ctx, "default", g.ID)
		}()
	}
	for i := 0; i < workers; i++ {
		<-done
	}
}

// TestMockController_ErrorInjection_TML verifies SetError for TML and ordering methods.
func TestMockController_ErrorInjection_TML(t *testing.T) {
	ctx := context.Background()
	const site = "default"
	sentinel := errors.New("injected")

	cases := []struct {
		method string
		call   func(m *testutil.MockController) error
	}{
		{
			"ListTrafficMatchingLists",
			func(m *testutil.MockController) error {
				_, err := m.ListTrafficMatchingLists(ctx, site)
				return err
			},
		},
		{
			"CreateTrafficMatchingList",
			func(m *testutil.MockController) error {
				_, err := m.CreateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{})
				return err
			},
		},
		{
			"UpdateTrafficMatchingList",
			func(m *testutil.MockController) error {
				return m.UpdateTrafficMatchingList(ctx, site, controller.TrafficMatchingList{})
			},
		},
		{
			"DeleteTrafficMatchingList",
			func(m *testutil.MockController) error {
				return m.DeleteTrafficMatchingList(ctx, site, "id")
			},
		},
		{
			"GetPolicyOrdering",
			func(m *testutil.MockController) error {
				_, err := m.GetPolicyOrdering(ctx, site, "src", "dst")
				return err
			},
		},
		{
			"SetPolicyOrdering",
			func(m *testutil.MockController) error {
				return m.SetPolicyOrdering(ctx, site, "src", "dst", controller.PolicyOrdering{})
			},
		},
		{
			"DiscoverSites",
			func(m *testutil.MockController) error {
				_, err := m.DiscoverSites(ctx)
				return err
			},
		},
		{
			"DiscoverZones",
			func(m *testutil.MockController) error {
				_, err := m.DiscoverZones(ctx, site)
				return err
			},
		},
		{
			"GetSiteID",
			func(m *testutil.MockController) error {
				_, err := m.GetSiteID(ctx, site)
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			m := testutil.NewMockController()
			m.SetError(tc.method, sentinel)
			if err := tc.call(m); !errors.Is(err, sentinel) {
				t.Fatalf("expected sentinel error, got: %v", err)
			}
			if err := tc.call(m); err != nil {
				t.Fatalf("expected no error on second call, got: %v", err)
			}
		})
	}
}
