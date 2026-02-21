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

	t.Run("reorder records call", func(t *testing.T) {
		m := testutil.NewMockController()
		req := controller.ZonePolicyReorderRequest{
			SourceZoneID:      "zone-src",
			DestinationZoneID: "zone-dst",
		}
		if err := m.ReorderZonePolicies(ctx, site, req); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if m.Calls("ReorderZonePolicies") != 1 {
			t.Fatal("expected 1 call to ReorderZonePolicies")
		}
	})
}

// TestMockController_Zones covers zone listing.
func TestMockController_Zones(t *testing.T) {
	ctx := context.Background()
	const site = "default"

	t.Run("preset zones are returned", func(t *testing.T) {
		m := testutil.NewMockController()
		m.SetZones(site, []controller.Zone{{ID: "z1", Name: "WAN"}})
		zones, err := m.ListZones(ctx, site)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(zones) != 1 || zones[0].Name != "WAN" {
			t.Fatalf("unexpected zones: %+v", zones)
		}
	})

	t.Run("unknown site returns empty", func(t *testing.T) {
		m := testutil.NewMockController()
		zones, err := m.ListZones(ctx, "other")
		if err != nil || len(zones) != 0 {
			t.Fatalf("expected empty, nil; got %v, %v", zones, err)
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
			"ReorderZonePolicies",
			func(m *testutil.MockController) error {
				return m.ReorderZonePolicies(ctx, site, controller.ZonePolicyReorderRequest{})
			},
		},
		{
			"ListZones",
			func(m *testutil.MockController) error { _, err := m.ListZones(ctx, site); return err },
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
