package testutil

import (
	"context"
	"fmt"
	"sync"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// MockController implements controller.Controller for testing.
// All methods are safe for concurrent use.
type MockController struct {
	mu sync.Mutex

	// Preset list responses per site
	groups   map[string][]controller.FirewallGroup
	rules    map[string][]controller.FirewallRule
	policies map[string][]controller.ZonePolicy
	zones    map[string][]controller.Zone

	// Preset feature detection results per site
	features map[string]map[string]bool

	// Error injection: method -> next error (consumed on first call)
	errors map[string]error

	// Call counts per method
	calls map[string]int

	// Auto-increment ID counter for created resources
	nextID int
}

// NewMockController returns a zero-state MockController ready for use.
func NewMockController() *MockController {
	return &MockController{
		groups:   make(map[string][]controller.FirewallGroup),
		rules:    make(map[string][]controller.FirewallRule),
		policies: make(map[string][]controller.ZonePolicy),
		zones:    make(map[string][]controller.Zone),
		features: make(map[string]map[string]bool),
		errors:   make(map[string]error),
		calls:    make(map[string]int),
	}
}

// SetGroups presets the list of firewall groups returned for a site.
func (m *MockController) SetGroups(site string, groups []controller.FirewallGroup) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.groups[site] = groups
}

// SetRules presets the list of firewall rules returned for a site.
func (m *MockController) SetRules(site string, rules []controller.FirewallRule) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rules[site] = rules
}

// SetPolicies presets the list of zone policies returned for a site.
func (m *MockController) SetPolicies(site string, policies []controller.ZonePolicy) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.policies[site] = policies
}

// SetZones presets the list of zones returned for a site.
func (m *MockController) SetZones(site string, zones []controller.Zone) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.zones[site] = zones
}

// SetHasFeature presets the feature detection result for a site/feature pair.
func (m *MockController) SetHasFeature(site, feature string, val bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.features[site] == nil {
		m.features[site] = make(map[string]bool)
	}
	m.features[site][feature] = val
}

// SetError injects an error to be returned on the next call to the named method.
// The error is consumed (returned once) and then cleared.
func (m *MockController) SetError(method string, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.errors[method] = err
}

// Calls returns the total number of times the named method was called.
func (m *MockController) Calls(method string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls[method]
}

// popError returns and clears any pending error for the given method.
func (m *MockController) popError(method string) error {
	err := m.errors[method]
	delete(m.errors, method)
	return err
}

func (m *MockController) newID() string {
	m.nextID++
	return fmt.Sprintf("mock-id-%d", m.nextID)
}

// --- Controller interface implementation ------------------------------------

func (m *MockController) ListFirewallGroups(ctx context.Context, site string) ([]controller.FirewallGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["ListFirewallGroups"]++
	if err := m.popError("ListFirewallGroups"); err != nil {
		return nil, err
	}
	return append([]controller.FirewallGroup{}, m.groups[site]...), nil
}

func (m *MockController) CreateFirewallGroup(ctx context.Context, site string, g controller.FirewallGroup) (controller.FirewallGroup, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["CreateFirewallGroup"]++
	if err := m.popError("CreateFirewallGroup"); err != nil {
		return controller.FirewallGroup{}, err
	}
	g.ID = m.newID()
	m.groups[site] = append(m.groups[site], g)
	return g, nil
}

func (m *MockController) UpdateFirewallGroup(ctx context.Context, site string, g controller.FirewallGroup) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["UpdateFirewallGroup"]++
	if err := m.popError("UpdateFirewallGroup"); err != nil {
		return err
	}
	for i, existing := range m.groups[site] {
		if existing.ID == g.ID {
			m.groups[site][i] = g
			return nil
		}
	}
	return nil
}

func (m *MockController) DeleteFirewallGroup(ctx context.Context, site string, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["DeleteFirewallGroup"]++
	if err := m.popError("DeleteFirewallGroup"); err != nil {
		return err
	}
	groups := m.groups[site][:0]
	for _, g := range m.groups[site] {
		if g.ID != id {
			groups = append(groups, g)
		}
	}
	m.groups[site] = groups
	return nil
}

func (m *MockController) ListFirewallRules(ctx context.Context, site string) ([]controller.FirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["ListFirewallRules"]++
	if err := m.popError("ListFirewallRules"); err != nil {
		return nil, err
	}
	return append([]controller.FirewallRule{}, m.rules[site]...), nil
}

func (m *MockController) CreateFirewallRule(ctx context.Context, site string, r controller.FirewallRule) (controller.FirewallRule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["CreateFirewallRule"]++
	if err := m.popError("CreateFirewallRule"); err != nil {
		return controller.FirewallRule{}, err
	}
	r.ID = m.newID()
	m.rules[site] = append(m.rules[site], r)
	return r, nil
}

func (m *MockController) UpdateFirewallRule(ctx context.Context, site string, r controller.FirewallRule) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["UpdateFirewallRule"]++
	if err := m.popError("UpdateFirewallRule"); err != nil {
		return err
	}
	for i, existing := range m.rules[site] {
		if existing.ID == r.ID {
			m.rules[site][i] = r
			return nil
		}
	}
	return nil
}

func (m *MockController) DeleteFirewallRule(ctx context.Context, site string, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["DeleteFirewallRule"]++
	if err := m.popError("DeleteFirewallRule"); err != nil {
		return err
	}
	rules := m.rules[site][:0]
	for _, r := range m.rules[site] {
		if r.ID != id {
			rules = append(rules, r)
		}
	}
	m.rules[site] = rules
	return nil
}

func (m *MockController) ListZonePolicies(ctx context.Context, site string) ([]controller.ZonePolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["ListZonePolicies"]++
	if err := m.popError("ListZonePolicies"); err != nil {
		return nil, err
	}
	return append([]controller.ZonePolicy{}, m.policies[site]...), nil
}

func (m *MockController) CreateZonePolicy(ctx context.Context, site string, p controller.ZonePolicy) (controller.ZonePolicy, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["CreateZonePolicy"]++
	if err := m.popError("CreateZonePolicy"); err != nil {
		return controller.ZonePolicy{}, err
	}
	p.ID = m.newID()
	m.policies[site] = append(m.policies[site], p)
	return p, nil
}

func (m *MockController) UpdateZonePolicy(ctx context.Context, site string, p controller.ZonePolicy) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["UpdateZonePolicy"]++
	if err := m.popError("UpdateZonePolicy"); err != nil {
		return err
	}
	for i, existing := range m.policies[site] {
		if existing.ID == p.ID {
			m.policies[site][i] = p
			return nil
		}
	}
	return nil
}

func (m *MockController) DeleteZonePolicy(ctx context.Context, site string, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["DeleteZonePolicy"]++
	if err := m.popError("DeleteZonePolicy"); err != nil {
		return err
	}
	policies := m.policies[site][:0]
	for _, p := range m.policies[site] {
		if p.ID != id {
			policies = append(policies, p)
		}
	}
	m.policies[site] = policies
	return nil
}

func (m *MockController) ReorderZonePolicies(ctx context.Context, site string, orderedIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["ReorderZonePolicies"]++
	return m.popError("ReorderZonePolicies")
}

func (m *MockController) ListZones(ctx context.Context, site string) ([]controller.Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["ListZones"]++
	if err := m.popError("ListZones"); err != nil {
		return nil, err
	}
	return append([]controller.Zone{}, m.zones[site]...), nil
}

func (m *MockController) HasFeature(ctx context.Context, site string, feature string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["HasFeature"]++
	if err := m.popError("HasFeature"); err != nil {
		return false, err
	}
	if siteFeatures, ok := m.features[site]; ok {
		if val, ok := siteFeatures[feature]; ok {
			return val, nil
		}
	}
	return false, nil
}

func (m *MockController) Ping(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["Ping"]++
	return m.popError("Ping")
}

func (m *MockController) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls["Close"]++
	return nil
}
