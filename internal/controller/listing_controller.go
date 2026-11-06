package controller

import (
	"context"
	"reflect"
)

// passController is a Controller that serves listings from the listing pass
// its context carries and applies its writes to every pass in progress. All
// other methods go straight to the wrapped Controller.
type passController struct {
	Controller
	owner any
}

// WithListingPasses wraps c so that its listings and writes take part in
// listing passes (see BeginPass). A Controller already wrapped is returned as
// it is. Wrappers of the same Controller share each pass's listings.
func WithListingPasses(c Controller) Controller {
	if c == nil {
		return nil
	}
	if _, ok := c.(*passController); ok {
		return c
	}
	w := &passController{Controller: c}
	w.owner = w
	if reflect.TypeOf(c).Comparable() {
		w.owner = c
	}
	return w
}

func (w *passController) key(site string) siteKey {
	return siteKey{owner: w.owner, site: site}
}

// --- Traffic Matching Lists --------------------------------------------------

func (w *passController) ListTrafficMatchingLists(ctx context.Context, site string) ([]TrafficMatchingList, error) {
	return listThrough(ctx, w.key(site), tmlsOf, func() ([]TrafficMatchingList, error) {
		return w.Controller.ListTrafficMatchingLists(ctx, site)
	})
}

func (w *passController) CreateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) (TrafficMatchingList, error) {
	created, err := w.Controller.CreateTrafficMatchingList(ctx, site, list)
	recordWrite(w.key(site), tmlsOf, err, upsert(created, tmlID))
	return created, err
}

func (w *passController) UpdateTrafficMatchingList(ctx context.Context, site string, list TrafficMatchingList) error {
	err := w.Controller.UpdateTrafficMatchingList(ctx, site, list)
	recordWrite(w.key(site), tmlsOf, err, upsert(list, tmlID))
	return err
}

func (w *passController) DeleteTrafficMatchingList(ctx context.Context, site string, id string) error {
	err := w.Controller.DeleteTrafficMatchingList(ctx, site, id)
	recordDelete(w.key(site), tmlsOf, err, id, tmlID)
	return err
}

// --- Zone Policies -----------------------------------------------------------

func (w *passController) ListZonePolicies(ctx context.Context, site string) ([]ZonePolicy, error) {
	return listThrough(ctx, w.key(site), policiesOf, func() ([]ZonePolicy, error) {
		return w.Controller.ListZonePolicies(ctx, site)
	})
}

func (w *passController) CreateZonePolicy(ctx context.Context, site string, p ZonePolicy) (ZonePolicy, error) {
	created, err := w.Controller.CreateZonePolicy(ctx, site, p)
	recordWrite(w.key(site), policiesOf, err, upsert(created, policyID))
	return created, err
}

// UpdateZonePolicy drops the policy listing even on success: a PUT carries no
// port or destination filters and the controller drops them, so the policy it
// holds can differ from the one sent. Updates are repairs, which are rare.
func (w *passController) UpdateZonePolicy(ctx context.Context, site string, p ZonePolicy) error {
	err := w.Controller.UpdateZonePolicy(ctx, site, p)
	recordWrite(w.key(site), policiesOf, err, invalidate[ZonePolicy])
	return err
}

func (w *passController) DeleteZonePolicy(ctx context.Context, site string, id string) error {
	err := w.Controller.DeleteZonePolicy(ctx, site, id)
	recordDelete(w.key(site), policiesOf, err, id, policyID)
	return err
}

// --- Firewall Groups ---------------------------------------------------------

func (w *passController) ListFirewallGroups(ctx context.Context, site string) ([]FirewallGroup, error) {
	return listThrough(ctx, w.key(site), groupsOf, func() ([]FirewallGroup, error) {
		return w.Controller.ListFirewallGroups(ctx, site)
	})
}

func (w *passController) CreateFirewallGroup(ctx context.Context, site string, g FirewallGroup) (FirewallGroup, error) {
	created, err := w.Controller.CreateFirewallGroup(ctx, site, g)
	recordWrite(w.key(site), groupsOf, err, upsert(created, groupID))
	return created, err
}

func (w *passController) UpdateFirewallGroup(ctx context.Context, site string, g FirewallGroup) error {
	err := w.Controller.UpdateFirewallGroup(ctx, site, g)
	recordWrite(w.key(site), groupsOf, err, upsert(g, groupID))
	return err
}

func (w *passController) DeleteFirewallGroup(ctx context.Context, site string, id string) error {
	err := w.Controller.DeleteFirewallGroup(ctx, site, id)
	recordDelete(w.key(site), groupsOf, err, id, groupID)
	return err
}

// --- Firewall Rules ----------------------------------------------------------

func (w *passController) ListFirewallRules(ctx context.Context, site string) ([]FirewallRule, error) {
	return listThrough(ctx, w.key(site), rulesOf, func() ([]FirewallRule, error) {
		return w.Controller.ListFirewallRules(ctx, site)
	})
}

func (w *passController) CreateFirewallRule(ctx context.Context, site string, r FirewallRule) (FirewallRule, error) {
	created, err := w.Controller.CreateFirewallRule(ctx, site, r)
	recordWrite(w.key(site), rulesOf, err, upsert(created, ruleID))
	return created, err
}

// UpdateFirewallRule drops the rule listing even on success: the controller
// stores rule fields the model does not carry, so the rule it holds can differ
// from the one sent. Updates are repairs, which are rare.
func (w *passController) UpdateFirewallRule(ctx context.Context, site string, r FirewallRule) error {
	err := w.Controller.UpdateFirewallRule(ctx, site, r)
	recordWrite(w.key(site), rulesOf, err, invalidate[FirewallRule])
	return err
}

func (w *passController) DeleteFirewallRule(ctx context.Context, site string, id string) error {
	err := w.Controller.DeleteFirewallRule(ctx, site, id)
	recordDelete(w.key(site), rulesOf, err, id, ruleID)
	return err
}
