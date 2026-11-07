package firewall

import (
	"context"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/testutil"
)

// driftWithFlowReportsOff turns Insights flow reporting off on the named
// policy, the way an admin would in the UniFi UI, and changes its connection
// states so the next repair has to rewrite it.
func driftWithFlowReportsOff(t *testing.T, ctrl *testutil.MockController, name string) {
	t.Helper()
	policies, err := ctrl.ListZonePolicies(context.Background(), testSite)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	found := false
	for i := range policies {
		if policies[i].Name == name {
			policies[i].ReportFlowEnabled = &off
			policies[i].ConnectionStateFilter = []string{"ESTABLISHED"}
			found = true
		}
	}
	if !found {
		t.Fatalf("policy %s not found", name)
	}
	ctrl.SetPolicies(testSite, policies)
}

func assertFlowReportsOff(t *testing.T, ctrl *testutil.MockController, name string) {
	t.Helper()
	p, ok := policiesByName(t, ctrl)[name]
	if !ok {
		t.Fatalf("policy %s missing after the repair", name)
	}
	if len(p.ConnectionStateFilter) == 1 && p.ConnectionStateFilter[0] == "ESTABLISHED" {
		t.Fatalf("policy %s was not repaired: %+v", name, p)
	}
	if p.ReportFlowEnabled == nil || *p.ReportFlowEnabled {
		t.Fatalf("policy %s reportFlowEnabled = %v after the repair, want the admin's false kept", name, p.ReportFlowEnabled)
	}
}

// UniFi Network 11 sets reportFlowEnabled to true whenever a write leaves it
// out. A repair must carry the policy's own value, or every repair would undo
// an admin who turned flow reports off for a busy block policy.
func TestRepairKeepsReportFlowSetting(t *testing.T) {
	mgr, ctrl := zoneSite(t, []config.ZonePair{{Src: "wan", Dst: "lan"}})
	driftWithFlowReportsOff(t, ctrl, inboundPolicy)
	if err := mgr.RepairInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("RepairInfrastructure: %v", err)
	}
	assertFlowReportsOff(t, ctrl, inboundPolicy)
}

// A filtered policy is replaced rather than updated; the replacement carries
// the setting too.
func TestReplacementKeepsReportFlowSetting(t *testing.T) {
	mgr, ctrl := egressSite(t, config.ZonePair{Src: "lan", Dst: "wan", Egress: true})
	driftWithFlowReportsOff(t, ctrl, egressPolicy)
	if err := mgr.RepairInfrastructure(context.Background(), []string{testSite}); err != nil {
		t.Fatalf("RepairInfrastructure: %v", err)
	}
	assertFlowReportsOff(t, ctrl, egressPolicy)
}

// A policy created by the bouncer leaves the field out, so the controller's
// default applies; on controllers before Network 11 nothing is sent.
func TestNewPolicyLeavesReportFlowToTheController(t *testing.T) {
	_, ctrl := zoneSite(t, []config.ZonePair{{Src: "wan", Dst: "lan"}})
	p, ok := policiesByName(t, ctrl)[inboundPolicy]
	if !ok {
		t.Fatal("inbound policy missing")
	}
	if p.ReportFlowEnabled != nil {
		t.Fatalf("new policy sent reportFlowEnabled = %v, want it left out", *p.ReportFlowEnabled)
	}
}
