package firewall

import (
	"testing"
)

func TestDefaultTemplates(t *testing.T) {
	n, err := NewNamer(
		"crowdsec-block-{{.Family}}-{{.Index}}",
		"crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}",
		"Managed by cs-unifi-bouncer-pro.",
	)
	if err != nil {
		t.Fatalf("NewNamer: %v", err)
	}

	d := NameData{Family: "v4", Index: 0, Site: "default"}
	got, err := n.GroupName(d)
	if err != nil {
		t.Fatal(err)
	}
	if got != "crowdsec-block-v4-0" {
		t.Errorf("GroupName: got %q, want %q", got, "crowdsec-block-v4-0")
	}

	d.Family = "v6"
	d.Index = 2
	got, err = n.GroupName(d)
	if err != nil {
		t.Fatal(err)
	}
	if got != "crowdsec-block-v6-2" {
		t.Errorf("GroupName v6: got %q, want %q", got, "crowdsec-block-v6-2")
	}
}

func TestRuleNameTemplate(t *testing.T) {
	n, err := NewNamer(
		"crowdsec-block-{{.Family}}-{{.Index}}",
		"crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}",
		"desc",
	)
	if err != nil {
		t.Fatal(err)
	}

	d := NameData{Family: "v4", Index: 0, Site: "default"}
	got, err := n.RuleName(d)
	if err != nil {
		t.Fatal(err)
	}
	if got != "crowdsec-drop-v4-0" {
		t.Errorf("RuleName: got %q, want %q", got, "crowdsec-drop-v4-0")
	}
}

func TestPolicyNameTemplate(t *testing.T) {
	n, err := NewNamer(
		"crowdsec-block-{{.Family}}-{{.Index}}",
		"crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.SrcZone}}-{{.DstZone}}-{{.Family}}-{{.Index}}",
		"desc",
	)
	if err != nil {
		t.Fatal(err)
	}

	d := NameData{Family: "v4", Index: 0, Site: "default", SrcZone: "wan", DstZone: "lan"}
	got, err := n.PolicyName(d)
	if err != nil {
		t.Fatal(err)
	}
	want := "crowdsec-policy-wan-lan-v4-0"
	if got != want {
		t.Errorf("PolicyName: got %q, want %q", got, want)
	}
}

func TestCustomTemplate(t *testing.T) {
	n, err := NewNamer(
		"prod-block-{{.Family}}-{{.Index}}",
		"prod-drop-{{.Family}}-{{.Index}}",
		"prod-policy-{{.Family}}-{{.Index}}",
		"Custom desc",
	)
	if err != nil {
		t.Fatal(err)
	}

	d := NameData{Family: "v4", Index: 5, Site: "site1"}
	got, err := n.GroupName(d)
	if err != nil {
		t.Fatal(err)
	}
	if got != "prod-block-v4-5" {
		t.Errorf("custom GroupName: got %q", got)
	}
}

func TestInvalidTemplateReturnsError(t *testing.T) {
	_, err := NewNamer(
		"{{.Invalid unclosed",
		"crowdsec-drop-{{.Family}}-{{.Index}}",
		"crowdsec-policy-{{.Family}}-{{.Index}}",
		"desc",
	)
	if err == nil {
		t.Error("expected error for invalid template")
	}
}

func TestDescriptionReturned(t *testing.T) {
	desc := "My custom description"
	n, err := NewNamer("g-{{.Family}}", "r-{{.Family}}", "p-{{.Family}}", desc)
	if err != nil {
		t.Fatal(err)
	}
	if n.Description() != desc {
		t.Errorf("Description: got %q, want %q", n.Description(), desc)
	}
}

func TestFamilyHelper(t *testing.T) {
	if Family(false) != "v4" {
		t.Error("expected v4 for false")
	}
	if Family(true) != "v6" {
		t.Error("expected v6 for true")
	}
}

func TestSiteVariable(t *testing.T) {
	n, err := NewNamer(
		"{{.Site}}-block-{{.Family}}-{{.Index}}",
		"{{.Site}}-drop-{{.Family}}-{{.Index}}",
		"{{.Site}}-policy-{{.Family}}-{{.Index}}",
		"desc",
	)
	if err != nil {
		t.Fatal(err)
	}

	d := NameData{Family: "v4", Index: 0, Site: "homelab"}
	got, err := n.GroupName(d)
	if err != nil {
		t.Fatal(err)
	}
	if got != "homelab-block-v4-0" {
		t.Errorf("site variable: got %q", got)
	}
}
