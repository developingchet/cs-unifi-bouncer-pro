package firewall

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// NameData holds variables available in name templates.
type NameData struct {
	Family  string // "v4" or "v6"
	Index   int    // shard number (0, 1, 2...)
	Site    string // UniFi site name
	SrcZone string // source zone name (zone mode only)
	DstZone string // destination zone name (zone mode only)
	Prefix  string // value of GROUP_PREFIX env var (default "crowdsec")
}

// Namer renders Go-template name strings for managed UniFi objects.
type Namer struct {
	groupTmpl    *template.Template
	groupPrefix  string
	ruleTmpl     *template.Template
	rulePrefix   string
	policyTmpl   *template.Template
	policyPrefix string
	description  string
}

// NewNamer parses and validates the three name templates.
func NewNamer(groupTmpl, ruleTmpl, policyTmpl, description string) (*Namer, error) {
	gt, err := template.New("group").Parse(groupTmpl)
	if err != nil {
		return nil, fmt.Errorf("GROUP_NAME_TEMPLATE: %w", err)
	}
	rt, err := template.New("rule").Parse(ruleTmpl)
	if err != nil {
		return nil, fmt.Errorf("RULE_NAME_TEMPLATE: %w", err)
	}
	pt, err := template.New("policy").Parse(policyTmpl)
	if err != nil {
		return nil, fmt.Errorf("POLICY_NAME_TEMPLATE: %w", err)
	}
	return &Namer{
		groupTmpl:    gt,
		groupPrefix:  strings.SplitN(groupTmpl, "{{", 2)[0],
		ruleTmpl:     rt,
		rulePrefix:   strings.SplitN(ruleTmpl, "{{", 2)[0],
		policyTmpl:   pt,
		policyPrefix: strings.SplitN(policyTmpl, "{{", 2)[0],
		description:  description,
	}, nil
}

// GroupName renders the firewall group name for the given data.
func (n *Namer) GroupName(d NameData) (string, error) {
	return render(n.groupTmpl, d)
}

// RuleName renders the legacy drop rule name for the given data.
func (n *Namer) RuleName(d NameData) (string, error) {
	return render(n.ruleTmpl, d)
}

// PolicyName renders the zone policy name for the given data.
func (n *Namer) PolicyName(d NameData) (string, error) {
	return render(n.policyTmpl, d)
}

// Description returns the static object description string.
func (n *Namer) Description() string {
	return n.description
}

func (n *Namer) PolicyPrefix() string {
	return n.policyPrefix
}

func (n *Namer) RulePrefix() string {
	return n.rulePrefix
}

func (n *Namer) GroupPrefix() string {
	return n.groupPrefix
}

func render(tmpl *template.Template, data NameData) (string, error) {
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render template %q: %w", tmpl.Name(), err)
	}
	return buf.String(), nil
}

// Family returns the family string for an IPv6 flag.
func Family(ipv6 bool) string {
	if ipv6 {
		return "v6"
	}
	return "v4"
}
