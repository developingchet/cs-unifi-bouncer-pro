package firewall

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
)

// NameData holds variables available in name templates. It is the type
// config validates the templates against.
type NameData = config.NameData

// Namer renders Go-template name strings for managed UniFi objects.
type Namer struct {
	groupTmpl    *template.Template
	groupPrefix  string
	ruleTmpl     *template.Template
	rulePrefix   string
	policyTmpl   *template.Template
	policyPrefix string
}

// NewNamer parses and validates the three name templates.
func NewNamer(groupTmpl, ruleTmpl, policyTmpl string) (*Namer, error) {
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
