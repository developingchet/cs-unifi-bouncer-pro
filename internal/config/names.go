package config

import (
	"bytes"
	"fmt"
	"text/template"
	"unicode/utf8"
)

// NameData holds the variables available in the object name templates.
type NameData struct {
	Family  string // "v4" or "v6"
	Index   int    // shard number (0, 1, 2...)
	Site    string // UniFi site name
	SrcZone string // source zone name (zone mode only)
	DstZone string // destination zone name (zone mode only)
}

// maxLegacyGroupName is the longest firewall group name the classic API
// accepts; a longer one is refused with api.err.InvalidPayload.
const maxLegacyGroupName = 64

// validateLegacyGroupName checks that GROUP_NAME_TEMPLATE renders a name the
// classic API accepts for the first shard of each family on each site. A name
// that only grows past the limit at a higher index is refused when that shard
// is created, which shard_create_failed reports.
func validateLegacyGroupName(tmpl string, sites []string) error {
	t, err := template.New("GROUP_NAME_TEMPLATE").Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("GROUP_NAME_TEMPLATE is invalid Go template: %w", err)
	}
	for _, site := range sites {
		for _, family := range []string{"v4", "v6"} {
			var buf bytes.Buffer
			if err := t.Execute(&buf, NameData{Family: family, Index: 0, Site: site}); err != nil {
				return fmt.Errorf("GROUP_NAME_TEMPLATE cannot be rendered: %w", err)
			}
			if n := utf8.RuneCount(buf.Bytes()); n > maxLegacyGroupName {
				return fmt.Errorf("GROUP_NAME_TEMPLATE renders %q (%d characters) for site %q; legacy firewall groups are limited to %d characters",
					buf.String(), n, site, maxLegacyGroupName)
			}
		}
	}
	return nil
}

// validateNameTemplate parses tmpl and renders it for two shards. Parsing
// alone accepted templates that fail on every render ({{.Foo}}) and ones
// without {{.Index}}, which give every shard the same name so the second
// shard can never be created.
func validateNameTemplate(name, tmpl string) error {
	t, err := template.New(name).Option("missingkey=error").Parse(tmpl)
	if err != nil {
		return fmt.Errorf("%s is invalid Go template: %w", name, err)
	}
	var names [2]string
	for i := range names {
		var buf bytes.Buffer
		data := NameData{Family: "v4", Index: i, Site: "default", SrcZone: "External", DstZone: "Internal"}
		if err := t.Execute(&buf, data); err != nil {
			return fmt.Errorf("%s cannot be rendered: %w", name, err)
		}
		names[i] = buf.String()
	}
	if names[0] == "" {
		return fmt.Errorf("%s renders an empty name", name)
	}
	if names[0] == names[1] {
		return fmt.Errorf("%s must include {{.Index}} so each shard gets its own name", name)
	}
	return nil
}
