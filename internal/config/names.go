package config

import (
	"bytes"
	"fmt"
	"text/template"
)

// NameData holds the variables available in the object name templates.
type NameData struct {
	Family  string // "v4" or "v6"
	Index   int    // shard number (0, 1, 2...)
	Site    string // UniFi site name
	SrcZone string // source zone name (zone mode only)
	DstZone string // destination zone name (zone mode only)
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
