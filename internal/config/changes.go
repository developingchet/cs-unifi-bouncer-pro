package config

import (
	"reflect"
	"slices"
	"strings"
)

// ChangedSettings returns the names of the settings whose values differ
// between running and reloaded, in the order Config declares them, leaving
// out the names in except. Only names are returned, never values, so the
// result may be logged even when a secret changed. With UNIFI_SITES_AUTO the
// running UNIFI_SITES holds the discovered sites, so it is not compared.
func ChangedSettings(running, reloaded *Config, except ...string) []string {
	rv, nv := reflect.ValueOf(running).Elem(), reflect.ValueOf(reloaded).Elem()
	t := rv.Type()
	var changed []string
	for i := range t.NumField() {
		name := settingName(t.Field(i))
		if name == "" || slices.Contains(except, name) {
			continue
		}
		if name == "UNIFI_SITES" && running.UnifiSitesAuto {
			continue
		}
		if !reflect.DeepEqual(rv.Field(i).Interface(), nv.Field(i).Interface()) {
			changed = append(changed, name)
		}
	}
	return changed
}

// settingName returns the environment variable a Config field is read from:
// its setting tag, or its koanf key in upper case. Fields that hold no
// setting have neither.
func settingName(f reflect.StructField) string {
	if name := f.Tag.Get("setting"); name != "" {
		return name
	}
	if key := f.Tag.Get("koanf"); key != "" && key != "-" {
		return strings.ToUpper(key)
	}
	return ""
}
