package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestChangedSettings(t *testing.T) {
	running, err := loadWith(t, nil)
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadWith(t, map[string]string{
		"CROWDSEC_LAPI_KEY": "rotated-key",
		"LOG_LEVEL":         "debug",
		"ZONE_PAIRS":        "External->Internal",
		"BLOCKLIST_URLS":    "https://lists.example/a.txt",
	})
	if err != nil {
		t.Fatal(err)
	}
	got := ChangedSettings(running, reloaded, "ZONE_PAIRS")
	want := []string{"CROWDSEC_LAPI_KEY", "LOG_LEVEL", "BLOCKLIST_URLS"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ChangedSettings = %q, want %q", got, want)
	}
	if got := ChangedSettings(running, running); len(got) != 0 {
		t.Errorf("ChangedSettings of one configuration = %q, want none", got)
	}
}

// With UNIFI_SITES_AUTO the daemon replaces UNIFI_SITES with the discovered
// sites, which a reload cannot reproduce.
func TestChangedSettingsIgnoresDiscoveredSites(t *testing.T) {
	running, err := loadWith(t, map[string]string{"UNIFI_SITES_AUTO": "true"})
	if err != nil {
		t.Fatal(err)
	}
	reloaded, err := loadWith(t, map[string]string{"UNIFI_SITES_AUTO": "true"})
	if err != nil {
		t.Fatal(err)
	}
	running.UnifiSites = []string{"default", "branch"}
	if got := ChangedSettings(running, reloaded); len(got) != 0 {
		t.Errorf("ChangedSettings = %q, want none", got)
	}
}

func TestCloudflareZonePairsFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "cloudflare_zone_pairs")
	if err := os.WriteFile(file, []byte("# reverse proxy\nExternal->Dmz:80,443@10.0.5.251\nExternal->Internal\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadWith(t, map[string]string{
		"CLOUDFLARE_WHITELIST_ENABLED": "true",
		"CLOUDFLARE_ZONE_PAIRS":        "External->Hotspot",
		"CLOUDFLARE_ZONE_PAIRS_FILE":   file,
	})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := []string{"External->Dmz:80,443@10.0.5.251", "External->Internal"}
	if !reflect.DeepEqual(cfg.CloudflareZonePairs, want) {
		t.Errorf("CloudflareZonePairs = %q, want %q", cfg.CloudflareZonePairs, want)
	}
}

func TestCloudflareZonePairsFileMustBeReadable(t *testing.T) {
	_, err := loadWith(t, map[string]string{
		"CLOUDFLARE_WHITELIST_ENABLED": "true",
		"CLOUDFLARE_ZONE_PAIRS_FILE":   "/nonexistent/cloudflare_zone_pairs",
	})
	if err == nil || !strings.Contains(err.Error(), "CLOUDFLARE_ZONE_PAIRS_FILE: cannot read /nonexistent/cloudflare_zone_pairs") {
		t.Fatalf("Load = %v, want a CLOUDFLARE_ZONE_PAIRS_FILE read error", err)
	}
}
