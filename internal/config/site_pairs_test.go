package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func setSitePairEnv(t *testing.T, sites string) {
	t.Helper()
	setEnv(t, "UNIFI_URL", "https://192.168.1.1")
	setEnv(t, "UNIFI_API_KEY", "key")
	setEnv(t, "CROWDSEC_LAPI_KEY", "lapi-key")
	setEnv(t, "UNIFI_SITES", sites)
}

func TestParseZonePairSitePrefix(t *testing.T) {
	tests := []struct {
		pair, site, src, dst string
		dstIPs               []string
	}{
		{"External->Dmz", "", "External", "Dmz", nil},
		{"default/External->Dmz", "default", "External", "Dmz", nil},
		{" branch / Wan->Lan", "branch", "Wan", "Lan", nil},
		{"External->Dmz@10.0.0.0/24", "", "External", "Dmz", []string{"10.0.0.0/24"}},
		{"branch/Wan:22->Lan@10.0.0.0/24,2001:db8::/64", "branch", "Wan", "Lan", []string{"10.0.0.0/24", "2001:db8::/64"}},
	}
	for _, tt := range tests {
		t.Run(tt.pair, func(t *testing.T) {
			pairs, err := parseZonePairList([]string{tt.pair})
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			p := pairs[0]
			if p.Site != tt.site || p.Src != tt.src || p.Dst != tt.dst || !slices.Equal(p.DstIPs, tt.dstIPs) {
				t.Errorf("parsed %+v, want site %q, %s->%s, destination IPs %v", p, tt.site, tt.src, tt.dst, tt.dstIPs)
			}
		})
	}
}

func TestParseZonePairRejectsBadSitePrefix(t *testing.T) {
	for _, pair := range []string{"/External->Dmz", " /External->Dmz", "my site/External->Dmz", "a:b/External->Dmz"} {
		if _, err := parseZonePairList([]string{pair}); err == nil || !strings.Contains(err.Error(), "site name") {
			t.Errorf("parse %q: err = %v, want a site name error", pair, err)
		}
	}
}

func TestZonePairStringOmitsSitePrefix(t *testing.T) {
	pairs, err := parseZonePairList([]string{"branch/Wan:22,2222->Lan:80@10.0.0.5,2001:db8::/64"})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := pairs[0].String(), "Wan:22,2222->Lan:80@10.0.0.5,2001:db8::/64"; got != want {
		t.Errorf("String() = %q, want %q", got, want)
	}
}

func TestPairsForSite(t *testing.T) {
	pairs := []ZonePair{
		{Src: "External", Dst: "Dmz"},
		{Site: "branch", Src: "Wan", Dst: "Lan"},
		{Site: "branch", Src: "Wan", Dst: "Iot"},
		{Src: "Dmz", Dst: "External", Egress: true},
		{Site: "lab", Src: "Lab", Dst: "Internet", Egress: true},
	}
	tests := []struct {
		site string
		want []string
	}{
		// default has no pairs of its own in either setting.
		{"default", []string{"External->Dmz", "Dmz->External"}},
		// branch replaces the inbound pairs and keeps the unprefixed egress pair.
		{"branch", []string{"Wan->Lan", "Wan->Iot", "Dmz->External"}},
		// lab replaces the egress pair and keeps the unprefixed inbound pair.
		{"lab", []string{"External->Dmz", "Lab->Internet"}},
	}
	for _, tt := range tests {
		t.Run(tt.site, func(t *testing.T) {
			var got []string
			for _, p := range PairsForSite(pairs, tt.site) {
				got = append(got, p.String())
			}
			if !slices.Equal(got, tt.want) {
				t.Errorf("PairsForSite(%q) = %v, want %v", tt.site, got, tt.want)
			}
		})
	}
}

func TestPairsForSiteWithOnlyPrefixedPairs(t *testing.T) {
	pairs := []ZonePair{{Site: "branch", Src: "Wan", Dst: "Lan"}}
	if got := PairsForSite(pairs, "default"); len(got) != 0 {
		t.Errorf("PairsForSite(default) = %+v, want none: every pair belongs to another site", got)
	}
}

func TestLoadMixedSitePairs(t *testing.T) {
	setSitePairEnv(t, "default,branch")
	setEnv(t, "ZONE_PAIRS", "External->Dmz;branch/Wan:443->Lan;branch/Wan->Iot")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pairs, err := cfg.ParseZonePairs()
	if err != nil {
		t.Fatal(err)
	}
	if got := PairSites(pairs); !slices.Equal(got, []string{"branch"}) {
		t.Errorf("PairSites = %v, want [branch]", got)
	}
	if got := PairsForSite(pairs, "branch"); len(got) != 2 || got[0].String() != "Wan:443->Lan" {
		t.Errorf("branch pairs = %+v", got)
	}
	if got := PairsForSite(pairs, "default"); len(got) != 1 || got[0].String() != "External->Dmz" {
		t.Errorf("default pairs = %+v", got)
	}
}

func TestSitePairsFromFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "zone_pairs")
	content := "# head office\ndefault/External->Internal\n\n# branch office, other zone names\nbranch/Wan:443->Lan@10.1.0.0/24\nbranch/Wan->Iot,branch/Wan->Guest\n"
	if err := os.WriteFile(file, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	setSitePairEnv(t, "default,branch")
	setEnv(t, "FIREWALL_MODE", "zone")
	setEnv(t, "ZONE_PAIRS_FILE", file)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	pairs, err := cfg.ParseZonePairs()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"default": {"External->Internal"},
		"branch":  {"Wan:443->Lan@10.1.0.0/24", "Wan->Iot", "Wan->Guest"},
	}
	for site, wantPairs := range want {
		var got []string
		for _, p := range PairsForSite(pairs, site) {
			got = append(got, p.String())
		}
		if !slices.Equal(got, wantPairs) {
			t.Errorf("site %s pairs = %v, want %v", site, got, wantPairs)
		}
	}
}

func TestValidateRejectsUnknownPairSite(t *testing.T) {
	tests := []struct {
		name, key, value, want string
	}{
		{"zone pairs", "ZONE_PAIRS", "External->Dmz;branch/Wan->Lan",
			`ZONE_PAIRS names site "branch", which is not in UNIFI_SITES (default)`},
		{"egress pairs", "EGRESS_ZONE_PAIRS", "lab/Lab->External",
			`EGRESS_ZONE_PAIRS names site "lab", which is not in UNIFI_SITES (default)`},
		{"cloudflare pairs", "CLOUDFLARE_ZONE_PAIRS", "branch/External->Dmz",
			`CLOUDFLARE_ZONE_PAIRS names site "branch", which is not in UNIFI_SITES (default)`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSitePairEnv(t, "default")
			setEnv(t, "CLOUDFLARE_WHITELIST_ENABLED", "true")
			setEnv(t, "CLOUDFLARE_ZONE_PAIRS", "External->Dmz")
			setEnv(t, tt.key, tt.value)
			if _, err := Load(); err == nil || err.Error() != tt.want {
				t.Fatalf("Load: err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestValidateIgnoresZonePairSitesInLegacyMode(t *testing.T) {
	setSitePairEnv(t, "default")
	setEnv(t, "FIREWALL_MODE", "legacy")
	setEnv(t, "ZONE_PAIRS", "branch/Wan->Lan")
	if _, err := Load(); err != nil {
		t.Fatalf("Load: %v; ZONE_PAIRS is not used with FIREWALL_MODE=legacy", err)
	}
}

func TestValidateRequiresAZonePairForEverySiteInZoneMode(t *testing.T) {
	setSitePairEnv(t, "default,branch")
	setEnv(t, "FIREWALL_MODE", "zone")
	setEnv(t, "ZONE_PAIRS", "branch/Wan->Lan")
	want := `ZONE_PAIRS leaves site "default" without a zone pair; add a pair without a site prefix or one starting with "default/"`
	if _, err := Load(); err == nil || err.Error() != want {
		t.Fatalf("Load: err = %v, want %q", err, want)
	}

	setEnv(t, "ZONE_PAIRS", "branch/Wan->Lan;default/External->Internal")
	if _, err := Load(); err != nil {
		t.Fatalf("Load with a pair for each site: %v", err)
	}
}

func TestValidateEgressDuplicatesPerSite(t *testing.T) {
	setSitePairEnv(t, "default,branch")
	for _, ok := range []string{
		"Dmz->External;branch/Dmz->External",
		"default/Dmz->External;branch/Dmz->External",
	} {
		setEnv(t, "EGRESS_ZONE_PAIRS", ok)
		if _, err := Load(); err != nil {
			t.Errorf("EGRESS_ZONE_PAIRS=%s: %v", ok, err)
		}
	}
	setEnv(t, "EGRESS_ZONE_PAIRS", "branch/Dmz->External;branch/Dmz->External:443")
	want := `EGRESS_ZONE_PAIRS names Dmz->External more than once for site "branch"`
	if _, err := Load(); err == nil || err.Error() != want {
		t.Fatalf("Load: err = %v, want %q", err, want)
	}
}

func TestUnknownPairSiteWarningsWithAutoSites(t *testing.T) {
	setSitePairEnv(t, "")
	setEnv(t, "UNIFI_SITES_AUTO", "true")
	setEnv(t, "ZONE_PAIRS", "External->Dmz;branch/Wan->Lan;lab/Lab->Lan")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v; prefixes cannot be checked before the sites are discovered", err)
	}
	got := cfg.UnknownPairSiteWarnings([]string{"default", "branch"})
	want := []string{`ZONE_PAIRS names site "lab", which is not among the managed sites (default, branch); its pairs apply to no site`}
	if !slices.Equal(got, want) {
		t.Errorf("warnings = %q, want %q", got, want)
	}
}
