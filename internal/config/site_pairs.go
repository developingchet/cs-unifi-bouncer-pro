package config

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// cutSitePrefix splits the optional "<site>/" prefix off a zone pair. Only a
// slash before the arrow starts a prefix: a destination CIDR after "@" holds
// one too.
func cutSitePrefix(pair string) (site, rest string, err error) {
	src, _, _ := strings.Cut(pair, "->")
	idx := strings.Index(src, "/")
	if idx == -1 {
		return "", pair, nil
	}
	site = strings.TrimSpace(src[:idx])
	if site == "" {
		return "", "", fmt.Errorf("site name before \"/\" must not be empty")
	}
	if strings.ContainsAny(site, " \t,;:@") {
		return "", "", fmt.Errorf("invalid site name %q before \"/\"", site)
	}
	return site, pair[idx+1:], nil
}

// String renders the pair in the ZONE_PAIRS syntax, without its site prefix.
func (p ZonePair) String() string {
	var b strings.Builder
	b.WriteString(p.Src)
	writePorts(&b, p.SrcPorts)
	b.WriteString("->")
	b.WriteString(p.Dst)
	writePorts(&b, p.DstPorts)
	if len(p.DstIPs) > 0 {
		b.WriteString("@")
		b.WriteString(strings.Join(p.DstIPs, ","))
	}
	return b.String()
}

func writePorts(b *strings.Builder, ports []int) {
	for i, port := range ports {
		if i == 0 {
			b.WriteString(":")
		} else {
			b.WriteString(",")
		}
		b.WriteString(strconv.Itoa(port))
	}
}

// SitePairs returns the pairs of one zone pair setting that apply to site. A
// site with pairs of its own ("<site>/Src->Dst") uses only those; every other
// site uses the pairs without a site prefix. siteOf returns a pair's prefix,
// or "" for none. ZONE_PAIRS, EGRESS_ZONE_PAIRS and CLOUDFLARE_ZONE_PAIRS are
// each resolved this way, independently of one another.
func SitePairs[P any](pairs []P, site string, siteOf func(P) string) []P {
	var own, shared []P
	for _, p := range pairs {
		switch siteOf(p) {
		case site:
			own = append(own, p)
		case "":
			shared = append(shared, p)
		}
	}
	if len(own) > 0 {
		return own
	}
	return shared
}

// PairsForSite returns the pairs that apply to site. Inbound and egress pairs
// come from different settings and are resolved separately, so a site may
// override ZONE_PAIRS and still use the unprefixed EGRESS_ZONE_PAIRS.
func PairsForSite(pairs []ZonePair, site string) []ZonePair {
	var inbound, egress []ZonePair
	for _, p := range pairs {
		if p.Egress {
			egress = append(egress, p)
		} else {
			inbound = append(inbound, p)
		}
	}
	siteOf := func(p ZonePair) string { return p.Site }
	return append(SitePairs(inbound, site, siteOf), SitePairs(egress, site, siteOf)...)
}

// PairSites returns the sites named by the pairs' prefixes, in the order they
// first appear.
func PairSites(pairs []ZonePair) []string {
	var sites []string
	for _, p := range pairs {
		if p.Site != "" && !slices.Contains(sites, p.Site) {
			sites = append(sites, p.Site)
		}
	}
	return sites
}

// pairSetting is one zone pair setting and its parsed pairs.
type pairSetting struct {
	name  string
	pairs []ZonePair
}

// pairSettings returns the zone pair settings in effect: ZONE_PAIRS unless
// FIREWALL_MODE=legacy, EGRESS_ZONE_PAIRS, and CLOUDFLARE_ZONE_PAIRS when the
// Cloudflare whitelist is on.
func (c *Config) pairSettings() ([]pairSetting, error) {
	var settings []pairSetting
	if c.FirewallMode != "legacy" {
		pairs, err := c.ParseZonePairs()
		if err != nil {
			return nil, fmt.Errorf("ZONE_PAIRS: %w", err)
		}
		settings = append(settings, pairSetting{"ZONE_PAIRS", pairs})
	}
	egress, err := c.ParseEgressZonePairs()
	if err != nil {
		return nil, fmt.Errorf("EGRESS_ZONE_PAIRS: %w", err)
	}
	settings = append(settings, pairSetting{"EGRESS_ZONE_PAIRS", egress})
	if c.CloudflareWhitelistEnabled {
		cloudflare, err := c.ParseCloudflareZonePairs()
		if err != nil {
			return nil, fmt.Errorf("CLOUDFLARE_ZONE_PAIRS: %w", err)
		}
		settings = append(settings, pairSetting{"CLOUDFLARE_ZONE_PAIRS", cloudflare})
	}
	return settings, nil
}

// validatePairSites checks that every site prefix names a site in
// UNIFI_SITES, and that with FIREWALL_MODE=zone each site is left with a
// ZONE_PAIRS pair. With UNIFI_SITES_AUTO the sites are known only once
// discovered; UnknownPairSiteWarnings covers that case.
func (c *Config) validatePairSites() error {
	if c.UnifiSitesAuto {
		return nil
	}
	settings, err := c.pairSettings()
	if err != nil {
		return err
	}
	for _, s := range settings {
		for _, site := range PairSites(s.pairs) {
			if !slices.Contains(c.UnifiSites, site) {
				return fmt.Errorf("%s names site %q, which is not in UNIFI_SITES (%s)",
					s.name, site, strings.Join(c.UnifiSites, ", "))
			}
		}
	}
	if c.FirewallMode != "zone" {
		return nil
	}
	inbound := settings[0].pairs
	for _, site := range c.UnifiSites {
		if len(PairsForSite(inbound, site)) == 0 {
			return fmt.Errorf("ZONE_PAIRS leaves site %q without a zone pair; add a pair without a site prefix or one starting with %q",
				site, site+"/")
		}
	}
	return nil
}

// UnknownPairSiteWarnings returns a warning for each site prefix that names
// none of sites. Pairs with such a prefix apply to no site. Validate rejects
// them when UNIFI_SITES lists the sites; with UNIFI_SITES_AUTO they can only
// be found once the sites are discovered.
func (c *Config) UnknownPairSiteWarnings(sites []string) []string {
	settings, err := c.pairSettings()
	if err != nil {
		return nil
	}
	var warnings []string
	for _, s := range settings {
		for _, site := range PairSites(s.pairs) {
			if !slices.Contains(sites, site) {
				warnings = append(warnings, fmt.Sprintf("%s names site %q, which is not among the managed sites (%s); its pairs apply to no site",
					s.name, site, strings.Join(sites, ", ")))
			}
		}
	}
	return warnings
}
