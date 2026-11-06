package main

import (
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/rs/zerolog"
)

// logSitePairs warns about site prefixes in the zone pair settings that name
// none of sites and about sites whose pairs cannot enforce IPv6 bans, then
// logs the zone pairs each site uses.
func logSitePairs(cfg *config.Config, sites []string, log zerolog.Logger) {
	for _, w := range cfg.UnknownPairSiteWarnings(sites) {
		log.Warn().Msg(w)
	}
	if cfg.FirewallMode == "legacy" {
		return
	}
	for _, w := range cfg.UnenforcedIPv6Warnings(sites) {
		log.Warn().Msg(w)
	}
	// Validate has parsed each setting already.
	inbound, _ := cfg.ParseZonePairs()
	egress, _ := cfg.ParseEgressZonePairs()
	var cloudflare []config.ZonePair
	if cfg.CloudflareWhitelistEnabled {
		cloudflare, _ = cfg.ParseCloudflareZonePairs()
	}
	for _, site := range sites {
		event := log.Info().Str("site", site).
			Strs("zone_pairs", pairStrings(config.PairsForSite(inbound, site)))
		if len(egress) > 0 {
			event = event.Strs("egress_zone_pairs", pairStrings(config.PairsForSite(egress, site)))
		}
		if len(cloudflare) > 0 {
			event = event.Strs("cloudflare_zone_pairs", pairStrings(config.PairsForSite(cloudflare, site)))
		}
		event.Msg("zone pairs for site")
	}
}

func pairStrings(pairs []config.ZonePair) []string {
	out := make([]string, 0, len(pairs))
	for _, p := range pairs {
		out = append(out, p.String())
	}
	return out
}

// zonePairSummary lists pairs as "src->dst, ...", or "0 pair(s)" when empty.
func zonePairSummary(pairs []config.ZonePair) string {
	if len(pairs) == 0 {
		return "0 pair(s)"
	}
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts = append(parts, p.Src+"->"+p.Dst)
	}
	return strings.Join(parts, ", ")
}

// zonePairRows renders one zone pair setting as validate output rows. A
// setting without site prefixes is a single row. Otherwise each site in
// UNIFI_SITES gets a "name[site]" row with the pairs it uses. With
// UNIFI_SITES_AUTO the sites are not known yet, so each prefixed site gets a
// row and "name[*]" holds the unprefixed pairs every other site uses.
func zonePairRows(name string, pairs []config.ZonePair, cfg *config.Config) [][2]string {
	prefixed := config.PairSites(pairs)
	if len(prefixed) == 0 {
		return [][2]string{{name, zonePairSummary(pairs)}}
	}
	sites := cfg.UnifiSites
	if cfg.UnifiSitesAuto {
		sites = prefixed
	}
	rows := make([][2]string, 0, len(sites)+1)
	for _, site := range sites {
		rows = append(rows, [2]string{name + "[" + site + "]", zonePairSummary(config.PairsForSite(pairs, site))})
	}
	if cfg.UnifiSitesAuto {
		var shared []config.ZonePair
		for _, p := range pairs {
			if p.Site == "" {
				shared = append(shared, p)
			}
		}
		rows = append(rows, [2]string{name + "[*]", zonePairSummary(shared)})
	}
	return rows
}
