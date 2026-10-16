package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// Moving a site to the zone-based firewall (which UniFi Network 11 does for
// every site on upgrade) turns each legacy rule into a zone policy. A rule the
// bouncer created becomes a policy that keeps the rule's name and still blocks
// the shard list, but it carries neither the block policy name nor the cache
// record that zone mode uses to recognise its own policies. Left alone it
// would keep its old zones and settings, and UniFi would refuse to delete the
// list while the policy references it, so pruning or draining that shard
// would fail on every attempt.

// convertedRuleName reports whether name is one the bouncer gave a legacy
// rule: a rule still recorded in the policy cache, or one with the rule name
// prefix. Names of zone-mode block policies and staged copies never match.
func (m *managerImpl) convertedRuleName(name string, legacyNames map[string]bool) bool {
	if prefix := m.namer.PolicyPrefix(); prefix != "" && strings.HasPrefix(name, prefix) {
		return false
	}
	if strings.HasPrefix(name, stagedPolicyPrefix) {
		return false
	}
	if legacyNames[name] {
		return true
	}
	prefix := m.namer.RulePrefix()
	return prefix != "" && strings.HasPrefix(name, prefix)
}

// legacyRuleKeys returns the cache keys of the legacy rules recorded for
// site, keyed by rule name.
func (m *managerImpl) legacyRuleKeys(site string) (map[string]string, error) {
	records, err := m.store.ListPolicies()
	if err != nil {
		return nil, fmt.Errorf("list cached policies: %w", err)
	}
	keys := make(map[string]string)
	for key, rec := range records {
		if rec.Site == site && rec.Mode == "legacy" {
			keys[cacheName(key)] = key
		}
	}
	return keys, nil
}

func nameSet(keys map[string]string) map[string]bool {
	names := make(map[string]bool, len(keys))
	for name := range keys {
		names[name] = true
	}
	return names
}

// managedListIDs returns the controller IDs of the shard lists loaded for site.
func (m *managerImpl) managedListIDs(site string) map[string]bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	ids := make(map[string]bool)
	for _, sm := range []*ShardManager{m.v4Mgrs[site], m.v6Mgrs[site]} {
		if sm == nil {
			continue
		}
		for _, id := range sm.GroupIDs() {
			ids[id] = true
		}
	}
	return ids
}

// convertedRules returns the policies converted from the bouncer's legacy
// rules: a BLOCK or REJECT policy with a legacy rule name whose source is one
// of the lists in ids.
func (m *managerImpl) convertedRules(policies []controller.ZonePolicy, legacyNames, ids map[string]bool) []controller.ZonePolicy {
	var converted []controller.ZonePolicy
	for _, p := range policies {
		if p.Action != "BLOCK" && p.Action != "REJECT" {
			continue
		}
		if !m.convertedRuleName(p.Name, legacyNames) {
			continue
		}
		for _, id := range p.TrafficMatchingListIDs {
			if ids[id] {
				converted = append(converted, p)
				break
			}
		}
	}
	return converted
}

// retireConvertedRules deletes the zone policies converted from the bouncer's
// legacy rules on a zone-mode site, then drops the site's legacy rule records,
// which describe rules the controller no longer has. A converted policy is
// kept while any list it blocks has no enabled block policy of the bouncer's
// own, so retiring it never leaves a banned address unblocked.
func (m *managerImpl) retireConvertedRules(ctx context.Context, site string) error {
	if m.cachedMode(site) != "zone" {
		return nil
	}
	keys, err := m.legacyRuleKeys(site)
	if err != nil {
		return err
	}
	policies, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return fmt.Errorf("list zone policies: %w", err)
	}
	managed := m.managedListIDs(site)
	covered := m.coveredListIDs(site, policies)

	var errs []error
	kept := 0
	for _, p := range m.convertedRules(policies, nameSet(keys), managed) {
		if !allCovered(p.TrafficMatchingListIDs, managed, covered) {
			kept++
			m.log.Warn().Str("site", site).Str("policy", p.Name).
				Msg("keeping a zone policy converted from a legacy rule until the bouncer's own block policy covers its list")
			continue
		}
		if err := m.deleteConvertedRule(ctx, site, p); err != nil {
			errs = append(errs, err)
			kept++
		}
	}
	m.siteMu.Lock()
	m.convertedLeft[site] = kept > 0
	m.siteMu.Unlock()
	if kept > 0 || m.cfg.DryRun {
		return errors.Join(errs...)
	}
	return errors.Join(append(errs, m.forgetLegacyRules(site, keys))...)
}

// retryConvertedRules retires the converted legacy rules that startup had to
// keep, once reconcile has provisioned the block policies they wait for.
// Sites with none left are skipped without an API call.
func (m *managerImpl) retryConvertedRules(ctx context.Context, site string) error {
	m.siteMu.RLock()
	left := m.convertedLeft[site]
	m.siteMu.RUnlock()
	if !left {
		return nil
	}
	return m.retireConvertedRules(ctx, site)
}

// forgetLegacyRules removes the legacy rule records of a site that now runs
// the zone-based firewall.
func (m *managerImpl) forgetLegacyRules(site string, keys map[string]string) error {
	var errs []error
	for name, key := range keys {
		if err := m.store.DeletePolicy(key); err != nil {
			errs = append(errs, fmt.Errorf("remove legacy rule %s from storage: %w", name, err))
		}
	}
	if len(keys) > len(errs) {
		m.log.Info().Str("site", site).Int("rules", len(keys)-len(errs)).
			Msg("removed legacy rule records; the site now uses the zone-based firewall")
	}
	return errors.Join(errs...)
}

// coveredListIDs returns the lists that at least one of the bouncer's own
// enabled block policies on site uses as its source.
func (m *managerImpl) coveredListIDs(site string, policies []controller.ZonePolicy) map[string]bool {
	covered := make(map[string]bool)
	for _, p := range policies {
		if p.Action != "BLOCK" || !p.Enabled {
			continue
		}
		if !m.ownsOrphanReference(site, "zone", p.Name, p.ID, p.Description) &&
			!strings.HasPrefix(p.Name, stagedPolicyPrefix) {
			continue
		}
		for _, id := range p.TrafficMatchingListIDs {
			covered[id] = true
		}
	}
	return covered
}

// allCovered reports whether every managed list in ids is covered.
func allCovered(ids []string, managed, covered map[string]bool) bool {
	for _, id := range ids {
		if managed[id] && !covered[id] {
			return false
		}
	}
	return true
}

// deleteConvertedRulesFor deletes the converted legacy rules that block any
// of the lists in ids, which are about to be deleted, so their coverage no
// longer matters. With dry-run it only logs them.
func (m *managerImpl) deleteConvertedRulesFor(ctx context.Context, site string, ids map[string]bool,
	policies []controller.ZonePolicy,
) error {
	keys, err := m.legacyRuleKeys(site)
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range m.convertedRules(policies, nameSet(keys), ids) {
		if err := m.deleteConvertedRule(ctx, site, p); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// deleteConvertedRulesForList deletes the converted legacy rules that block
// listID before the list itself is pruned or drained. Converted rules only
// remain on a site where retireConvertedRules had to keep some, so other
// sites skip the policy listing.
func (m *managerImpl) deleteConvertedRulesForList(ctx context.Context, site, listID string) error {
	m.siteMu.RLock()
	left := m.convertedLeft[site]
	m.siteMu.RUnlock()
	if !left || listID == "" {
		return nil
	}
	policies, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return fmt.Errorf("list zone policies: %w", err)
	}
	return m.deleteConvertedRulesFor(ctx, site, map[string]bool{listID: true}, policies)
}

// drainConvertedRules deletes, or with dry-run previews, the converted legacy
// rules that block the lists a drain is about to delete.
func (m *managerImpl) drainConvertedRules(ctx context.Context, site string, groupIDs map[string]struct{}) error {
	if m.cachedMode(site) != "zone" || len(groupIDs) == 0 {
		return nil
	}
	policies, err := m.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return fmt.Errorf("list zone policies for site %s: %w", site, err)
	}
	ids := make(map[string]bool, len(groupIDs))
	for id := range groupIDs {
		ids[id] = true
	}
	if err := m.deleteConvertedRulesFor(ctx, site, ids, policies); err != nil {
		return fmt.Errorf("drain converted legacy rules for site %s: %w", site, err)
	}
	return nil
}

func (m *managerImpl) deleteConvertedRule(ctx context.Context, site string, p controller.ZonePolicy) error {
	if m.cfg.DryRun {
		m.log.Info().Str("site", site).Str("policy", p.Name).Str("policy_id", p.ID).
			Msg("[DRY-RUN] would delete zone policy converted from a legacy rule")
		return nil
	}
	if err := m.ctrl.DeleteZonePolicy(ctx, site, p.ID); err != nil {
		var missing *controller.ErrNotFound
		if !errors.As(err, &missing) {
			return fmt.Errorf("delete zone policy %s converted from a legacy rule: %w", p.Name, err)
		}
	}
	m.log.Info().Str("site", site).Str("policy", p.Name).Str("policy_id", p.ID).
		Msg("deleted zone policy converted from a legacy rule")
	return nil
}
