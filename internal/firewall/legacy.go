package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// LegacyConfig holds configuration for WAN_IN / WANv6_IN legacy firewall mode.
type LegacyConfig struct {
	RuleIndexStartV4 int
	RuleIndexStartV6 int
	RulesetV4        string
	RulesetV6        string
	BlockAction      string // "drop" or "reject"
	LogDrops         bool
	Description      string
	APIWriteDelay    time.Duration
}

// LegacyManager manages legacy WAN_IN drop rules pointing at managed groups.
type LegacyManager struct {
	cfg   LegacyConfig
	namer *Namer
	ctrl  controller.Controller
	store storage.Store
	log   zerolog.Logger
}

// NewLegacyManager constructs a LegacyManager.
func NewLegacyManager(cfg LegacyConfig, namer *Namer, ctrl controller.Controller, store storage.Store, log zerolog.Logger) *LegacyManager {
	return &LegacyManager{cfg: cfg, namer: namer, ctrl: ctrl, store: store, log: log}
}

// EnsureRules idempotently creates drop rules for each group shard.
// If the rule already exists (from bbolt policy cache), it verifies and updates it.
// After ensuring active shards, it sweeps for orphaned rules with the managed
// description and ownership evidence from the cache or static name prefix.
// This catches rules left by removed shards, mode switches, or a wiped bbolt.
func (lm *LegacyManager) EnsureRules(ctx context.Context, site string, v4Shards, v6Shards *ShardManager) error {
	// Fetch ALL existing rules once for all families (avoids one GET per family).
	existingRules, err := lm.ctrl.ListFirewallRules(ctx, site)
	if err != nil {
		return err
	}
	existingByID := make(map[string]controller.FirewallRule, len(existingRules))
	for _, r := range existingRules {
		existingByID[r.ID] = r
	}

	// Build the set of rule names expected by the current config before ensuring,
	// so the orphan sweep below can compare against a stable snapshot.
	expectedRuleNames := make(map[string]bool)
	for _, entry := range []struct {
		sm   *ShardManager
		ipv6 bool
	}{{v4Shards, false}, {v6Shards, true}} {
		if entry.sm == nil {
			continue
		}
		for _, ref := range entry.sm.GroupRefs() {
			name, nameErr := lm.namer.RuleName(NameData{Family: Family(entry.ipv6), Index: ref.Index, Site: site})
			if nameErr == nil {
				expectedRuleNames[name] = true
			}
		}
	}

	if err := lm.ensureRulesForFamily(ctx, site, false, existingByID, v4Shards); err != nil {
		return err
	}
	if v6Shards != nil {
		if err := lm.ensureRulesForFamily(ctx, site, true, existingByID, v6Shards); err != nil {
			return err
		}
	}

	// API-level orphan sweep: delete owned pre-existing rules that are no longer
	// for an active shard. Uses existingRules (the snapshot
	// taken before any creates above) so newly-created rules are never swept.
	// Guards: description, action, ruleset, and non-empty source group must all
	// match what the bouncer creates — a rule the bouncer couldn't have made is
	// never touched even if its description coincidentally matches.
	for _, r := range existingRules {
		if r.Description != lm.cfg.Description {
			continue
		}
		if prefix := lm.namer.RulePrefix(); prefix == "" || !strings.HasPrefix(r.Name, prefix) {
			cached, err := getCachedPolicy(lm.store, site, r.Name)
			if err != nil {
				return fmt.Errorf("check rule ownership %s: %w", r.Name, err)
			}
			if cached == nil || cached.UnifiID != r.ID || cached.Site != site || cached.Mode != "legacy" {
				continue
			}
		}
		if r.Action != lm.cfg.BlockAction {
			continue // the bouncer only creates rules with the configured block action
		}
		if r.Ruleset != lm.cfg.RulesetV4 && r.Ruleset != lm.cfg.RulesetV6 {
			continue // the bouncer only creates rules in the configured rulesets
		}
		if len(r.SrcFirewallGroupIDs) == 0 {
			continue // every bouncer rule has exactly one source group
		}
		if expectedRuleNames[r.Name] {
			continue
		}
		if delErr := lm.ctrl.DeleteFirewallRule(ctx, site, r.ID); delErr != nil {
			lm.log.Warn().Err(delErr).Str("rule", r.Name).Str("site", site).
				Msg("failed to delete API-orphaned legacy rule")
			continue
		} else {
			lm.log.Info().Str("rule", r.Name).Str("site", site).
				Msg("deleted API-orphaned legacy rule (matches managed description, not in current config)")
		}
		if err := deleteCachedPolicy(lm.store, site, r.Name); err != nil {
			return fmt.Errorf("remove orphaned rule %s from cache: %w", r.Name, err)
		}
	}
	return nil
}

func (lm *LegacyManager) ensureRulesForFamily(ctx context.Context, site string, ipv6 bool, existingByID map[string]controller.FirewallRule, sm *ShardManager) error {
	family := Family(ipv6)
	ruleset := lm.cfg.RulesetV4
	indexStart := lm.cfg.RuleIndexStartV4
	if ipv6 {
		ruleset = lm.cfg.RulesetV6
		indexStart = lm.cfg.RuleIndexStartV6
	}

	groupRefs := sm.GroupRefs()

	firstCreate := true
	for _, ref := range groupRefs {
		i, groupID := ref.Index, ref.ID
		ruleName, err := lm.namer.RuleName(NameData{Family: family, Index: i, Site: site})
		if err != nil {
			return err
		}

		existing, lookupErr := getCachedPolicy(lm.store, site, ruleName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", ruleName, lookupErr)
		}
		if existing == nil || existing.UnifiID == "" || existingByID[existing.UnifiID].ID == "" {
			for _, candidate := range existingByID {
				if candidate.Name != ruleName {
					continue
				}
				if candidate.Description != lm.cfg.Description {
					return fmt.Errorf("rule %s exists with a different description", ruleName)
				}
				if err := setCachedPolicy(lm.store, site, ruleName, storage.PolicyRecord{UnifiID: candidate.ID, Site: site, Mode: "legacy"}); err != nil {
					return fmt.Errorf("cache existing rule %s: %w", ruleName, err)
				}
				existing = &storage.PolicyRecord{UnifiID: candidate.ID, Site: site, Mode: "legacy"}
				break
			}
		}

		if existing != nil && existing.UnifiID != "" {
			if apiRule, found := existingByID[existing.UnifiID]; found {
				if apiRule.Name != ruleName {
					return fmt.Errorf("cached rule %s points to different API rule %s", ruleName, apiRule.Name)
				}
				if legacyRuleNeedsUpdate(apiRule, groupID, indexStart+i, ruleset, lm.cfg) {
					apiRule.Enabled = true
					apiRule.RuleIndex = indexStart + i
					apiRule.Action = lm.cfg.BlockAction
					apiRule.Ruleset = ruleset
					apiRule.Description = lm.cfg.Description
					apiRule.Logging = lm.cfg.LogDrops
					apiRule.Protocol = "all"
					apiRule.SrcFirewallGroupIDs = []string{groupID}
					if err := lm.ctrl.UpdateFirewallRule(ctx, site, apiRule); err != nil {
						return fmt.Errorf("update legacy rule %s: %w", ruleName, err)
					}
					existingByID[apiRule.ID] = apiRule
				}
				continue
			}
		}

		// Apply delay between consecutive creates (not before the first one)
		if !firstCreate && lm.cfg.APIWriteDelay > 0 {
			select {
			case <-time.After(lm.cfg.APIWriteDelay):
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		firstCreate = false

		// Create the rule
		rule := controller.FirewallRule{
			Name:                ruleName,
			Enabled:             true,
			RuleIndex:           indexStart + i,
			Action:              lm.cfg.BlockAction,
			Ruleset:             ruleset,
			Description:         lm.cfg.Description,
			Logging:             lm.cfg.LogDrops,
			Protocol:            "all",
			SrcFirewallGroupIDs: []string{groupID},
		}

		created, err := lm.ctrl.CreateFirewallRule(ctx, site, rule)
		if err != nil {
			var conflict *controller.ErrConflict
			if errors.As(err, &conflict) {
				if id := lm.findExistingRuleByName(ctx, site, ruleName); id != "" {
					lm.log.Warn().Str("rule", ruleName).Str("id", id).
						Msg("legacy rule already exists (409 conflict); recovering existing ID")
					if storeErr := setCachedPolicy(lm.store, site, ruleName, storage.PolicyRecord{UnifiID: id, Site: site, Mode: "legacy"}); storeErr != nil {
						lm.log.Warn().Err(storeErr).Str("rule", ruleName).Msg("failed to cache recovered rule in bbolt")
					}
					existingByID[id] = controller.FirewallRule{ID: id, Name: ruleName}
					continue
				}
			}
			return fmt.Errorf("create legacy rule %s: %w", ruleName, err)
		}
		existingByID[created.ID] = created

		if err := setCachedPolicy(lm.store, site, ruleName, storage.PolicyRecord{
			UnifiID: created.ID,
			Site:    site,
			Mode:    "legacy",
		}); err != nil {
			lm.log.Warn().Err(err).Str("rule", ruleName).Msg("failed to cache rule in bbolt")
		}

		lm.log.Info().Str("name", ruleName).Str("id", created.ID).Int("index", rule.RuleIndex).Msg("created legacy firewall rule")
	}
	return nil
}

func legacyRuleNeedsUpdate(rule controller.FirewallRule, groupID string, index int, ruleset string, cfg LegacyConfig) bool {
	return !rule.Enabled || rule.RuleIndex != index || rule.Action != cfg.BlockAction ||
		rule.Ruleset != ruleset || rule.Description != cfg.Description ||
		rule.Logging != cfg.LogDrops || rule.Protocol != "all" ||
		len(rule.SrcFirewallGroupIDs) != 1 || rule.SrcFirewallGroupIDs[0] != groupID
}

// EnsureRuleForShard creates the firewall rule for a single new shard if it doesn't already exist.
// Called when a new shard overflows mid-operation.
func (lm *LegacyManager) EnsureRuleForShard(ctx context.Context, site, groupID string, ipv6 bool, shardIdx int) error {
	family := Family(ipv6)
	ruleset := lm.cfg.RulesetV4
	indexStart := lm.cfg.RuleIndexStartV4
	if ipv6 {
		ruleset = lm.cfg.RulesetV6
		indexStart = lm.cfg.RuleIndexStartV6
	}

	ruleName, err := lm.namer.RuleName(NameData{Family: family, Index: shardIdx, Site: site})
	if err != nil {
		return err
	}

	existing, lookupErr := getCachedPolicy(lm.store, site, ruleName)
	if lookupErr != nil {
		return fmt.Errorf("lookup policy %s: %w", ruleName, lookupErr)
	}

	if existing != nil && existing.UnifiID != "" {
		// Verify it still exists in the API
		rules, apiErr := lm.ctrl.ListFirewallRules(ctx, site)
		if apiErr != nil {
			return apiErr
		}
		for _, r := range rules {
			if r.ID == existing.UnifiID {
				lm.log.Debug().Str("rule", ruleName).Msg("legacy rule already exists for new shard")
				return nil
			}
		}
	}

	rule := controller.FirewallRule{
		Name:                ruleName,
		Enabled:             true,
		RuleIndex:           indexStart + shardIdx,
		Action:              lm.cfg.BlockAction,
		Ruleset:             ruleset,
		Description:         lm.cfg.Description,
		Logging:             lm.cfg.LogDrops,
		Protocol:            "all",
		SrcFirewallGroupIDs: []string{groupID},
	}

	created, err := lm.ctrl.CreateFirewallRule(ctx, site, rule)
	if err != nil {
		var conflict *controller.ErrConflict
		if errors.As(err, &conflict) {
			if id := lm.findExistingRuleByName(ctx, site, ruleName); id != "" {
				lm.log.Warn().Str("rule", ruleName).Str("id", id).
					Msg("legacy rule already exists (409 conflict); recovering existing ID")
				if storeErr := setCachedPolicy(lm.store, site, ruleName, storage.PolicyRecord{UnifiID: id, Site: site, Mode: "legacy"}); storeErr != nil {
					lm.log.Warn().Err(storeErr).Str("rule", ruleName).Msg("failed to cache recovered rule in bbolt")
				}
				lm.log.Info().Str("name", ruleName).Str("id", id).
					Msg("recovered legacy firewall rule for new shard")
				return nil
			}
		}
		return fmt.Errorf("create legacy rule %s: %w", ruleName, err)
	}

	if err := setCachedPolicy(lm.store, site, ruleName, storage.PolicyRecord{
		UnifiID: created.ID,
		Site:    site,
		Mode:    "legacy",
	}); err != nil {
		lm.log.Warn().Err(err).Str("rule", ruleName).Msg("failed to cache rule in bbolt")
	}

	lm.log.Info().Str("name", ruleName).Str("id", created.ID).Int("index", rule.RuleIndex).
		Msg("created legacy firewall rule for new shard")
	return nil
}

// DeleteRuleForShard deletes the firewall rule for the given shard index.
// Called during shard pruning.
func (lm *LegacyManager) DeleteRuleForShard(ctx context.Context, site string, ipv6 bool, shardIdx int) error {
	family := Family(ipv6)

	ruleName, err := lm.namer.RuleName(NameData{Family: family, Index: shardIdx, Site: site})
	if err != nil {
		return err
	}

	existing, lookupErr := getCachedPolicy(lm.store, site, ruleName)
	if lookupErr != nil {
		return fmt.Errorf("lookup policy %s: %w", ruleName, lookupErr)
	}

	if existing == nil || existing.UnifiID == "" {
		return nil // Already gone
	}

	if err := lm.ctrl.DeleteFirewallRule(ctx, site, existing.UnifiID); err != nil {
		return fmt.Errorf("delete legacy rule %s: %w", ruleName, err)
	}

	if err := deleteCachedPolicy(lm.store, site, ruleName); err != nil {
		lm.log.Warn().Err(err).Str("rule", ruleName).Msg("failed to delete policy from bbolt")
	}

	lm.log.Info().Str("name", ruleName).Msg("deleted legacy firewall rule for pruned shard")
	return nil
}

// DeleteRules removes all managed legacy rules for a site.
func (lm *LegacyManager) DeleteRules(ctx context.Context, site string) error {
	policies, err := lm.store.ListPolicies()
	if err != nil {
		return err
	}
	var errs []error
	for name, rec := range policies {
		if rec.Site != site || rec.Mode != "legacy" {
			continue
		}
		if err := lm.ctrl.DeleteFirewallRule(ctx, site, rec.UnifiID); err != nil {
			var missing *controller.ErrNotFound
			if !errors.As(err, &missing) {
				errs = append(errs, fmt.Errorf("delete legacy rule %s: %w", name, err))
				continue
			}
		}
		if err := lm.store.DeletePolicy(name); err != nil {
			errs = append(errs, fmt.Errorf("remove legacy rule %s from storage: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

// findExistingRuleByName queries the UniFi API for a firewall rule with the given name.
// Used for 409 conflict recovery: if CreateFirewallRule returns ErrConflict, the rule
// already exists and we can recover its ID to continue without re-creating.
func (lm *LegacyManager) findExistingRuleByName(ctx context.Context, site, name string) string {
	rules, err := lm.ctrl.ListFirewallRules(ctx, site)
	if err != nil {
		return ""
	}
	for _, r := range rules {
		if r.Name == name {
			return r.ID
		}
	}
	return ""
}
