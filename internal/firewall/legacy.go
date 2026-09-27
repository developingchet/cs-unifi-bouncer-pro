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
		for _, ref := range entry.sm.OwnedRefs() {
			name, nameErr := lm.namer.RuleName(NameData{Family: Family(entry.ipv6), Index: ref.Index, Site: site})
			if nameErr == nil {
				expectedRuleNames[name] = true
			}
		}
	}

	// One shard the controller refuses must not leave every later shard
	// without a rule, so failures are collected and the rest carry on.
	failed := lm.ensureRulesForFamily(ctx, site, false, existingByID, v4Shards)
	if v6Shards != nil {
		failed = append(failed, lm.ensureRulesForFamily(ctx, site, true, existingByID, v6Shards)...)
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// API-level orphan sweep: delete owned pre-existing rules that are no longer
	// for an active shard. Uses existingRules (the snapshot
	// taken before any creates above) so newly-created rules are never swept.
	// Guards: description, action, ruleset, and non-empty source group must all
	// match what the bouncer creates — a rule the bouncer couldn't have made is
	// never touched even if its description coincidentally matches.
	for _, r := range existingRules {
		owned, err := lm.ownsRule(site, r)
		if err != nil {
			return err
		}
		if !owned {
			continue
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
	return provisionFailure(failed)
}

// ownsRule reports whether the orphan sweep may treat r as the bouncer's own.
// A rule with the managed description is owned when it carries the managed
// name prefix or is cached by ID. The classic API does not store
// descriptions, so an empty one proves nothing: such a rule is owned only when
// the cache holds its exact ID. Without the cache it is left alone.
func (lm *LegacyManager) ownsRule(site string, r controller.FirewallRule) (bool, error) {
	switch r.Description {
	case lm.cfg.Description:
		if prefix := lm.namer.RulePrefix(); prefix != "" && strings.HasPrefix(r.Name, prefix) {
			return true, nil
		}
	case "":
	default:
		return false, nil
	}
	cached, err := getCachedPolicy(lm.store, site, r.Name)
	if err != nil {
		return false, fmt.Errorf("check rule ownership %s: %w", r.Name, err)
	}
	return cached != nil && cached.UnifiID == r.ID && cached.Site == site && cached.Mode == "legacy", nil
}

// ensureRulesForFamily ensures the drop rule of every active shard in one
// family. It returns one error per shard that failed; those shards are marked
// so the next sync retries them.
func (lm *LegacyManager) ensureRulesForFamily(ctx context.Context, site string, ipv6 bool, existingByID map[string]controller.FirewallRule, sm *ShardManager) []error {
	family := Family(ipv6)
	ruleset := lm.cfg.RulesetV4
	indexStart := lm.cfg.RuleIndexStartV4
	if ipv6 {
		ruleset = lm.cfg.RulesetV6
		indexStart = lm.cfg.RuleIndexStartV6
	}

	var failed []error
	firstCreate := true
	for _, ref := range sm.GroupRefs() {
		if ctx.Err() != nil {
			return failed
		}
		desired, err := lm.desiredRule(site, family, ruleset, indexStart, ref.Index, ref.ID)
		created := false
		if err == nil {
			created, err = lm.ensureRule(ctx, site, desired, existingByID, !firstCreate)
		}
		if err != nil {
			sm.MarkUnprovisioned(ref.Index)
			failed = append(failed, fmt.Errorf("%s shard %d: %w", family, ref.Index, err))
			continue
		}
		if created {
			firstCreate = false
		}
	}
	return failed
}

// desiredRule renders the rule the bouncer maintains for one shard.
func (lm *LegacyManager) desiredRule(site, family, ruleset string, indexStart, shardIdx int, groupID string) (controller.FirewallRule, error) {
	name, err := lm.namer.RuleName(NameData{Family: family, Index: shardIdx, Site: site})
	if err != nil {
		return controller.FirewallRule{}, err
	}
	return controller.FirewallRule{
		Name:                name,
		Enabled:             true,
		RuleIndex:           indexStart + shardIdx,
		Action:              lm.cfg.BlockAction,
		Ruleset:             ruleset,
		Description:         lm.cfg.Description,
		Logging:             lm.cfg.LogDrops,
		Protocol:            "all",
		SrcFirewallGroupIDs: []string{groupID},
	}, nil
}

// ensureRule makes the controller hold desired: it adopts a rule with the same
// name, repairs one whose settings or source group drifted, and otherwise
// creates it. existingByID is the site's current rule list and is kept up to
// date. delay pauses before a create. It reports whether a rule was created.
func (lm *LegacyManager) ensureRule(ctx context.Context, site string, desired controller.FirewallRule,
	existingByID map[string]controller.FirewallRule, delay bool,
) (bool, error) {
	name := desired.Name
	existing, err := getCachedPolicy(lm.store, site, name)
	if err != nil {
		return false, fmt.Errorf("lookup policy %s: %w", name, err)
	}
	id := ""
	if existing != nil && existingByID[existing.UnifiID].ID != "" {
		id = existing.UnifiID
	}
	if id == "" {
		for _, candidate := range existingByID {
			if candidate.Name != name {
				continue
			}
			// The classic API does not store descriptions, so an empty one is
			// the bouncer's own rule; only a different description is foreign.
			if candidate.Description != "" && candidate.Description != lm.cfg.Description {
				return false, fmt.Errorf("rule %s exists with a different description", name)
			}
			id = candidate.ID
			if err := setCachedPolicy(lm.store, site, name, storage.PolicyRecord{UnifiID: id, Site: site, Mode: "legacy"}); err != nil {
				return false, fmt.Errorf("cache existing rule %s: %w", name, err)
			}
			break
		}
	}

	if id != "" {
		current := existingByID[id]
		if current.Name != name {
			return false, fmt.Errorf("cached rule %s points to different API rule %s", name, current.Name)
		}
		return false, lm.repairRule(ctx, site, current, desired, existingByID)
	}

	if delay && lm.cfg.APIWriteDelay > 0 {
		select {
		case <-time.After(lm.cfg.APIWriteDelay):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	created, err := lm.ctrl.CreateFirewallRule(ctx, site, desired)
	if err != nil {
		var conflict *controller.ErrConflict
		if !errors.As(err, &conflict) {
			return false, fmt.Errorf("create legacy rule %s: %w", name, err)
		}
		recovered, found, lookupErr := lm.lookupRuleByName(ctx, site, name)
		if lookupErr != nil || !found {
			return false, fmt.Errorf("create legacy rule %s: %w", name, err)
		}
		lm.log.Warn().Str("rule", name).Str("id", recovered.ID).
			Msg("legacy rule already exists (conflict); recovering it")
		if err := setCachedPolicy(lm.store, site, name, storage.PolicyRecord{UnifiID: recovered.ID, Site: site, Mode: "legacy"}); err != nil {
			return false, fmt.Errorf("cache recovered rule %s: %w", name, err)
		}
		return false, lm.repairRule(ctx, site, recovered, desired, existingByID)
	}
	existingByID[created.ID] = created
	if err := setCachedPolicy(lm.store, site, name, storage.PolicyRecord{UnifiID: created.ID, Site: site, Mode: "legacy"}); err != nil {
		lm.log.Warn().Err(err).Str("rule", name).Msg("failed to cache rule in bbolt")
	}
	lm.log.Info().Str("name", name).Str("id", created.ID).Int("index", desired.RuleIndex).Msg("created legacy firewall rule")
	return true, nil
}

// repairRule updates current to desired's settings when any of them drifted.
func (lm *LegacyManager) repairRule(ctx context.Context, site string, current, desired controller.FirewallRule,
	existingByID map[string]controller.FirewallRule,
) error {
	existingByID[current.ID] = current
	if !legacyRuleNeedsUpdate(current, desired.SrcFirewallGroupIDs[0], desired.RuleIndex, desired.Ruleset, lm.cfg) {
		return nil
	}
	updated := current
	updated.Enabled = desired.Enabled
	updated.RuleIndex = desired.RuleIndex
	updated.Action = desired.Action
	updated.Ruleset = desired.Ruleset
	updated.Description = desired.Description
	updated.Logging = desired.Logging
	updated.Protocol = desired.Protocol
	updated.SrcFirewallGroupIDs = desired.SrcFirewallGroupIDs
	if err := lm.ctrl.UpdateFirewallRule(ctx, site, updated); err != nil {
		return fmt.Errorf("update legacy rule %s: %w", desired.Name, err)
	}
	lm.log.Info().Str("rule", desired.Name).Msg("repaired legacy firewall rule settings")
	existingByID[updated.ID] = updated
	return nil
}

func legacyRuleNeedsUpdate(rule controller.FirewallRule, groupID string, index int, ruleset string, cfg LegacyConfig) bool {
	return !rule.Enabled || rule.RuleIndex != index || rule.Action != cfg.BlockAction ||
		// The classic API does not store descriptions; an empty one is not drift.
		rule.Ruleset != ruleset || (rule.Description != "" && rule.Description != cfg.Description) ||
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

	desired, err := lm.desiredRule(site, family, ruleset, indexStart, shardIdx, groupID)
	if err != nil {
		return err
	}
	rules, err := lm.ctrl.ListFirewallRules(ctx, site)
	if err != nil {
		return fmt.Errorf("list firewall rules: %w", err)
	}
	existingByID := make(map[string]controller.FirewallRule, len(rules))
	for _, r := range rules {
		existingByID[r.ID] = r
	}
	_, err = lm.ensureRule(ctx, site, desired, existingByID, false)
	return err
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

// lookupRuleByName finds a firewall rule by name. It is used for conflict
// recovery: when a create reports the rule already exists, the bouncer adopts
// it instead of creating another.
func (lm *LegacyManager) lookupRuleByName(ctx context.Context, site, name string) (controller.FirewallRule, bool, error) {
	rules, err := lm.ctrl.ListFirewallRules(ctx, site)
	if err != nil {
		return controller.FirewallRule{}, false, fmt.Errorf("list firewall rules: %w", err)
	}
	for _, r := range rules {
		if r.Name == name {
			return r, true, nil
		}
	}
	return controller.FirewallRule{}, false, nil
}
