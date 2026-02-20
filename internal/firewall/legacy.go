package firewall

import (
	"context"
	"fmt"
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
func (lm *LegacyManager) EnsureRules(ctx context.Context, site string, v4Shards, v6Shards *ShardManager) error {
	if err := lm.ensureRulesForFamily(ctx, site, false, v4Shards); err != nil {
		return err
	}
	if v6Shards != nil {
		if err := lm.ensureRulesForFamily(ctx, site, true, v6Shards); err != nil {
			return err
		}
	}
	return nil
}

func (lm *LegacyManager) ensureRulesForFamily(ctx context.Context, site string, ipv6 bool, sm *ShardManager) error {
	family := Family(ipv6)
	ruleset := lm.cfg.RulesetV4
	indexStart := lm.cfg.RuleIndexStartV4
	if ipv6 {
		ruleset = lm.cfg.RulesetV6
		indexStart = lm.cfg.RuleIndexStartV6
	}

	groupIDs := sm.GroupIDs()

	// Fetch ALL existing rules once before the loop (avoids N redundant GETs).
	existingRules, err := lm.ctrl.ListFirewallRules(ctx, site)
	if err != nil {
		return err
	}
	existingByID := make(map[string]bool, len(existingRules))
	for _, r := range existingRules {
		existingByID[r.ID] = true
	}

	firstCreate := true
	for i, groupID := range groupIDs {
		ruleName, err := lm.namer.RuleName(NameData{Family: family, Index: i, Site: site})
		if err != nil {
			return err
		}

		existing, lookupErr := lm.store.GetPolicy(ruleName)
		if lookupErr != nil {
			return fmt.Errorf("lookup policy %s: %w", ruleName, lookupErr)
		}

		if existing != nil && existing.UnifiID != "" && existingByID[existing.UnifiID] {
			lm.log.Debug().Str("rule", ruleName).Msg("legacy rule already exists")
			continue
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
			return fmt.Errorf("create legacy rule %s: %w", ruleName, err)
		}

		if err := lm.store.SetPolicy(ruleName, storage.PolicyRecord{
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

	existing, lookupErr := lm.store.GetPolicy(ruleName)
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
		return fmt.Errorf("create legacy rule %s: %w", ruleName, err)
	}

	if err := lm.store.SetPolicy(ruleName, storage.PolicyRecord{
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

	existing, lookupErr := lm.store.GetPolicy(ruleName)
	if lookupErr != nil {
		return fmt.Errorf("lookup policy %s: %w", ruleName, lookupErr)
	}

	if existing == nil || existing.UnifiID == "" {
		return nil // Already gone
	}

	if err := lm.ctrl.DeleteFirewallRule(ctx, site, existing.UnifiID); err != nil {
		return fmt.Errorf("delete legacy rule %s: %w", ruleName, err)
	}

	if err := lm.store.DeletePolicy(ruleName); err != nil {
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
	for name, rec := range policies {
		if rec.Site != site || rec.Mode != "legacy" {
			continue
		}
		if err := lm.ctrl.DeleteFirewallRule(ctx, site, rec.UnifiID); err != nil {
			lm.log.Warn().Err(err).Str("rule", name).Msg("failed to delete legacy rule")
			continue
		}
		if err := lm.store.DeletePolicy(name); err != nil {
			lm.log.Warn().Err(err).Str("rule", name).Msg("failed to delete policy from bbolt")
		}
	}
	return nil
}
