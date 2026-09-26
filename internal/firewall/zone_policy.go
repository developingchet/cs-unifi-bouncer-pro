package firewall

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// policiesByID lists all zone policies for site and indexes them by ID.
func (zm *ZoneManager) policiesByID(ctx context.Context, site string) (map[string]controller.ZonePolicy, error) {
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return nil, err
	}
	existingByID := make(map[string]controller.ZonePolicy, len(policies))
	for _, p := range policies {
		existingByID[p.ID] = p
	}
	return existingByID, nil
}

// EnsurePolicies idempotently creates zone policies for each shard and zone pair.
func (zm *ZoneManager) EnsurePolicies(ctx context.Context, site string, v4Shards, v6Shards *ShardManager) error {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()
	zoneMap, err := zm.zoneMapForSite(site)
	if err != nil {
		return err
	}

	// Fetch ALL existing policies once for all zone pairs (avoids one GET per pair).
	existingByID, err := zm.policiesByID(ctx, site)
	if err != nil {
		return err
	}

	// Build the set of all policy names expected by the current config so that
	// cleanupOrphanedBlockPolicies can identify policies from removed zone pairs.
	expectedNames := make(map[string]bool)
	for _, pair := range zm.cfg.ZonePairs {
		for _, ipv6 := range []bool{false, true} {
			sm := v4Shards
			if ipv6 {
				sm = v6Shards
			}
			if sm == nil {
				continue
			}
			family := Family(ipv6)
			for _, ref := range sm.OwnedRefs() {
				name, err := zm.namer.PolicyName(NameData{
					Family:  family,
					Index:   ref.Index,
					Site:    site,
					SrcZone: pair.Src,
					DstZone: pair.Dst,
				})
				if err == nil {
					expectedNames[name] = true
				}
			}
		}
	}

	// One shard the controller refuses must not leave every later shard
	// without a policy, so failures are collected and the rest carry on.
	var failed []error
	for _, pair := range zm.cfg.ZonePairs {
		failed = append(failed, zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, false, v4Shards)...)
		if v6Shards != nil {
			failed = append(failed, zm.ensurePoliciesForPair(ctx, site, pair, zoneMap, existingByID, true, v6Shards)...)
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	// Remove any block policies that were managed by this bouncer but whose
	// zone pair has since been removed from ZONE_PAIRS config.
	if err := zm.cleanupOrphanedBlockPolicies(ctx, site, expectedNames, existingByID); err != nil {
		return err
	}
	zm.mu.RLock()
	portIDs := zm.portTMLCache[site]
	zm.mu.RUnlock()
	zm.cleanupOrphanedPortTMLs(ctx, site, portIDs)
	return provisionFailure(failed)
}

// ensurePoliciesForPair ensures the block policy of every active shard for one
// zone pair. It returns one error per shard that failed; those shards are
// marked so the next sync retries them.
func (zm *ZoneManager) ensurePoliciesForPair(ctx context.Context, site string, pair config.ZonePair, zoneMap map[string]string, existingByID map[string]controller.ZonePolicy, ipv6 bool, sm *ShardManager) []error {
	var failed []error
	firstCreate := true
	for _, ref := range sm.GroupRefs() {
		if ctx.Err() != nil {
			return failed
		}
		created, err := zm.ensureShardPolicy(ctx, site, pair, zoneMap, existingByID, ipv6, ref, !firstCreate)
		if err != nil {
			sm.MarkUnprovisioned(ref.Index)
			failed = append(failed, fmt.Errorf("%s shard %d (%s->%s): %w", Family(ipv6), ref.Index, pair.Src, pair.Dst, err))
			continue
		}
		if created {
			firstCreate = false
		}
	}
	return failed
}

func (zm *ZoneManager) ensureShardPolicy(ctx context.Context, site string, pair config.ZonePair, zoneMap map[string]string,
	existingByID map[string]controller.ZonePolicy, ipv6 bool, ref GroupRef, delay bool,
) (bool, error) {
	desired, err := zm.desiredPolicy(site, pair, zoneMap, ipv6, ref.Index, ref.ID)
	if err != nil {
		return false, err
	}
	return zm.ensurePolicy(ctx, site, desired, existingByID, delay)
}

// desiredPolicy renders the block policy the bouncer maintains for one shard
// and zone pair.
func (zm *ZoneManager) desiredPolicy(site string, pair config.ZonePair, zoneMap map[string]string, ipv6 bool, shardIdx int, groupID string) (controller.ZonePolicy, error) {
	name, err := zm.namer.PolicyName(NameData{Family: Family(ipv6), Index: shardIdx, Site: site, SrcZone: pair.Src, DstZone: pair.Dst})
	if err != nil {
		return controller.ZonePolicy{}, err
	}
	if groupID == "" {
		return controller.ZonePolicy{}, fmt.Errorf("shard %d for %s->%s has empty TML ID — cannot create block policy without source filter", shardIdx, pair.Src, pair.Dst)
	}
	ipVersion := "IPV4"
	if ipv6 {
		ipVersion = "IPV6"
	}
	policy := controller.ZonePolicy{
		Name:                   name,
		Enabled:                true,
		Action:                 "BLOCK",
		Description:            zm.cfg.Description,
		SrcZone:                zoneMap[pair.Src],
		DstZone:                zoneMap[pair.Dst],
		IPVersion:              ipVersion,
		TrafficMatchingListIDs: []string{groupID},
		ConnectionStateFilter:  append([]string(nil), zm.cfg.ConnectionStates...),
		LoggingEnabled:         zm.cfg.LogDrops,
	}
	zm.mu.RLock()
	if ids, ok := zm.portTMLCache[site][pair.Src+":"+pair.Dst]; ok {
		policy.SrcPortTMLID = ids.SrcTMLID
		policy.DstPortTMLID = ids.DstTMLID
		policy.DstIPTMLID = pickDstIPTML(ids.DstIPTMLIDs, ipv6)
	}
	zm.mu.RUnlock()
	return policy, nil
}

// ensurePolicy makes the controller hold desired: it adopts a policy with the
// same name, repairs one whose settings drifted, and otherwise creates it.
// existingByID is the site's current policy list and is kept up to date.
// delay pauses before a create. It reports whether a policy was created.
func (zm *ZoneManager) ensurePolicy(ctx context.Context, site string, desired controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy, delay bool,
) (bool, error) {
	name := desired.Name
	id, err := zm.resolvePolicyID(site, name, existingByID)
	if err != nil {
		return false, err
	}
	if id != "" {
		gone, err := zm.repairPolicy(ctx, site, existingByID[id], desired, existingByID)
		if err != nil || !gone {
			return false, err
		}
	}

	if delay && zm.cfg.APIWriteDelay > 0 {
		select {
		case <-time.After(zm.cfg.APIWriteDelay):
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}
	created, err := zm.ctrl.CreateZonePolicy(ctx, site, desired)
	if err != nil {
		var conflict *controller.ErrConflict
		if !errors.As(err, &conflict) {
			return false, fmt.Errorf("create zone policy %s: %w", name, err)
		}
		recovered, found, lookupErr := zm.lookupPolicyByName(ctx, site, name)
		if lookupErr != nil || !found {
			return false, fmt.Errorf("create zone policy %s: %w", name, err)
		}
		zm.log.Warn().Str("policy", name).Str("id", recovered.ID).
			Msg("zone policy already exists (conflict); recovering it")
		if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: recovered.ID, Site: site, Mode: "zone"}); err != nil {
			return false, fmt.Errorf("cache recovered zone policy %s: %w", name, err)
		}
		gone, err := zm.repairPolicy(ctx, site, recovered, desired, existingByID)
		if err == nil && gone {
			err = fmt.Errorf("zone policy %s disappeared during conflict recovery", name)
		}
		return false, err
	}
	existingByID[created.ID] = created
	if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: created.ID, Site: site, Mode: "zone"}); err != nil {
		zm.log.Warn().Err(err).Str("policy", name).Msg("failed to cache policy in bbolt")
	}
	zm.log.Info().Str("name", name).Str("id", created.ID).
		Str("src", desired.SrcZone).Str("dst", desired.DstZone).Msg("created zone policy")
	return true, nil
}

// resolvePolicyID returns the ID of the listed policy named name, preferring
// the cached ID and adopting an uncached policy with the managed description.
// It returns "" when no such policy is listed.
func (zm *ZoneManager) resolvePolicyID(site, name string, existingByID map[string]controller.ZonePolicy) (string, error) {
	cached, err := getCachedPolicy(zm.store, site, name)
	if err != nil {
		return "", fmt.Errorf("lookup policy %s: %w", name, err)
	}
	if cached != nil {
		if p, ok := existingByID[cached.UnifiID]; ok && p.ID != "" {
			if p.Name != name {
				return "", fmt.Errorf("cached policy %s points to different API policy %s", name, p.Name)
			}
			return p.ID, nil
		}
	}
	for _, candidate := range existingByID {
		if candidate.Name != name {
			continue
		}
		if candidate.Description != zm.cfg.Description {
			return "", fmt.Errorf("policy %s exists with a different description", name)
		}
		if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: candidate.ID, Site: site, Mode: "zone"}); err != nil {
			return "", fmt.Errorf("cache existing zone policy %s: %w", name, err)
		}
		return candidate.ID, nil
	}
	return "", nil
}

// repairPolicy brings current in line with desired. It reports gone when the
// controller confirms current no longer exists, so the caller recreates it.
func (zm *ZoneManager) repairPolicy(ctx context.Context, site string, current, desired controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy,
) (bool, error) {
	existingByID[current.ID] = current
	if !needsUpdateZonePolicy(current, desired) {
		zm.log.Debug().Str("policy", desired.Name).Msg("zone policy already exists")
		return false, nil
	}
	zm.log.Info().Str("policy", desired.Name).Msg("zone policy settings drifted; repairing")
	if current.SrcPortTMLID != desired.SrcPortTMLID || current.DstPortTMLID != desired.DstPortTMLID || current.DstIPTMLID != desired.DstIPTMLID {
		return false, zm.replacePolicy(ctx, site, current, desired, existingByID)
	}
	updated := desired
	updated.ID = current.ID
	updated.Index = current.Index
	err := zm.ctrl.UpdateZonePolicy(ctx, site, updated)
	if err == nil {
		existingByID[updated.ID] = updated
		return false, nil
	}
	var nf *controller.ErrNotFound
	if !errors.As(err, &nf) {
		return false, fmt.Errorf("update zone policy %s: %w", desired.Name, err)
	}
	return zm.confirmPolicyGone(ctx, site, current, existingByID)
}

// replacePolicy swaps current for desired when its filter lists change, which
// the controller's PUT endpoint cannot do. The replacement is staged under a
// temporary name first so a failed delete or rename never leaves the shard
// without a block policy.
func (zm *ZoneManager) replacePolicy(ctx context.Context, site string, current, desired controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy,
) error {
	name := desired.Name
	staged, err := zm.stageReplacementPolicy(ctx, site, desired, existingByID)
	if err != nil {
		return fmt.Errorf("stage replacement for zone policy %s: %w", name, err)
	}
	if err := zm.ctrl.DeleteZonePolicy(ctx, site, current.ID); err != nil {
		var nf *controller.ErrNotFound
		if !errors.As(err, &nf) {
			return fmt.Errorf("delete old zone policy %s after staging replacement: %w", name, err)
		}
	}
	delete(existingByID, current.ID)
	renamed := desired
	renamed.ID = staged.ID
	if err := zm.ctrl.UpdateZonePolicy(ctx, site, renamed); err != nil {
		return fmt.Errorf("rename staged zone policy %s: %w", name, err)
	}
	if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: staged.ID, Site: site, Mode: "zone"}); err != nil {
		return fmt.Errorf("cache replacement zone policy %s: %w", name, err)
	}
	existingByID[staged.ID] = renamed
	return nil
}

// confirmPolicyGone handles a 404 on update. A restarting controller answers
// 404 for everything, so the policy counts as deleted only when a fresh listing
// no longer shows it. Otherwise it returns an error and the next pass retries,
// which never creates a duplicate.
func (zm *ZoneManager) confirmPolicyGone(ctx context.Context, site string, current controller.ZonePolicy,
	existingByID map[string]controller.ZonePolicy,
) (bool, error) {
	name := current.Name
	listed, found, err := zm.lookupPolicyByName(ctx, site, name)
	if err != nil {
		return false, fmt.Errorf("zone policy %s returned 404 and could not be re-listed (controller restarting?): %w", name, err)
	}
	if found {
		if listed.ID != current.ID {
			delete(existingByID, current.ID)
			existingByID[listed.ID] = listed
			if err := setCachedPolicy(zm.store, site, name, storage.PolicyRecord{UnifiID: listed.ID, Site: site, Mode: "zone"}); err != nil {
				return false, fmt.Errorf("cache relisted zone policy %s: %w", name, err)
			}
		}
		return false, fmt.Errorf("zone policy %s returned 404 but is still listed; retrying next sync", name)
	}
	zm.log.Warn().Str("policy", name).Str("id", current.ID).Msg("zone policy was deleted outside the bouncer; recreating it")
	delete(existingByID, current.ID)
	if err := deleteCachedPolicy(zm.store, site, name); err != nil {
		return false, fmt.Errorf("clear cached zone policy %s: %w", name, err)
	}
	return true, nil
}

// stageReplacementPolicy provisions the desired filters under a temporary
// managed name before the old policy is removed. A retry reuses an existing
// stage only when it still targets the same group and filters.
func (zm *ZoneManager) stageReplacementPolicy(ctx context.Context, site string, desired controller.ZonePolicy, existingByID map[string]controller.ZonePolicy) (controller.ZonePolicy, error) {
	parts := []string{desired.Name, desired.SrcZone, desired.DstZone, desired.IPVersion,
		desired.TrafficMatchingListIDs[0], desired.SrcPortTMLID, desired.DstPortTMLID, desired.DstIPTMLID}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	stagedName := "crowdsec-policy-stage-" + hex.EncodeToString(digest[:10])
	stagedDesired := desired
	stagedDesired.Name = stagedName
	reuse := func(candidate controller.ZonePolicy) (controller.ZonePolicy, error) {
		if len(candidate.TrafficMatchingListIDs) != 1 || candidate.TrafficMatchingListIDs[0] != desired.TrafficMatchingListIDs[0] ||
			candidate.SrcPortTMLID != desired.SrcPortTMLID || candidate.DstPortTMLID != desired.DstPortTMLID || candidate.DstIPTMLID != desired.DstIPTMLID {
			return controller.ZonePolicy{}, fmt.Errorf("staged policy %s has unexpected group or filter IDs", stagedName)
		}
		if needsUpdateZonePolicy(candidate, desired) {
			stagedDesired.ID = candidate.ID
			if err := zm.ctrl.UpdateZonePolicy(ctx, site, stagedDesired); err != nil {
				return controller.ZonePolicy{}, fmt.Errorf("repair staged policy %s: %w", stagedName, err)
			}
		}
		return candidate, nil
	}
	for _, candidate := range existingByID {
		if candidate.Name == stagedName {
			return reuse(candidate)
		}
	}
	staged, err := zm.ctrl.CreateZonePolicy(ctx, site, stagedDesired)
	if err == nil {
		return staged, nil
	}
	var conflict *controller.ErrConflict
	if !errors.As(err, &conflict) {
		return controller.ZonePolicy{}, fmt.Errorf("create staged policy %s: %w", stagedName, err)
	}
	policies, listErr := zm.ctrl.ListZonePolicies(ctx, site)
	if listErr != nil {
		return controller.ZonePolicy{}, fmt.Errorf("find staged policy %s: %w", stagedName, listErr)
	}
	for _, candidate := range policies {
		if candidate.Name == stagedName {
			return reuse(candidate)
		}
	}
	return controller.ZonePolicy{}, fmt.Errorf("staged policy %s conflicted but was not found", stagedName)
}

// EnsurePoliciesForShard ensures the zone policies for a single new shard
// across all configured zone pairs. Called when a new shard overflows
// mid-operation.
func (zm *ZoneManager) EnsurePoliciesForShard(ctx context.Context, site, groupID string, ipv6 bool, shardIdx int) error {
	zm.opMu.Lock()
	defer zm.opMu.Unlock()

	zoneMap, err := zm.zoneMapForSite(site)
	if err != nil {
		return err
	}

	existingByID, err := zm.policiesByID(ctx, site)
	if err != nil {
		return fmt.Errorf("list policies for shard %d: %w", shardIdx, err)
	}

	firstCreate := true
	for _, pair := range zm.cfg.ZonePairs {
		desired, err := zm.desiredPolicy(site, pair, zoneMap, ipv6, shardIdx, groupID)
		if err != nil {
			return err
		}
		created, err := zm.ensurePolicy(ctx, site, desired, existingByID, !firstCreate)
		if err != nil {
			return err
		}
		if created {
			firstCreate = false
		}
	}
	return nil
}

// needsUpdateZonePolicy reports whether current differs from desired in any
// setting the bouncer manages: enabled state, action, zones, IP version,
// description, connection states, logging, the source list, and the port and
// destination-IP filter lists.
func needsUpdateZonePolicy(current, desired controller.ZonePolicy) bool {
	return current.Enabled != desired.Enabled ||
		current.Action != desired.Action ||
		current.SrcZone != desired.SrcZone ||
		current.DstZone != desired.DstZone ||
		current.IPVersion != desired.IPVersion ||
		current.Description != desired.Description ||
		current.LoggingEnabled != desired.LoggingEnabled ||
		!sameConnectionStates(current.ConnectionStateFilter, desired.ConnectionStateFilter) ||
		!slices.Equal(current.TrafficMatchingListIDs, desired.TrafficMatchingListIDs) ||
		current.SrcPortTMLID != desired.SrcPortTMLID ||
		current.DstPortTMLID != desired.DstPortTMLID ||
		current.DstIPTMLID != desired.DstIPTMLID
}

func sameConnectionStates(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, state := range a {
		counts[state]++
	}
	for _, state := range b {
		counts[state]--
		if counts[state] < 0 {
			return false
		}
	}
	return true
}

// lookupPolicyByName finds a zone policy by name. It is used for conflict
// recovery and to confirm a 404 before recreating a policy.
func (zm *ZoneManager) lookupPolicyByName(ctx context.Context, site, name string) (controller.ZonePolicy, bool, error) {
	policies, err := zm.ctrl.ListZonePolicies(ctx, site)
	if err != nil {
		return controller.ZonePolicy{}, false, fmt.Errorf("list zone policies: %w", err)
	}
	for _, p := range policies {
		if p.Name == name {
			return p, true, nil
		}
	}
	return controller.ZonePolicy{}, false, nil
}
