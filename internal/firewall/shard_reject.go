package firewall

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

const (
	// maxRejectedPerSync bounds how many refused members one shard write drops
	// and retries before giving up until the next tick.
	maxRejectedPerSync = 10

	// maxRefusedPerShard bounds how many members a shard leaves out at once.
	// Every member is a canonical address or prefix, so a controller that
	// refuses more than a handful is faulty or is not the controller, and the
	// write fails instead of dropping more bans.
	maxRefusedPerShard = 10

	// refusalHold is how long a refused member stays out of its shard. When
	// it lapses, drift detection sees the member missing and the next write
	// offers it again, so a refusal that was not genuine does not disable a
	// ban for the life of the process.
	refusalHold = time.Hour
)

// putAcceptedMembers writes ips to the shard, leaving out members the
// controller has refused. When a write fails because the controller names a
// member it does not accept (the classic API's FirewallGroupInvalidArgs), that
// member is held out of the shard for refusalHold and the write is retried
// without it. Without this, one unacceptable entry fails every write of its
// shard, and the failures open the circuit breaker and stop every other ban.
// It returns the members actually written.
func (sm *ShardManager) putAcceptedMembers(ctx context.Context, shard *Shard, ips []string) ([]string, int, error) {
	members := sm.withoutRejected(shard, ips)
	for attempt := 0; ; attempt++ {
		sent, err := sm.putShardMembers(ctx, shard, members)
		var bad *controller.ErrBadRequest
		if err == nil || !errors.As(err, &bad) || attempt >= maxRejectedPerSync || !slices.Contains(members, bad.Arg) {
			return members, sent, err
		}
		if !sm.rejectMember(shard, bad.Arg) {
			return members, sent, fmt.Errorf("controller refused %d members of shard %s; not leaving out more: %w",
				maxRefusedPerShard+1, shard.Name, err)
		}
		members = slices.DeleteFunc(slices.Clone(members), func(m string) bool { return m == bad.Arg })
	}
}

// withoutRejected returns ips minus the shard's refused members, forgetting
// refusals that have lapsed or whose member is no longer in the shard.
func (sm *ShardManager) withoutRejected(shard *Shard, ips []string) []string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(shard.rejected) == 0 {
		return ips
	}
	now := sm.now()
	kept := make(map[string]time.Time, len(shard.rejected))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if until, bad := shard.rejected[ip]; bad && now.Before(until) {
			kept[ip] = until
			continue
		}
		out = append(out, ip)
	}
	if len(kept) != len(shard.rejected) {
		shard.rejected = kept
		sm.updateMetricsLocked()
	}
	return out
}

// refusedMembers returns the members the controller has refused for shard
// whose refusal has not lapsed.
func (sm *ShardManager) refusedMembers(shard *Shard) []string {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	now := sm.now()
	refused := make([]string, 0, len(shard.rejected))
	for ip, until := range shard.rejected {
		if now.Before(until) {
			refused = append(refused, ip)
		}
	}
	return refused
}

// isRefused reports whether member is held out of shard at now. Callers hold sm.mu.
func (s *Shard) isRefused(member string, now time.Time) bool {
	until, ok := s.rejected[member]
	return ok && now.Before(until)
}

// refusedCount is the number of members held out of shard at now. Callers hold sm.mu.
func (s *Shard) refusedCount(now time.Time) int {
	n := 0
	for _, until := range s.rejected {
		if now.Before(until) {
			n++
		}
	}
	return n
}

// rejectMember holds member out of shard for refusalHold. It refuses, and
// returns false, when the shard already holds maxRefusedPerShard members out.
func (sm *ShardManager) rejectMember(shard *Shard, member string) bool {
	sm.mu.Lock()
	now := sm.now()
	if shard.refusedCount(now) >= maxRefusedPerShard {
		sm.mu.Unlock()
		sm.log.Error().Str("shard", shard.Name).Str("member", member).Str("site", sm.site).
			Int("limit", maxRefusedPerShard).
			Msg("controller refused more ban entries than a shard leaves out; failing the write instead")
		return false
	}
	if shard.rejected == nil {
		shard.rejected = make(map[string]time.Time)
	}
	shard.rejected[member] = now.Add(refusalHold)
	sm.updateMetricsLocked()
	sm.mu.Unlock()
	sm.log.Error().Str("shard", shard.Name).Str("member", member).Str("site", sm.site).
		Dur("retry_in", refusalHold).
		Msg("controller refused a ban entry; it is left out of the shard and not enforced until it is retried")
	sm.events.entryRefused(RefusedEntry{
		Site: sm.site, Family: shard.Family, Shard: shard.Name, Entry: member, RetryIn: refusalHold,
	})
	return true
}
