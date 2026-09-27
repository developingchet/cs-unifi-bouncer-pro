package firewall

import (
	"context"
	"errors"
	"slices"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// maxRejectedPerSync bounds how many refused members one shard write drops
// and retries before giving up until the next tick.
const maxRejectedPerSync = 10

// putAcceptedMembers writes ips to the shard, leaving out members the
// controller has refused. When a write fails because the controller names a
// member it does not accept (the classic API's FirewallGroupInvalidArgs), that
// member is quarantined for this shard and the write is retried without it.
// Without this, one unacceptable entry fails every write of its shard, and the
// failures open the circuit breaker and stop every other ban. It returns the
// members actually written.
func (sm *ShardManager) putAcceptedMembers(ctx context.Context, shard *Shard, ips []string) ([]string, int, error) {
	members := sm.withoutRejected(shard, ips)
	for attempt := 0; ; attempt++ {
		sent, err := sm.putShardMembers(ctx, shard, members)
		var bad *controller.ErrBadRequest
		if err == nil || !errors.As(err, &bad) || attempt >= maxRejectedPerSync || !slices.Contains(members, bad.Arg) {
			return members, sent, err
		}
		sm.rejectMember(shard, bad.Arg)
		members = slices.DeleteFunc(slices.Clone(members), func(m string) bool { return m == bad.Arg })
	}
}

// withoutRejected returns ips minus the shard's rejected members, forgetting
// rejections for members that are no longer in the shard.
func (sm *ShardManager) withoutRejected(shard *Shard, ips []string) []string {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if len(shard.rejected) == 0 {
		return ips
	}
	kept := make(map[string]struct{}, len(shard.rejected))
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if _, bad := shard.rejected[ip]; bad {
			kept[ip] = struct{}{}
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

func (sm *ShardManager) rejectMember(shard *Shard, member string) {
	sm.mu.Lock()
	if shard.rejected == nil {
		shard.rejected = make(map[string]struct{})
	}
	shard.rejected[member] = struct{}{}
	sm.updateMetricsLocked()
	sm.mu.Unlock()
	sm.log.Error().Str("shard", shard.Name).Str("member", member).Str("site", sm.site).
		Msg("controller refused a ban entry; it is left out of the shard and not enforced")
}
