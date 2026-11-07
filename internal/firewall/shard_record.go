package firewall

import (
	"errors"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// shardRecordInterval is the longest a flush leaves a shard's group record
// behind its members. The members in a record are read only at startup, to
// restore a shard whose controller list has lost them; a record older than
// the ban database is filtered against it there (see stillBanned), and the
// reconcile that follows adds any ban the record missed. Saving each flush's
// members at once would rewrite up to 10,000 addresses per shard per batch.
const shardRecordInterval = 10 * time.Minute

// saveShardRecords writes the group record of every shard whose members were
// flushed since its record last saved them. Callers hold the manager's
// syncMu, or otherwise know no shard is drained or pruned meanwhile, so a
// record is never written back for a shard that was just deleted.
func (sm *ShardManager) saveShardRecords() error {
	type pendingRecord struct {
		shard *Shard
		rec   storage.GroupRecord
	}
	sm.mu.Lock()
	sm.recordsSavedAt = sm.now()
	var pending []pendingRecord
	for _, shard := range sm.fam.Shards {
		if !shard.recordStale || shard.ID == "" {
			continue
		}
		shard.recordStale = false
		pending = append(pending, pendingRecord{shard: shard, rec: storage.GroupRecord{
			UnifiID: shard.ID, Site: sm.site, Index: shard.Index, Members: shard.IPs.Members(), IPv6: sm.ipv6,
		}})
	}
	sm.mu.Unlock()

	var errs []error
	for _, p := range pending {
		if err := sm.store.SetGroup(cacheKey(sm.site, p.shard.Name), p.rec); err != nil {
			errs = append(errs, fmt.Errorf("save group record %s: %w", p.shard.Name, err))
			sm.mu.Lock()
			p.shard.recordStale = true
			sm.mu.Unlock()
		}
	}
	return errors.Join(errs...)
}

// saveShardRecordsIfDue runs saveShardRecords when shardRecordInterval has
// passed since it last ran.
func (sm *ShardManager) saveShardRecordsIfDue() {
	sm.mu.RLock()
	due := sm.now().Sub(sm.recordsSavedAt) >= shardRecordInterval
	sm.mu.RUnlock()
	if !due {
		return
	}
	if err := sm.saveShardRecords(); err != nil {
		sm.log.Warn().Err(err).Str("site", sm.site).Msg("failed to save shard group records; retrying at the next save")
	}
}

// SaveShardRecords writes the group records whose members lag behind their
// shards, for every loaded site. The daemon calls it on shutdown.
func (m *managerImpl) SaveShardRecords() error {
	m.syncMu.Lock()
	defer m.syncMu.Unlock()
	m.mu.RLock()
	var mgrs []*ShardManager
	for _, byFamily := range []map[string]*ShardManager{m.v4Mgrs, m.v6Mgrs} {
		for _, sm := range byFamily {
			mgrs = append(mgrs, sm)
		}
	}
	m.mu.RUnlock()
	var errs []error
	for _, sm := range mgrs {
		if err := sm.saveShardRecords(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// saveSiteShardRecords writes the lagging group records of one site's shard
// managers. Callers hold syncMu.
func (m *managerImpl) saveSiteShardRecords(site string, v4, v6 *ShardManager) {
	for _, sm := range []*ShardManager{v4, v6} {
		if sm == nil {
			continue
		}
		if err := sm.saveShardRecords(); err != nil {
			m.log.Warn().Err(err).Str("site", site).Msg("failed to save shard group records after reconcile")
		}
	}
}
