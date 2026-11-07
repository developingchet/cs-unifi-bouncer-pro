package firewall

import "time"

// ShardEvents receives shard failures that leave bans unenforced, so the
// daemon can pass them on (as webhooks) without this package depending on
// how. A nil function is skipped. The functions are called from shard syncs
// and must return quickly.
type ShardEvents struct {
	// CreateFailed is called after each failed attempt to create a shard
	// object on the controller.
	CreateFailed func(ShardCreateFailure)
	// EntryRefused is called when the controller refuses a ban entry and it
	// is left out of its shard.
	EntryRefused func(RefusedEntry)
}

// ShardCreateFailure describes a shard whose controller object could not be
// created.
type ShardCreateFailure struct {
	Site                string
	Family              string
	Shard               string
	UnsyncedIPs         int
	ConsecutiveFailures int
	RetryIn             time.Duration
}

// RefusedEntry describes a ban entry the controller refused.
type RefusedEntry struct {
	Site    string
	Family  string
	Shard   string
	Entry   string
	RetryIn time.Duration
}

func (e ShardEvents) createFailed(f ShardCreateFailure) {
	if e.CreateFailed != nil {
		e.CreateFailed(f)
	}
}

func (e ShardEvents) entryRefused(r RefusedEntry) {
	if e.EntryRefused != nil {
		e.EntryRefused(r)
	}
}

// SetEvents sets the receiver of this shard manager's failure events.
func (sm *ShardManager) SetEvents(events ShardEvents) {
	sm.events = events
}
