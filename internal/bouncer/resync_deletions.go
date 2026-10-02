package bouncer

import "sync"

// resyncDeletions records the decisions the stream deletes while a resync is
// in flight. The resync's snapshot of the active decisions is taken when the
// LAPI answers, so a decision deleted after that moment is still in it; the
// record lets the resync leave such a decision unapplied instead of bringing
// back a ban CrowdSec has already lifted.
type resyncDeletions struct {
	mu      sync.Mutex
	active  bool
	deleted map[string]struct{}
}

// begin starts recording deletions. It must run before the snapshot is
// requested.
func (r *resyncDeletions) begin() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = true
	r.deleted = make(map[string]struct{})
}

// end stops recording and forgets what was recorded.
func (r *resyncDeletions) end() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.active = false
	r.deleted = nil
}

// noteDeleted records that the stream deleted the decision with this source.
func (r *resyncDeletions) noteDeleted(source string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active {
		r.deleted[source] = struct{}{}
	}
}

// wasDeleted reports whether the decision was deleted since begin.
func (r *resyncDeletions) wasDeleted(source string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.deleted[source]
	return ok
}
