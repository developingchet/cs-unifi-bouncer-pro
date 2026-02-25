package firewall

import "sync"

// IPSet is a goroutine-safe set of IP/CIDR strings for a single shard.
// It tracks whether the set has changed since the last successful sync.
type IPSet struct {
	mu          sync.RWMutex
	members     map[string]struct{}
	dirty       bool
	lastFlushed map[string]struct{} // snapshot of members at the last successful PUT
}

// NewIPSet creates an empty IPSet.
func NewIPSet() *IPSet {
	return &IPSet{members: make(map[string]struct{})}
}

// Add adds ip to the set and marks it dirty. Returns true if ip was not already present.
func (s *IPSet) Add(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.members[ip]; exists {
		return false
	}
	s.members[ip] = struct{}{}
	s.dirty = true
	return true
}

// Remove removes ip from the set and marks it dirty. Returns true if ip was present.
func (s *IPSet) Remove(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.members[ip]; !exists {
		return false
	}
	delete(s.members, ip)
	s.dirty = true
	return true
}

// Contains returns true if ip is in the set. Does not affect the dirty flag.
func (s *IPSet) Contains(ip string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.members[ip]
	return ok
}

// Len returns the current number of members.
func (s *IPSet) Len() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.members)
}

// Capacity returns how many more IPs can fit given the shard limit.
func (s *IPSet) Capacity(shardLimit int) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c := shardLimit - len(s.members)
	if c < 0 {
		return 0
	}
	return c
}

// Members returns a copy of all members regardless of dirty state.
// Use this for reconciliation/diffing. Does not affect the dirty flag.
func (s *IPSet) Members() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.members))
	for ip := range s.members {
		out = append(out, ip)
	}
	return out
}

// Replace replaces the entire set with ips and marks dirty.
// Used to load existing TML content as baseline.
func (s *IPSet) Replace(ips []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.members = make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		s.members[ip] = struct{}{}
	}
	s.dirty = true
}

// IsDirty returns whether the set has changed since the last CommitClean.
func (s *IPSet) IsDirty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.dirty
}

// PeekDirty returns the current members if dirty, or nil if clean.
// Does NOT clear the dirty flag — use CommitClean after a successful write.
func (s *IPSet) PeekDirty() ([]string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.dirty {
		return nil, false
	}
	out := make([]string, 0, len(s.members))
	for ip := range s.members {
		out = append(out, ip)
	}
	return out, true
}

// CommitClean clears the dirty flag. Call only after a successful API write.
func (s *IPSet) CommitClean() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = false
}

// MarkClean clears the dirty flag without a successful write (baseline init).
func (s *IPSet) MarkClean() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirty = false
}

// HasChangedFromFlushed returns true if the current member set differs from the
// last successfully flushed snapshot. Returns true when no flush has occurred yet.
func (s *IPSet) HasChangedFromFlushed() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastFlushed == nil {
		return true
	}
	if len(s.members) != len(s.lastFlushed) {
		return true
	}
	for ip := range s.members {
		if _, ok := s.lastFlushed[ip]; !ok {
			return true
		}
	}
	return false
}

// CommitFlushed snapshots the current member set as the last-flushed state.
// Call after a successful API write to enable diff-based skip optimisation.
func (s *IPSet) CommitFlushed() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastFlushed = make(map[string]struct{}, len(s.members))
	for ip := range s.members {
		s.lastFlushed[ip] = struct{}{}
	}
	s.dirty = false
}
