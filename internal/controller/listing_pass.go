package controller

import (
	"context"
	"errors"
	"slices"
	"sync"
)

// A listing pass lets one unit of work, such as a reconcile, a startup load
// or a Cloudflare whitelist sync, list each site's traffic matching lists,
// zone policies, firewall groups and firewall rules once. The listing of
// traffic matching lists carries every member of every shard, several
// megabytes of JSON with 100k bans, and most steps of such work start from it.
//
// Inside a pass, a Controller wrapped by WithListingPasses answers a repeat
// listing of a site from the copy the first one returned. Every write made
// through a wrapped Controller, inside a pass or not, is applied to the copies
// of every pass in progress, so a pass sees its own writes and those other
// work in this process makes meanwhile. Changes made by anything else, such as
// the UniFi UI or another bouncer instance, show only in the next pass. A step
// that must see the controller as it is now, such as confirming that an object
// reported missing is really gone, asks for a FreshListing; its result also
// replaces the pass's copy.

type passKey struct{}

type freshKey struct{}

// listingPass holds the listings taken during one pass, by owner and site.
type listingPass struct {
	mu    sync.Mutex
	ended bool
	sites map[siteKey]*siteListings
}

// siteKey identifies one site's listings of one controller. owner is the
// wrapped Controller, so wrappers of the same controller share listings.
type siteKey struct {
	owner any
	site  string
}

// collection is one listing kept by a pass.
type collection[T any] struct {
	items  []T
	loaded bool
	// writes counts the writes applied to the collection, so a listing that
	// was in flight during a write is not kept: it may predate the write.
	writes uint64
}

type siteListings struct {
	tmls     collection[TrafficMatchingList]
	policies collection[ZonePolicy]
	groups   collection[FirewallGroup]
	rules    collection[FirewallRule]
}

func tmlsOf(s *siteListings) *collection[TrafficMatchingList] { return &s.tmls }
func policiesOf(s *siteListings) *collection[ZonePolicy]      { return &s.policies }
func groupsOf(s *siteListings) *collection[FirewallGroup]     { return &s.groups }
func rulesOf(s *siteListings) *collection[FirewallRule]       { return &s.rules }

func tmlID(t TrafficMatchingList) string { return t.ID }
func policyID(p ZonePolicy) string       { return p.ID }
func groupID(g FirewallGroup) string     { return g.ID }
func ruleID(r FirewallRule) string       { return r.ID }

// activePasses holds the passes in progress, which every write is applied to.
var activePasses = struct {
	sync.Mutex
	set map[*listingPass]struct{}
}{set: make(map[*listingPass]struct{})}

// BeginPass starts a listing pass and returns the context that carries it and
// the function that ends it. A ctx already inside a pass is returned as it is,
// with a no-op end, so nested work shares the outer pass. A context that
// outlives its pass behaves as if it carried none.
func BeginPass(ctx context.Context) (context.Context, func()) {
	if passFrom(ctx) != nil {
		return ctx, func() {}
	}
	p := &listingPass{sites: make(map[siteKey]*siteListings)}
	activePasses.Lock()
	activePasses.set[p] = struct{}{}
	activePasses.Unlock()
	end := func() {
		activePasses.Lock()
		delete(activePasses.set, p)
		activePasses.Unlock()
		p.mu.Lock()
		p.ended = true
		p.sites = nil
		p.mu.Unlock()
	}
	return context.WithValue(ctx, passKey{}, p), end
}

// WithPassOf returns ctx carrying the listing pass that from carries, if any.
// It lets work that runs under a longer-lived context take part in the pass
// of the work that triggered it.
func WithPassOf(ctx, from context.Context) context.Context {
	p := passFrom(from)
	if p == nil {
		return ctx
	}
	return context.WithValue(ctx, passKey{}, p)
}

// FreshListing returns ctx marked so that listings made with it are fetched
// from the controller even inside a pass. The fetched listing replaces the
// pass's copy.
func FreshListing(ctx context.Context) context.Context {
	return context.WithValue(ctx, freshKey{}, true)
}

// passFrom returns the pass in progress that ctx carries, or nil.
func passFrom(ctx context.Context) *listingPass {
	p, _ := ctx.Value(passKey{}).(*listingPass)
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended {
		return nil
	}
	return p
}

// listThrough returns the pass's copy of a listing, or fetches it and keeps a
// copy for the rest of the pass. Outside a pass it only fetches. The copies
// are shallow: the slices inside the listed objects, such as a list's items,
// are shared with the pass and with every other caller, so a caller must not
// change them in place.
func listThrough[T any](ctx context.Context, key siteKey, pick func(*siteListings) *collection[T],
	fetch func() ([]T, error)) ([]T, error) {
	p := passFrom(ctx)
	if p == nil {
		return fetch()
	}
	fresh, _ := ctx.Value(freshKey{}).(bool)
	items, writes, hit := cachedListing(p, key, pick, fresh)
	if hit {
		return items, nil
	}
	listed, err := fetch()
	if err != nil {
		return nil, err
	}
	keepListing(p, key, pick, writes, listed)
	return listed, nil
}

// cachedListing returns a copy of the pass's listing when it holds one and a
// fresh listing was not asked for. Otherwise it returns the collection's write
// count, which keepListing checks.
func cachedListing[T any](p *listingPass, key siteKey, pick func(*siteListings) *collection[T], fresh bool) ([]T, uint64, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended {
		return nil, 0, false
	}
	s := p.sites[key]
	if s == nil {
		s = &siteListings{}
		p.sites[key] = s
	}
	c := pick(s)
	if c.loaded && !fresh {
		return slices.Clone(c.items), c.writes, true
	}
	return nil, c.writes, false
}

// keepListing stores a fetched listing unless a write was applied while it
// was in flight.
func keepListing[T any](p *listingPass, key siteKey, pick func(*siteListings) *collection[T], writes uint64, items []T) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended {
		return
	}
	s := p.sites[key]
	if s == nil {
		return
	}
	c := pick(s)
	if c.writes != writes {
		return
	}
	c.items = slices.Clone(items)
	c.loaded = true
}

// applyWrite applies change to the site's listing in every pass in progress.
func applyWrite[T any](key siteKey, pick func(*siteListings) *collection[T], change func(*collection[T])) {
	activePasses.Lock()
	passes := make([]*listingPass, 0, len(activePasses.set))
	for p := range activePasses.set {
		passes = append(passes, p)
	}
	activePasses.Unlock()
	for _, p := range passes {
		p.mu.Lock()
		if s := p.sites[key]; s != nil {
			c := pick(s)
			c.writes++
			if c.loaded {
				change(c)
			}
		}
		p.mu.Unlock()
	}
}

// recordWrite applies the outcome of a write to the passes in progress:
// change when it succeeded, nothing when the controller refused it and so
// changed nothing, and otherwise drops the listing, since the write may or
// may not have taken effect.
func recordWrite[T any](key siteKey, pick func(*siteListings) *collection[T], err error, change func(*collection[T])) {
	switch {
	case err == nil:
		applyWrite(key, pick, change)
	case refused(err):
	default:
		applyWrite(key, pick, invalidate[T])
	}
}

// recordDelete applies a delete. A not-found answer means the object is gone.
func recordDelete[T any](key siteKey, pick func(*siteListings) *collection[T], err error, id string, idOf func(T) string) {
	var nf *ErrNotFound
	if errors.As(err, &nf) {
		err = nil
	}
	recordWrite(key, pick, err, remove(id, idOf))
}

// refused reports whether the controller turned a write down without
// changing anything: a 400, a 409 or a 429.
func refused(err error) bool {
	var bad *ErrBadRequest
	var conflict *ErrConflict
	var rl *ErrRateLimit
	return errors.As(err, &bad) || errors.As(err, &conflict) || errors.As(err, &rl)
}

// upsert replaces the listed object with v's ID by v, or appends v.
func upsert[T any](v T, idOf func(T) string) func(*collection[T]) {
	id := idOf(v)
	if id == "" {
		return invalidate[T]
	}
	return func(c *collection[T]) {
		for i := range c.items {
			if idOf(c.items[i]) == id {
				c.items[i] = v
				return
			}
		}
		c.items = append(c.items, v)
	}
}

// remove drops the listed object with ID id.
func remove[T any](id string, idOf func(T) string) func(*collection[T]) {
	return func(c *collection[T]) {
		c.items = slices.DeleteFunc(c.items, func(v T) bool { return idOf(v) == id })
	}
}

// invalidate drops the listing so the next one is fetched.
func invalidate[T any](c *collection[T]) {
	c.items = nil
	c.loaded = false
}
