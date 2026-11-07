package banstate

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// Claim is one source's claim on an address until Expiry (zero for none).
type Claim struct {
	IP     string
	IPv6   bool
	Source string
	Expiry time.Time
}

// ClaimResult is the outcome of one Claim.
type ClaimResult struct {
	// Added reports that the claim banned an address no active claim held.
	Added bool
	// Err is set when the ban could not be applied or confirmed. The claim
	// stays recorded as pending, so reconcile and the next claim retry it.
	Err error
}

// ClaimRequest is one address for ClaimMany.
type ClaimRequest struct {
	IP   string
	IPv6 bool
}

// claimChunkSize bounds how long a batch of claims holds the lock, so
// CrowdSec decisions interleave with a large feed instead of waiting for all
// of it.
const claimChunkSize = 500

var errSourceRequired = errors.New("ban source is required")

// Claim records source's claim on ip and applies the ban when it is the
// address's first active claim. It reports whether the address became banned.
func (m *Manager) Claim(ctx context.Context, ip string, ipv6 bool, source string, expiry time.Time) (bool, error) {
	if source == "" {
		return false, errSourceRequired
	}
	results, err := m.ClaimBatch(ctx, []Claim{{IP: ip, IPv6: ipv6, Source: source, Expiry: expiry}})
	if len(results) == 0 {
		return false, err
	}
	return results[0].Added, results[0].Err
}

// ClaimBatch records every claim and applies the bans that became pending.
// Each chunk of claimChunkSize claims costs two store transactions: one
// records the claims, marking first claims pending, and one confirms the bans
// that were applied. Claims on one address within a batch build on each
// other in order.
//
// results[i] is the outcome of claims[i]. A store failure or a cancelled
// context ends the batch: results then covers only the claims handled
// before it, and the error says why the rest were not.
func (m *Manager) ClaimBatch(ctx context.Context, claims []Claim) ([]ClaimResult, error) {
	if m.dryRun {
		return make([]ClaimResult, len(claims)), nil
	}
	results := make([]ClaimResult, 0, len(claims))
	for start := 0; start < len(claims); start += claimChunkSize {
		if err := ctx.Err(); err != nil {
			return results, err
		}
		chunk := claims[start:min(start+claimChunkSize, len(claims))]
		chunkResults, err := m.claimChunk(ctx, chunk)
		results = append(results, chunkResults...)
		if err != nil {
			return results, err
		}
	}
	return results, nil
}

// ClaimMany claims every request for source. It returns how many addresses
// became newly banned. Addresses whose firewall update fails stay recorded as
// pending, so reconcile (which works from the stored ban list) and the next
// claim both retry them; the returned error counts them and wraps the first.
func (m *Manager) ClaimMany(ctx context.Context, reqs []ClaimRequest, source string, expiry time.Time) (int, error) {
	if source == "" {
		return 0, errSourceRequired
	}
	claims := make([]Claim, len(reqs))
	for i, req := range reqs {
		claims[i] = Claim{IP: req.IP, IPv6: req.IPv6, Source: source, Expiry: expiry}
	}
	results, err := m.ClaimBatch(ctx, claims)
	added := 0
	var failures []error
	for _, result := range results {
		if result.Added {
			added++
		}
		if result.Err != nil {
			failures = append(failures, result.Err)
		}
	}
	if err != nil {
		return added, err
	}
	if len(failures) > 0 {
		return added, fmt.Errorf("%d of %d addresses not applied, first: %w", len(failures), len(reqs), failures[0])
	}
	return added, nil
}

// pendingBan is an address of a chunk whose ban is recorded as pending.
type pendingBan struct {
	ip     string
	claims []int // indices of the chunk's claims on ip
	adder  int   // index of the claim that made ip active, or -1
}

func (m *Manager) claimChunk(ctx context.Context, chunk []Claim) ([]ClaimResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	results := make([]ClaimResult, len(chunk))
	updates, pending, err := m.recordClaims(chunk, results)
	if err != nil {
		return nil, err
	}
	if len(pending) == 0 {
		return results, nil
	}
	confirmed := make(map[string]storage.BanEntry, len(pending))
	for _, p := range pending {
		entry := updates[p.ip]
		if err := m.apply(ctx, p.ip, entry.IPv6, true); err != nil {
			for _, i := range p.claims {
				results[i].Err = fmt.Errorf("apply ban %s: %w", p.ip, err)
			}
			continue
		}
		entry.Pending = false
		confirmed[p.ip] = entry
	}
	if err := m.store.BanPutMany(confirmed); err != nil {
		err = fmt.Errorf("confirm bans: %w", err)
		for _, p := range pending {
			if _, ok := confirmed[p.ip]; ok {
				for _, i := range p.claims {
					results[i].Err = err
				}
			}
		}
		return results, err
	}
	for _, p := range pending {
		if _, ok := confirmed[p.ip]; ok && p.adder >= 0 {
			results[p.adder].Added = true
		}
	}
	return results, nil
}

// recordClaims writes the chunk's claims in one transaction and returns the
// updated entries and the addresses left pending, in order of first claim.
// Claims without a source get an error in results and are not recorded.
func (m *Manager) recordClaims(chunk []Claim, results []ClaimResult) (map[string]storage.BanEntry, []*pendingBan, error) {
	now := time.Now().UTC()
	updates := make(map[string]storage.BanEntry, len(chunk))
	byIP := make(map[string]*pendingBan, len(chunk))
	var order []*pendingBan
	for i, c := range chunk {
		if c.Source == "" {
			results[i].Err = errSourceRequired
			continue
		}
		var existing *storage.BanEntry
		if entry, seen := updates[c.IP]; seen {
			existing = &entry
		} else {
			stored, err := m.store.BanGet(c.IP)
			if err != nil {
				return nil, nil, fmt.Errorf("read ban %s: %w", c.IP, err)
			}
			existing = stored
		}
		entry, wasActive := withClaim(existing, c.IPv6, c.Source, c.Expiry, now)
		updates[c.IP] = *entry
		p := byIP[c.IP]
		if p == nil {
			p = &pendingBan{ip: c.IP, adder: -1}
			byIP[c.IP] = p
			order = append(order, p)
		}
		p.claims = append(p.claims, i)
		if !wasActive && p.adder < 0 {
			p.adder = i
		}
	}
	if len(updates) == 0 {
		return updates, nil, nil
	}
	if err := m.store.BanPutMany(updates); err != nil {
		return nil, nil, fmt.Errorf("record bans: %w", err)
	}
	pending := order[:0]
	for _, p := range order {
		if updates[p.ip].Pending {
			pending = append(pending, p)
		}
	}
	return updates, pending, nil
}

// withClaim returns a copy of existing (or a new entry) with source's claim
// set to expiry, and whether the ban was already active before the claim.
func withClaim(existing *storage.BanEntry, ipv6 bool, source string, expiry, now time.Time) (*storage.BanEntry, bool) {
	if existing == nil {
		entry := &storage.BanEntry{RecordedAt: now, IPv6: ipv6, Pending: true,
			Claims: map[string]time.Time{source: expiry.UTC()}}
		entry.ExpiresAt = latestExpiry(entry.Claims)
		return entry, false
	}
	entry := *existing
	entry.Claims = claimsFor(*existing)
	wasActive := active(entry.Claims, now)
	entry.Claims[source] = expiry.UTC()
	entry.ExpiresAt = latestExpiry(entry.Claims)
	entry.Pending = entry.Pending || !wasActive
	return &entry, wasActive
}
