package banstate

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// Manager serializes changes to ban ownership and their firewall transitions.
type Manager struct {
	mu     sync.Mutex
	store  storage.Store
	fw     firewall.Manager
	sites  []string
	dryRun bool
}

func New(store storage.Store, fw firewall.Manager, sites []string, dryRun bool) *Manager {
	return &Manager{store: store, fw: fw, sites: sites, dryRun: dryRun}
}

func claimsFor(entry storage.BanEntry) map[string]time.Time {
	if entry.Claims == nil {
		return map[string]time.Time{"legacy": entry.ExpiresAt}
	}
	claims := make(map[string]time.Time, len(entry.Claims))
	for source, expiry := range entry.Claims {
		claims[source] = expiry
	}
	return claims
}

func active(claims map[string]time.Time, now time.Time) bool {
	for _, expiry := range claims {
		if expiry.IsZero() || expiry.After(now) {
			return true
		}
	}
	return false
}

func latestExpiry(claims map[string]time.Time) time.Time {
	var latest time.Time
	for _, expiry := range claims {
		if expiry.IsZero() {
			return time.Time{}
		}
		if expiry.After(latest) {
			latest = expiry
		}
	}
	return latest
}

func (m *Manager) Claim(ctx context.Context, ip string, ipv6 bool, source string, expiry time.Time) (bool, error) {
	if source == "" {
		return false, fmt.Errorf("ban source is required")
	}
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	existing, err := m.store.BanGet(ip)
	if err != nil {
		return false, fmt.Errorf("read ban: %w", err)
	}
	entry, wasActive := withClaim(existing, ipv6, source, expiry, time.Now().UTC())
	if err := m.store.BanPut(ip, *entry); err != nil {
		return false, fmt.Errorf("record ban: %w", err)
	}
	if !entry.Pending {
		return false, nil
	}
	if err := m.apply(ctx, ip, ipv6, true); err != nil {
		return false, err
	}
	entry.Pending = false
	if err := m.store.BanPut(ip, *entry); err != nil {
		return false, fmt.Errorf("confirm ban: %w", err)
	}
	return !wasActive, nil
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

// ClaimRequest is one address for ClaimMany.
type ClaimRequest struct {
	IP   string
	IPv6 bool
}

// claimChunkSize bounds how long ClaimMany holds the lock, so CrowdSec
// decisions interleave with a large feed instead of waiting for all of it.
const claimChunkSize = 500

// ClaimMany claims every request for source. Each chunk costs two store
// transactions (record, then confirm) instead of up to two per address.
// It returns how many addresses became newly banned. Addresses whose firewall
// update fails stay recorded as pending, so reconcile (which works from the
// stored ban list) and the next claim both retry them; the returned error
// counts them and wraps the first.
func (m *Manager) ClaimMany(ctx context.Context, reqs []ClaimRequest, source string, expiry time.Time) (int, error) {
	if source == "" {
		return 0, fmt.Errorf("ban source is required")
	}
	if m.dryRun {
		return 0, nil
	}
	added := 0
	var failures []error
	for start := 0; start < len(reqs); start += claimChunkSize {
		if err := ctx.Err(); err != nil {
			return added, err
		}
		chunk := reqs[start:min(start+claimChunkSize, len(reqs))]
		n, errs, err := m.claimChunk(ctx, chunk, source, expiry)
		added += n
		failures = append(failures, errs...)
		if err != nil {
			return added, err
		}
	}
	if len(failures) > 0 {
		return added, fmt.Errorf("%d of %d addresses not applied, first: %w", len(failures), len(reqs), failures[0])
	}
	return added, nil
}

func (m *Manager) claimChunk(ctx context.Context, chunk []ClaimRequest, source string, expiry time.Time) (int, []error, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now().UTC()
	updates := make(map[string]storage.BanEntry, len(chunk))
	newlyActive := make(map[string]bool, len(chunk))
	for _, req := range chunk {
		existing, err := m.store.BanGet(req.IP)
		if err != nil {
			return 0, nil, fmt.Errorf("read ban %s: %w", req.IP, err)
		}
		entry, wasActive := withClaim(existing, req.IPv6, source, expiry, now)
		updates[req.IP] = *entry
		newlyActive[req.IP] = !wasActive
	}
	if err := m.store.BanPutMany(updates); err != nil {
		return 0, nil, fmt.Errorf("record bans: %w", err)
	}

	confirmed := make(map[string]storage.BanEntry)
	var failures []error
	added := 0
	for ip, entry := range updates {
		if !entry.Pending {
			continue
		}
		if err := m.apply(ctx, ip, entry.IPv6, true); err != nil {
			failures = append(failures, fmt.Errorf("apply ban %s: %w", ip, err))
			continue
		}
		entry.Pending = false
		confirmed[ip] = entry
		if newlyActive[ip] {
			added++
		}
	}
	if err := m.store.BanPutMany(confirmed); err != nil {
		return added, failures, fmt.Errorf("confirm bans: %w", err)
	}
	return added, failures, nil
}

func (m *Manager) Release(ctx context.Context, ip, source string) (bool, error) {
	if source == "" {
		return false, fmt.Errorf("ban source is required")
	}
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, err := m.store.BanGet(ip)
	if err != nil || entry == nil {
		return false, err
	}
	claims := claimsFor(*entry)
	_, found := claims[source]
	_, legacy := claims["legacy"]
	legacyDecision := legacy && strings.HasPrefix(source, "crowdsec:")
	if !found && !legacyDecision {
		return false, nil
	}
	delete(claims, source)
	if legacyDecision {
		delete(claims, "legacy")
	}
	if active(claims, time.Now().UTC()) {
		entry.Claims = claims
		entry.ExpiresAt = latestExpiry(claims)
		return false, m.store.BanPut(ip, *entry)
	}
	if err := m.apply(ctx, ip, entry.IPv6, false); err != nil {
		return false, err
	}
	if err := m.store.BanDelete(ip); err != nil {
		return false, fmt.Errorf("delete ban: %w", err)
	}
	return true, nil
}

// ReleaseAll removes every claim for an explicit manual unban.
func (m *Manager) ReleaseAll(ctx context.Context, ip string, ipv6 bool) (bool, error) {
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, err := m.store.BanGet(ip)
	if err != nil {
		return false, err
	}
	if entry == nil {
		return false, m.apply(ctx, ip, ipv6, false)
	}
	if err := m.apply(ctx, ip, entry.IPv6, false); err != nil {
		return false, err
	}
	if err := m.store.BanDelete(ip); err != nil {
		return false, fmt.Errorf("delete ban: %w", err)
	}
	return true, nil
}

func (m *Manager) Expire(ctx context.Context, ip string) (bool, error) {
	if m.dryRun {
		return false, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	entry, err := m.store.BanGet(ip)
	if err != nil || entry == nil {
		return false, err
	}
	now := time.Now().UTC()
	claims := claimsFor(*entry)
	changed := false
	for source, expiry := range claims {
		if !expiry.IsZero() && !expiry.After(now) {
			delete(claims, source)
			changed = true
		}
	}
	if !changed {
		return false, nil
	}
	if len(claims) > 0 {
		entry.Claims = claims
		entry.ExpiresAt = latestExpiry(claims)
		return false, m.store.BanPut(ip, *entry)
	}
	if err := m.apply(ctx, ip, entry.IPv6, false); err != nil {
		return false, err
	}
	if err := m.store.BanDelete(ip); err != nil {
		return false, fmt.Errorf("delete expired ban: %w", err)
	}
	return true, nil
}

func (m *Manager) apply(ctx context.Context, ip string, ipv6, ban bool) error {
	var siteErrors []error
	for _, site := range m.sites {
		var err error
		if ban {
			err = m.fw.ApplyBan(ctx, site, ip, ipv6)
		} else {
			err = m.fw.ApplyUnban(ctx, site, ip, ipv6)
		}
		if err != nil {
			var unauthorized *controller.ErrUnauthorized
			var rateLimit *controller.ErrRateLimit
			if errors.As(err, &unauthorized) || errors.As(err, &rateLimit) {
				return fmt.Errorf("site %s: %w", site, err)
			}
			siteErrors = append(siteErrors, fmt.Errorf("site %s: %w", site, err))
		}
	}
	return errors.Join(siteErrors...)
}
