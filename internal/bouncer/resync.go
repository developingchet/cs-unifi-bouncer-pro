package bouncer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

const (
	// resyncHTTPTimeout bounds one full decision pull. A community blocklist
	// of ~150k decisions is tens of megabytes of JSON.
	resyncHTTPTimeout = 2 * time.Minute
	// resyncMaxBody caps the decision list read into memory.
	resyncMaxBody = 256 << 20
)

// The LAPI stream only returns decisions created after the bouncer's last
// pull, and it compares a sub-second cursor with a created_at stored in whole
// seconds. A decision created in the same second as a pull is therefore
// never streamed until the bouncer restarts. runPeriodicResync closes that
// gap by re-reading every active decision (GET /v1/decisions, which does not
// move the stream cursor) and applying the ones the ban database has no
// claim for.
func (b *Bouncer) runPeriodicResync(ctx context.Context) {
	ticker := time.NewTicker(b.cfg.CrowdSecResyncInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := b.resync(ctx); err != nil && ctx.Err() == nil {
				b.log.Warn().Err(err).Msg("CrowdSec decision resync failed")
			}
		}
	}
}

// resync applies every active LAPI decision that has no claim in the ban
// database. Only bans are recovered: a missed deletion still ends when the
// ban expires (BAN_TTL at the latest).
func (b *Bouncer) resync(ctx context.Context) error {
	start := time.Now()
	decisions, err := b.fetchActiveDecisions(ctx)
	if err != nil {
		return err
	}
	bans, err := b.store.BanList()
	if err != nil {
		return fmt.Errorf("read ban database: %w", err)
	}
	missing := b.passingDecisions(unclaimedDecisions(decisions, claimedSources(bans)))
	if len(missing) == 0 {
		b.log.Debug().Int("decisions", len(decisions)).Msg("CrowdSec resync: nothing missing")
		return nil
	}
	b.handleDecisionBlock(ctx, &models.DecisionsStreamResponse{New: missing}, "resync")
	if err := b.fwMgr.SyncDirty(ctx, b.cfg.UnifiSites); err != nil {
		b.log.Warn().Err(err).Msg("SyncDirty after resync failed")
	}
	b.log.Info().
		Int("decisions", len(decisions)).
		Int("recovered", len(missing)).
		Stringer("elapsed", time.Since(start).Round(time.Millisecond)).
		Msg("CrowdSec resync applied decisions the stream missed")
	return nil
}

// fetchActiveDecisions reads every active decision from the LAPI.
func (b *Bouncer) fetchActiveDecisions(ctx context.Context) ([]*models.Decision, error) {
	url := strings.TrimRight(b.cfg.CrowdSecLAPIURL, "/") + "/v1/decisions"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build decision list request: %w", err)
	}
	req.Header.Set("X-Api-Key", b.cfg.CrowdSecLAPIKey)
	req.Header.Set("User-Agent", userAgent(BinaryVersion))

	resp, err := b.lapiResyncHTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("list decisions: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list decisions: LAPI returned %s", resp.Status)
	}
	return decodeDecisions(io.LimitReader(resp.Body, resyncMaxBody+1))
}

// decodeDecisions parses a decision list. The LAPI answers "null" when there
// are no active decisions. A body over resyncMaxBody is an error rather than
// a silently truncated list.
func decodeDecisions(r io.Reader) ([]*models.Decision, error) {
	body, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read decision list: %w", err)
	}
	if len(body) > resyncMaxBody {
		return nil, fmt.Errorf("decision list exceeds %d MiB", resyncMaxBody>>20)
	}
	var decisions []*models.Decision
	if err := json.Unmarshal(body, &decisions); err != nil {
		return nil, fmt.Errorf("decode decision list: %w", err)
	}
	return decisions, nil
}

// claimedSources returns every claim source held in the ban database.
func claimedSources(bans map[string]storage.BanEntry) map[string]struct{} {
	sources := make(map[string]struct{}, len(bans))
	for _, entry := range bans {
		for source := range entry.Claims {
			sources[source] = struct{}{}
		}
	}
	return sources
}

// passingDecisions drops the decisions the filter pipeline rejects. A
// rejected decision never gets a claim, so it is unclaimed on every resync;
// the rejected sources are remembered so each is filtered (and counted in
// decisions_filtered_total) once rather than once per resync. The set is
// rebuilt from each run's input, so it never outgrows the active list.
func (b *Bouncer) passingDecisions(unclaimed []*models.Decision) []*models.Decision {
	rejected := make(map[string]struct{}, len(b.resyncRejected))
	var passing []*models.Decision
	for _, d := range unclaimed {
		source := decisionSource(d)
		if _, seen := b.resyncRejected[source]; seen {
			rejected[source] = struct{}{}
			continue
		}
		if !decision.Filter(d, b.filterCfg, b.log).Passed {
			rejected[source] = struct{}{}
			continue
		}
		passing = append(passing, d)
	}
	b.resyncRejected = rejected
	return passing
}

// unclaimedDecisions returns the decisions whose source has no claim yet.
func unclaimedDecisions(decisions []*models.Decision, claimed map[string]struct{}) []*models.Decision {
	var missing []*models.Decision
	for _, d := range decisions {
		if d == nil {
			continue
		}
		source := decisionSource(d)
		if source == "" {
			continue
		}
		if _, ok := claimed[source]; !ok {
			missing = append(missing, d)
		}
	}
	return missing
}
