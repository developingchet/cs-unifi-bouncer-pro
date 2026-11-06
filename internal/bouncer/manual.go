package bouncer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/decision"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// ManualOrigin is the claim source of an operator's ban and the origin its
// history events carry.
const ManualOrigin = "manual"

// InvalidRequestError reports a manual request refused before anything
// changed: an unparsable address, a guarded range, a bad duration.
type InvalidRequestError struct{ Err error }

func (e *InvalidRequestError) Error() string { return e.Err.Error() }
func (e *InvalidRequestError) Unwrap() error { return e.Err }

func invalid(format string, args ...any) error {
	return &InvalidRequestError{Err: fmt.Errorf(format, args...)}
}

// IsInvalidRequest reports whether err is an InvalidRequestError.
func IsInvalidRequest(err error) bool {
	var target *InvalidRequestError
	return errors.As(err, &target)
}

// CheckManualBan parses value and applies the guards CrowdSec decisions go
// through: a manual ban must not cut off a private network, a whitelisted
// address or most of the internet. It returns the sanitized address or range.
func CheckManualBan(value string, whitelist []*net.IPNet) (string, error) {
	ip, _, err := decision.ParseAndSanitize(value)
	if err != nil {
		return "", &InvalidRequestError{Err: err}
	}
	ipv6 := decision.IsIPv6(ip)
	switch {
	case decision.TooBroad(ip, ipv6):
		return "", invalid("refusing to ban %s: range is too broad (broader than /8 for IPv4 or /32 for IPv6)", ip)
	case decision.IsPrivate(ip):
		return "", invalid("refusing to ban %s: private, loopback or link-local addresses are never banned", ip)
	case decision.IsWhitelisted(ip, whitelist):
		return "", invalid("refusing to ban %s: it is covered by BLOCK_WHITELIST", ip)
	}
	return ip, nil
}

// ManualBanDuration returns how long a manual ban lasts: dur, with 0 meaning
// BAN_TTL and anything longer capped at BAN_TTL.
func ManualBanDuration(dur, banTTL time.Duration) (time.Duration, error) {
	if dur < 0 {
		return 0, invalid("ban duration must not be negative")
	}
	if dur == 0 || dur > banTTL {
		return banTTL, nil
	}
	return dur, nil
}

// banClaimer is the part of banstate.Manager manual actions use.
type banClaimer interface {
	Claim(ctx context.Context, ip string, ipv6 bool, source string, expiry time.Time) (bool, error)
	ReleaseAll(ctx context.Context, ip string, ipv6 bool) (bool, error)
}

// firewallSyncer is the part of firewall.Manager manual actions use.
type firewallSyncer interface {
	SyncDirty(ctx context.Context, sites []string) error
	Reconcile(ctx context.Context, sites []string) (*firewall.ReconcileResult, error)
}

// eventRecorder writes the ban history.
type eventRecorder interface {
	RecordEvent(e storage.EventEntry) error
}

// ManualActions carries out operator bans, unbans and reconciles through the
// ban-state manager, so a manual ban is a claim like any other source's and
// a later CrowdSec decision for the address does not disturb it. The daemon
// serves them on its health address; the CLI runs them directly when the
// daemon is stopped.
type ManualActions struct {
	Claims    banClaimer
	Firewall  firewallSyncer
	History   eventRecorder
	Sites     []string
	BanTTL    time.Duration
	Whitelist []*net.IPNet
	DryRun    bool
	Log       zerolog.Logger
}

// ManualResult reports a manual ban or unban. SyncErr is set when the change
// is recorded but could not be written to UniFi yet; the next sync retries it.
type ManualResult struct {
	IP        string
	ExpiresAt time.Time // bans only
	Changed   bool      // unbans: whether a ban was lifted
	SyncErr   error
}

// Ban claims value for ManualOrigin across every site for dur (see
// ManualBanDuration), records it in the history and writes it to UniFi.
func (a *ManualActions) Ban(ctx context.Context, value string, dur time.Duration) (ManualResult, error) {
	ip, err := CheckManualBan(value, a.Whitelist)
	if err != nil {
		return ManualResult{}, err
	}
	dur, err = ManualBanDuration(dur, a.BanTTL)
	if err != nil {
		return ManualResult{}, err
	}
	expiresAt := time.Now().Add(dur)
	if _, err := a.Claims.Claim(ctx, ip, decision.IsIPv6(ip), ManualOrigin, expiresAt); err != nil {
		return ManualResult{}, fmt.Errorf("ban %s: %w", ip, err)
	}
	a.record("ban", ip)
	a.Log.Info().Str("ip", ip).Time("expires_at", expiresAt).Msg("manual ban")
	return ManualResult{IP: ip, ExpiresAt: expiresAt, SyncErr: a.sync(ctx)}, nil
}

// Unban lifts every claim on value, records it in the history and writes the
// change to UniFi.
func (a *ManualActions) Unban(ctx context.Context, value string) (ManualResult, error) {
	ip, _, err := decision.ParseAndSanitize(value)
	if err != nil {
		return ManualResult{}, &InvalidRequestError{Err: err}
	}
	removed, err := a.Claims.ReleaseAll(ctx, ip, decision.IsIPv6(ip))
	if err != nil {
		return ManualResult{}, fmt.Errorf("unban %s: %w", ip, err)
	}
	if removed {
		a.record("unban", ip)
	}
	a.Log.Info().Str("ip", ip).Bool("lifted", removed).Msg("manual unban")
	return ManualResult{IP: ip, Changed: removed, SyncErr: a.sync(ctx)}, nil
}

// Reconcile runs a full reconcile of every site.
func (a *ManualActions) Reconcile(ctx context.Context) (*firewall.ReconcileResult, error) {
	return a.Firewall.Reconcile(ctx, a.Sites)
}

func (a *ManualActions) sync(ctx context.Context) error {
	if err := a.Firewall.SyncDirty(ctx, a.Sites); err != nil {
		return fmt.Errorf("write to UniFi: %w", err)
	}
	return nil
}

// record adds a history event. A dry run records nothing, and a failed write
// only warns: the ban itself is in place.
func (a *ManualActions) record(action, ip string) {
	if a.DryRun || a.History == nil {
		return
	}
	if err := a.History.RecordEvent(storage.EventEntry{
		Action: action, Origin: ManualOrigin, IP: ip, RecordedAt: time.Now(),
	}); err != nil {
		a.Log.Warn().Err(err).Str("ip", ip).Str("action", action).Msg("failed to record manual event")
	}
}
