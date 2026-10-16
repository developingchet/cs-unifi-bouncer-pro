package firewall

import (
	"context"
	"errors"
	"fmt"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
)

// ModeChangeError reports a site loaded in legacy mode that now needs the
// zone-based firewall: the controller was upgraded to a release that only
// enforces zone policies, or FIREWALL_MODE=auto now finds firewall zones on
// the site. The shard managers and policies are built for one mode at load
// time, so the daemon exits and its supervisor restarts it in the new mode.
type ModeChangeError struct {
	Site   string
	Reason string
}

func (e *ModeChangeError) Error() string {
	return fmt.Sprintf("site %s was loaded in legacy mode, but %s; restart the bouncer to load it in zone mode", e.Site, e.Reason)
}

// networkVersion returns the controller's Network version, read once and
// logged on first use. A version that cannot be read or parsed is logged and
// reported as unknown, so a controller or key that hides it still starts.
func (m *managerImpl) networkVersion(ctx context.Context, site string) (controller.NetworkVersion, bool) {
	m.versionMu.Lock()
	defer m.versionMu.Unlock()
	if m.versionRead {
		return m.version, m.versionKnown
	}
	version, err := m.readNetworkVersion(ctx, site)
	if ctx.Err() != nil {
		return controller.NetworkVersion{}, false
	}
	m.versionRead = true
	if err != nil {
		m.log.Warn().Err(err).Msg("could not read the UniFi Network version; assuming a release that still applies legacy rules")
		return controller.NetworkVersion{}, false
	}
	m.version, m.versionKnown = version, true
	m.log.Info().Stringer("network_version", version).Bool("zone_only", version.ZoneOnly()).
		Msg("detected UniFi Network version")
	return version, true
}

func (m *managerImpl) readNetworkVersion(ctx context.Context, site string) (controller.NetworkVersion, error) {
	raw, err := m.ctrl.ApplicationVersion(ctx, site)
	if err != nil {
		return controller.NetworkVersion{}, err
	}
	return controller.ParseNetworkVersion(raw)
}

// checkModeSupported refuses legacy mode on a release that enforces only the
// zone-based firewall: the rules would be created but block nothing.
func (m *managerImpl) checkModeSupported(ctx context.Context, site, mode string) error {
	if mode != "legacy" {
		return nil
	}
	version, known := m.networkVersion(ctx, site)
	if !known || !version.ZoneOnly() {
		return nil
	}
	if m.cfg.FirewallMode == "auto" {
		return fmt.Errorf("site %s has no firewall zones, and UniFi Network %s applies only the zone-based firewall, "+
			"so legacy rules would block nothing; the zone-based firewall needs an adopted UniFi gateway on the site", site, version)
	}
	return fmt.Errorf("FIREWALL_MODE=legacy: UniFi Network %s applies only the zone-based firewall and ignores legacy rules "+
		"on site %s; set UNIFI_API_KEY and ZONE_PAIRS and use FIREWALL_MODE=auto or zone", version, site)
}

// CheckModeChange re-checks every site that was loaded in legacy mode and
// returns a *ModeChangeError for the first one that now needs zone mode.
// Checks that fail for other reasons (the controller restarting during an
// upgrade, a timeout) are logged and retried on the next call.
func (m *managerImpl) CheckModeChange(ctx context.Context) error {
	for _, site := range m.sites {
		if m.cachedMode(site) != "legacy" {
			continue
		}
		reason, err := m.legacySiteChanged(ctx, site)
		if err != nil {
			if ctx.Err() == nil {
				m.log.Debug().Err(err).Str("site", site).Msg("firewall mode re-check failed; retrying on the next reconcile")
			}
			continue
		}
		if reason != "" {
			return &ModeChangeError{Site: site, Reason: reason}
		}
	}
	return nil
}

// legacySiteChanged reports why a legacy site now needs zone mode, or "".
func (m *managerImpl) legacySiteChanged(ctx context.Context, site string) (string, error) {
	version, err := m.readNetworkVersion(ctx, site)
	if err != nil {
		return "", fmt.Errorf("read UniFi Network version: %w", err)
	}
	if version.ZoneOnly() {
		return fmt.Sprintf("the controller now runs UniFi Network %s, which applies only the zone-based firewall", version), nil
	}
	if m.cfg.FirewallMode != "auto" {
		return "", nil
	}
	m.ctrl.InvalidateZoneCache(site)
	hasZone, err := m.ctrl.HasFeature(ctx, site, controller.FeatureZoneBasedFirewall)
	var needsKey *controller.ErrZoneFirewallNeedsAPIKey
	switch {
	case errors.As(err, &needsKey):
		return "the site now uses the zone-based firewall, which needs UNIFI_API_KEY", nil
	case err != nil:
		return "", fmt.Errorf("detect zone-based firewall: %w", err)
	case hasZone:
		return "the site now has firewall zones", nil
	}
	return "", nil
}
