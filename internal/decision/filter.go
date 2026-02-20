package decision

import (
	"net"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/metrics"
	"github.com/rs/zerolog"
)

// FilterConfig holds the parameters for the 8-stage decision pipeline.
type FilterConfig struct {
	// Stage 1: allowed action types
	AllowedActions []string // default: ["ban", "delete"]

	// Stage 2: scenario substrings to skip
	BlockScenarioExclude []string

	// Stage 3: allowed origins (empty = all)
	AllowedOrigins []string

	// Stage 4: allowed scopes
	AllowedScopes []string // default: ["ip", "range"]

	// Stage 7: whitelist
	Whitelist []*net.IPNet

	// Stage 8: minimum ban duration (0 = disabled)
	MinBanDuration time.Duration
}

// NewFilterConfig returns a FilterConfig with sensible defaults.
func NewFilterConfig() FilterConfig {
	return FilterConfig{
		AllowedActions: []string{"ban", "delete"},
		AllowedScopes:  []string{"ip", "range"},
	}
}

// FilterResult holds the decision after pipeline processing.
type FilterResult struct {
	Passed   bool
	Action   string // "ban" or "delete"
	Value    string // sanitized IP or CIDR
	IPv6     bool
	Duration time.Duration
}

// stage labels for metrics
const (
	stageAction    = "1_action"
	stageScenario  = "2_scenario_exclude"
	stageOrigin    = "3_origin"
	stageScope     = "4_scope"
	stageParse     = "5_parse"
	stagePrivate   = "6_private"
	stageWhitelist = "7_whitelist"
	stageMinDur    = "8_min_duration"
)

// Filter runs a CrowdSec decision through the 8-stage pipeline.
// Returns a FilterResult with Passed=true if the decision should be acted on.
func Filter(d *models.Decision, cfg FilterConfig, log zerolog.Logger) FilterResult {
	action := strings.ToLower(*d.Type)
	scope := strings.ToLower(*d.Scope)
	value := *d.Value
	origin := ""
	if d.Origin != nil {
		origin = *d.Origin
	}
	scenario := ""
	if d.Scenario != nil {
		scenario = *d.Scenario
	}

	// Stage 1: action must be ban or delete
	if !containsCI(cfg.AllowedActions, action) {
		metrics.DecisionsFiltered.WithLabelValues(stageAction, "unsupported_action").Inc()
		log.Trace().Str("action", action).Msg("filtered: unsupported action")
		return FilterResult{}
	}

	// Stage 2: scenario exclude
	for _, exc := range cfg.BlockScenarioExclude {
		if exc != "" && strings.Contains(scenario, exc) {
			metrics.DecisionsFiltered.WithLabelValues(stageScenario, "excluded_scenario").Inc()
			log.Trace().Str("scenario", scenario).Str("exclude", exc).Msg("filtered: excluded scenario")
			return FilterResult{}
		}
	}

	// Stage 3: origin filter (empty = all allowed)
	if len(cfg.AllowedOrigins) > 0 && !containsCI(cfg.AllowedOrigins, origin) {
		metrics.DecisionsFiltered.WithLabelValues(stageOrigin, "origin_not_allowed").Inc()
		log.Trace().Str("origin", origin).Msg("filtered: origin not allowed")
		return FilterResult{}
	}

	// Stage 4: scope must be ip or range
	if !containsCI(cfg.AllowedScopes, scope) {
		metrics.DecisionsFiltered.WithLabelValues(stageScope, "unsupported_scope").Inc()
		log.Trace().Str("scope", scope).Msg("filtered: unsupported scope")
		return FilterResult{}
	}

	// Stage 5: parse and sanitize
	sanitized, isCIDR, err := ParseAndSanitize(value)
	if err != nil {
		metrics.DecisionsFiltered.WithLabelValues(stageParse, "parse_error").Inc()
		log.Warn().Str("value", value).Err(err).Msg("filtered: parse error")
		return FilterResult{}
	}
	_ = isCIDR
	isV6 := IsIPv6(sanitized)

	// Stage 6: reject private/loopback/link-local/ULA
	if IsPrivate(sanitized) {
		metrics.DecisionsFiltered.WithLabelValues(stagePrivate, "private_ip").Inc()
		log.Trace().Str("ip", sanitized).Msg("filtered: private/loopback/link-local IP")
		return FilterResult{}
	}

	// Stage 7: reject whitelisted IPs/CIDRs
	if IsWhitelisted(sanitized, cfg.Whitelist) {
		metrics.DecisionsFiltered.WithLabelValues(stageWhitelist, "whitelisted").Inc()
		log.Trace().Str("ip", sanitized).Msg("filtered: whitelisted IP")
		return FilterResult{}
	}

	// Stage 8: minimum ban duration
	var dur time.Duration
	if d.Duration != nil && *d.Duration != "" {
		parsed, parseErr := time.ParseDuration(*d.Duration)
		if parseErr == nil {
			dur = parsed
		}
	}
	if action == "ban" && cfg.MinBanDuration > 0 && dur > 0 && dur < cfg.MinBanDuration {
		metrics.DecisionsFiltered.WithLabelValues(stageMinDur, "too_short").Inc()
		log.Trace().Str("ip", sanitized).Dur("duration", dur).Dur("min", cfg.MinBanDuration).Msg("filtered: ban duration too short")
		return FilterResult{}
	}

	return FilterResult{
		Passed:   true,
		Action:   action,
		Value:    sanitized,
		IPv6:     isV6,
		Duration: dur,
	}
}

func containsCI(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}
