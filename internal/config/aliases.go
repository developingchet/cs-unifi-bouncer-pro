package config

import (
	"fmt"
	"strings"

	"github.com/knadh/koanf/v2"
)

// maxShardLimit is the most entries a UniFi address list holds.
const maxShardLimit = 10000

// settingAlias is a deprecated setting that still works under its old name.
// shadowed means the current setting, when present, replaces the old one
// outright, so the old one is then ignored.
type settingAlias struct {
	old, current string
	shadowed     bool
}

// capacityAliases are the earlier names of the shard size settings. They keep
// their meaning: FIREWALL_GROUP_CAPACITY_V4 and _V6 size one family's shards
// when SHARD_LIMIT_V4 or _V6 is unset, and FIREWALL_GROUP_CAPACITY sizes a
// family neither of those covers, below SHARD_LIMIT, which stays the ceiling
// for all of them.
var capacityAliases = []settingAlias{
	{old: "FIREWALL_GROUP_CAPACITY", current: "SHARD_LIMIT"},
	{old: "FIREWALL_GROUP_CAPACITY_V4", current: "SHARD_LIMIT_V4", shadowed: true},
	{old: "FIREWALL_GROUP_CAPACITY_V6", current: "SHARD_LIMIT_V6", shadowed: true},
}

// dialIPv6Alias is the earlier name of UNIFI_DIAL_IPV6, easily mistaken for
// FIREWALL_ENABLE_IPV6.
var dialIPv6Alias = settingAlias{old: "ENABLE_IPV6", current: "UNIFI_DIAL_IPV6", shadowed: true}

// isSet reports whether the environment gives name a non-empty value.
func isSet(k *koanf.Koanf, name string) bool {
	return strings.TrimSpace(k.String(strings.ToLower(name))) != ""
}

// applySettingAliases resolves deprecated setting names into their current
// settings and records a deprecation warning for each one in use.
func (c *Config) applySettingAliases(k *koanf.Koanf) {
	for _, alias := range capacityAliases {
		if isSet(k, alias.old) {
			c.DeprecationWarnings = append(c.DeprecationWarnings, aliasWarning(alias, isSet(k, alias.current)))
		}
	}
	if isSet(k, dialIPv6Alias.old) {
		current := isSet(k, dialIPv6Alias.current)
		if !current {
			c.UnifiDialIPv6 = k.Bool(strings.ToLower(dialIPv6Alias.old))
		}
		c.DeprecationWarnings = append(c.DeprecationWarnings, aliasWarning(dialIPv6Alias, current))
	}
}

// aliasWarning words the deprecation warning for alias, saying the old
// setting is ignored when the current one is present and replaces it.
func aliasWarning(alias settingAlias, currentSet bool) string {
	msg := fmt.Sprintf("%s is deprecated; use %s instead", alias.old, alias.current)
	if currentSet && alias.shadowed {
		msg += fmt.Sprintf(" (%s is set, so %s is ignored)", alias.current, alias.old)
	}
	return msg
}

// validateShardLimits checks the per-family shard limits and their
// deprecated FIREWALL_GROUP_CAPACITY names.
func (c *Config) validateShardLimits() error {
	for _, setting := range []struct {
		name  string
		value int
	}{
		{"SHARD_LIMIT_V4", c.ShardLimitV4},
		{"SHARD_LIMIT_V6", c.ShardLimitV6},
	} {
		if setting.value < 0 || setting.value > maxShardLimit {
			return fmt.Errorf("%s must be between 1 and %d, or 0 to use SHARD_LIMIT (got %d)", setting.name, maxShardLimit, setting.value)
		}
	}
	return nil
}

// ShardCapacities returns the most IPs one IPv4 and one IPv6 shard hold.
// Each family takes the first non-zero of its SHARD_LIMIT_V4 or _V6, its
// deprecated FIREWALL_GROUP_CAPACITY_V4 or _V6, and FIREWALL_GROUP_CAPACITY,
// and is capped at SHARD_LIMIT. When none is set the family uses SHARD_LIMIT,
// or defaultLimit if SHARD_LIMIT is zero.
func (c *Config) ShardCapacities(defaultLimit int) (v4, v6 int) {
	limit := c.ShardLimit
	if limit == 0 {
		limit = defaultLimit
	}
	v4 = capped(firstNonZero(c.ShardLimitV4, c.FirewallGroupCapacityV4, c.FirewallGroupCapacity), limit)
	v6 = capped(firstNonZero(c.ShardLimitV6, c.FirewallGroupCapacityV6, c.FirewallGroupCapacity), limit)
	return v4, v6
}

func firstNonZero(values ...int) int {
	for _, v := range values {
		if v != 0 {
			return v
		}
	}
	return 0
}

// capped returns value, or limit when value is zero or above it.
func capped(value, limit int) int {
	if value == 0 || value > limit {
		return limit
	}
	return value
}
