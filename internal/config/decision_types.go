package config

import (
	"fmt"
	"slices"
	"strings"
)

// defaultBlockDecisionType is the decision type banned when
// BLOCK_DECISION_TYPES is unset.
const defaultBlockDecisionType = "ban"

// parseBlockDecisionTypes splits BLOCK_DECISION_TYPES into lower-case,
// de-duplicated decision types. An unset or empty value bans "ban" only.
func parseBlockDecisionTypes(raw string) []string {
	var types []string
	for _, t := range splitCSV(raw) {
		t = strings.ToLower(stripEnvQuotes(t))
		if !slices.Contains(types, t) {
			types = append(types, t)
		}
	}
	if len(types) == 0 {
		return []string{defaultBlockDecisionType}
	}
	return types
}

// validateBlockDecisionTypes checks that every BLOCK_DECISION_TYPES entry
// looks like a CrowdSec decision type. "delete" is refused: it names the
// removal of a decision, not a type a decision can have.
func (c *Config) validateBlockDecisionTypes() error {
	for _, t := range c.BlockDecisionTypes {
		if t == "delete" {
			return fmt.Errorf("BLOCK_DECISION_TYPES: %q is not a decision type; deleted decisions are always handled", t)
		}
		if !isDecisionType(t) {
			return fmt.Errorf("BLOCK_DECISION_TYPES: invalid decision type %q; use lower-case letters, digits, '_' and '-', such as ban,captcha", t)
		}
	}
	return nil
}

// isDecisionType reports whether s is 1 to 64 characters of a-z, 0-9, '_'
// and '-'.
func isDecisionType(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' && r != '-' {
			return false
		}
	}
	return true
}
