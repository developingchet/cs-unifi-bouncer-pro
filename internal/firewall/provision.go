package firewall

import (
	"errors"
	"fmt"
	"strings"
)

// ShardProvisionError collects the shards whose block policies or rules could
// not be ensured. Each one is marked for retry on the next sync, and its bans
// are reported as unenforced until then, so callers may treat it as non-fatal.
type ShardProvisionError struct {
	Errs []error
}

func (e *ShardProvisionError) Error() string {
	msgs := make([]string, len(e.Errs))
	for i, err := range e.Errs {
		msgs[i] = err.Error()
	}
	return "shards without a block policy or rule: " + strings.Join(msgs, "; ")
}

func (e *ShardProvisionError) Unwrap() []error { return e.Errs }

// Shards names the failed shards, e.g. "v4-3", in the order they failed.
func (e *ShardProvisionError) Shards() []string {
	var names []string
	seen := make(map[string]bool)
	for _, err := range e.Errs {
		var se *shardError
		if errors.As(err, &se) {
			name := fmt.Sprintf("%s-%d", se.family, se.index)
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// shardError is the failure to provision one shard.
type shardError struct {
	family string
	index  int
	scope  string // zone pair, empty in legacy mode
	err    error
}

func (e *shardError) Error() string {
	if e.scope != "" {
		return fmt.Sprintf("%s shard %d (%s): %v", e.family, e.index, e.scope, e.err)
	}
	return fmt.Sprintf("%s shard %d: %v", e.family, e.index, e.err)
}

func (e *shardError) Unwrap() error { return e.err }

// provisionFailure returns nil when every shard was provisioned.
func provisionFailure(failed []error) error {
	if len(failed) == 0 {
		return nil
	}
	return &ShardProvisionError{Errs: failed}
}

// IsShardProvisionError reports whether err only concerns individual shards
// that are already scheduled for retry.
func IsShardProvisionError(err error) bool {
	var spe *ShardProvisionError
	return errors.As(err, &spe)
}
