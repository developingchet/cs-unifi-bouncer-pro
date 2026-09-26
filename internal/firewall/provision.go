package firewall

import (
	"errors"
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
