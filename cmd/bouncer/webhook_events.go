package main

import (
	"errors"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/webhook"
)

// firewallHooks connects the firewall manager's callbacks to the webhook
// notifier. A nil notifier, as the one-shot commands pass, connects nothing.
func firewallHooks(n *webhook.Notifier) (cbOpen, cbClose func(), events firewall.ShardEvents) {
	if n == nil {
		return nil, nil, firewall.ShardEvents{}
	}
	cbOpen = func() { n.Fire(webhook.EventCircuitBreakerOpen, nil) }
	cbClose = func() { n.Fire(webhook.EventCircuitBreakerClose, nil) }
	events = firewall.ShardEvents{
		CreateFailed: func(f firewall.ShardCreateFailure) {
			n.FireLimited(webhook.EventShardCreateFailed, f.Site+"/"+f.Shard, map[string]any{
				"site":                 f.Site,
				"family":               f.Family,
				"shard":                f.Shard,
				"unsynced_ips":         f.UnsyncedIPs,
				"consecutive_failures": f.ConsecutiveFailures,
				"retry_in_seconds":     int(f.RetryIn.Seconds()),
			})
		},
		EntryRefused: func(r firewall.RefusedEntry) {
			n.FireLimited(webhook.EventBanEntryRefused, r.Site+"/"+r.Entry, map[string]any{
				"site":             r.Site,
				"family":           r.Family,
				"shard":            r.Shard,
				"entry":            r.Entry,
				"retry_in_seconds": int(r.RetryIn.Seconds()),
			})
		},
	}
	return cbOpen, cbClose, events
}

// fireModeChanged reports that the daemon is exiting to restart in another
// firewall mode. It is sent once: the process ends right after.
func fireModeChanged(n *webhook.Notifier, err error) {
	detail := map[string]any{}
	var changed *firewall.ModeChangeError
	if errors.As(err, &changed) {
		detail["site"] = changed.Site
		detail["reason"] = changed.Reason
	}
	n.Fire(webhook.EventFirewallModeChanged, detail)
}

// fireCloudflareSyncFailed reports a failed Cloudflare whitelist sync, at most
// once an hour; phase is "initial", "refresh" or "reload".
func fireCloudflareSyncFailed(n *webhook.Notifier, phase string) {
	n.FireLimited(webhook.EventCloudflareSyncFailed, "", map[string]any{"phase": phase})
}
