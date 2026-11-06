package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/spf13/cobra"
)

// statusSyncCmd prints the running bouncer's firewall sync state. It exists
// only in the running process, so there is no database fallback.
func statusSyncCmd(dataDir *string) *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "sync",
		Short: "Show the running bouncer's firewall sync state",
		Long: `Show dirty shards, bans not yet enforced, the circuit breaker state and the
last complete sync, as the running bouncer reports them on HEALTH_ADDR.
Run it inside the bouncer's container (docker exec).`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), 10*time.Second)
			defer cancel()
			var status bouncer.SyncStatus
			if err := callControl(ctx, *dataDir, http.MethodGet, bouncer.SyncStatusPath, nil, &status); err != nil {
				return fmt.Errorf("sync state is only available from the running bouncer: %w", err)
			}
			if asJSON {
				return writeIndentedJSON(os.Stdout, status)
			}
			return printSyncStatus(status)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the sync state as JSON")
	return cmd
}

func writeIndentedJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printSyncStatus(s bouncer.SyncStatus) error {
	w := newTable()
	fmt.Fprintln(w, "FIELD\tVALUE")
	fmt.Fprintf(w, "startup_synced\t%v\n", s.StartupSynced)
	fmt.Fprintf(w, "dirty_shards\t%d\n", s.DirtyShards)
	fmt.Fprintf(w, "unsynced_ips\t%d\n", s.UnsyncedIPs)
	for _, u := range s.UnsyncedBySite {
		fmt.Fprintf(w, "unsynced_ips[%s/%s]\t%d\n", printable(u.Site), printable(u.Family), u.Count)
	}
	fmt.Fprintf(w, "circuit_breaker_open\t%v\n", s.CircuitBreakerOpen)
	last := "-"
	if s.LastSync != nil {
		last = formatTime(*s.LastSync, "-")
		if s.LastSyncAgeSeconds != nil {
			last += fmt.Sprintf(" (%s ago)", (time.Duration(*s.LastSyncAgeSeconds) * time.Second).Round(time.Second))
		}
	}
	fmt.Fprintf(w, "last_sync\t%s\n", last)
	return w.Flush()
}
