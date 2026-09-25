package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/spf13/cobra"
)

// statusCmd prints a read-only summary of the bbolt database state.
// It opens the database in read-only mode and prints ban counts, group info,
// and policy info. It makes no API calls and needs the daemon's database lock released.
func statusCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Print a read-only summary of bbolt state (no API calls)",
		Long: `Print ban counts, shard groups, and firewall policies stored in bbolt.
Opens the database in read-only mode. Stop the daemon first to release its database lock.`,
	}

	defaultDataDir := os.Getenv("DATA_DIR")
	if defaultDataDir == "" {
		defaultDataDir = "/data"
	}
	var dataDir string
	// Persistent so subcommands inherit it.
	cmd.PersistentFlags().StringVar(&dataDir, "data-dir", defaultDataDir,
		"Path to the data directory containing bouncer.db (env: DATA_DIR)")

	cmd.RunE = func(*cobra.Command, []string) error {
		return withReadOnlyStore(dataDir, printStatusSummary)
	}
	cmd.AddCommand(statusBansCmd(&dataDir), statusIPCmd(&dataDir), statusHistoryCmd(&dataDir))
	return cmd
}

// withReadOnlyStore opens the database read-only for the duration of fn.
func withReadOnlyStore(dataDir string, fn func(storage.Store) error) error {
	store, err := storage.NewBboltStoreReadOnly(dataDir)
	if err != nil {
		return fmt.Errorf("open store (read-only): %w", err)
	}
	defer store.Close()
	return fn(store)
}

func newTable() *tabwriter.Writer {
	return tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
}

func isExpired(e storage.BanEntry, now time.Time) bool {
	return !e.ExpiresAt.IsZero() && e.ExpiresAt.Before(now)
}

// formatTime renders t as RFC 3339 UTC, or zero when t is unset.
func formatTime(t time.Time, zero string) string {
	if t.IsZero() {
		return zero
	}
	return t.UTC().Format(time.RFC3339)
}

func printStatusSummary(store storage.Store) error {
	banList, err := store.BanList()
	if err != nil {
		return fmt.Errorf("list bans: %w", err)
	}
	groups, err := store.ListGroups()
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}
	policies, err := store.ListPolicies()
	if err != nil {
		return fmt.Errorf("list policies: %w", err)
	}
	sizeBytes, err := store.SizeBytes()
	if err != nil {
		return fmt.Errorf("db size: %w", err)
	}

	now := time.Now()
	var activeBans, expiredBans int
	for _, entry := range banList {
		if isExpired(entry, now) {
			expiredBans++
		} else {
			activeBans++
		}
	}
	var lastGroupUpdate time.Time
	for _, rec := range groups {
		if rec.UpdatedAt.After(lastGroupUpdate) {
			lastGroupUpdate = rec.UpdatedAt
		}
	}

	w := newTable()
	fmt.Fprintln(w, "FIELD\tVALUE")
	fmt.Fprintf(w, "bans_active\t%d\n", activeBans)
	fmt.Fprintf(w, "bans_expired\t%d\n", expiredBans)
	fmt.Fprintf(w, "groups\t%d\n", len(groups))
	fmt.Fprintf(w, "policies\t%d\n", len(policies))
	fmt.Fprintf(w, "db_size_bytes\t%d\n", sizeBytes)
	fmt.Fprintf(w, "last_group_update\t%s\n", formatTime(lastGroupUpdate, "-"))
	return w.Flush()
}

// banFilter selects the rows `status bans` prints.
type banFilter struct {
	top      int
	sortBy   string
	expiring time.Duration
	expired  bool
}

type banRow struct {
	ip    string
	entry storage.BanEntry
}

func (f banFilter) apply(bans map[string]storage.BanEntry, now time.Time) []banRow {
	var rows []banRow
	for ip, entry := range bans {
		if isExpired(entry, now) != f.expired {
			continue
		}
		if f.expiring > 0 && (entry.ExpiresAt.IsZero() || entry.ExpiresAt.After(now.Add(f.expiring))) {
			continue
		}
		rows = append(rows, banRow{ip: ip, entry: entry})
	}
	sort.Slice(rows, func(i, j int) bool {
		if f.sortBy == "ip" {
			return rows[i].ip < rows[j].ip
		}
		return rows[i].entry.RecordedAt.After(rows[j].entry.RecordedAt)
	})
	if f.top > 0 && len(rows) > f.top {
		rows = rows[:f.top]
	}
	return rows
}

func statusBansCmd(dataDir *string) *cobra.Command {
	var f banFilter
	cmd := &cobra.Command{
		Use:   "bans",
		Short: "List tracked bans from bbolt",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			if f.sortBy != "ip" && f.sortBy != "recorded_at" {
				return fmt.Errorf("--sort must be recorded_at or ip, got %q", f.sortBy)
			}
			return withReadOnlyStore(*dataDir, func(store storage.Store) error {
				bans, err := store.BanList()
				if err != nil {
					return fmt.Errorf("list bans: %w", err)
				}
				now := time.Now()
				w := newTable()
				fmt.Fprintln(w, "IP\tIPv6\tRECORDED_AT\tEXPIRES_AT\tEXPIRED")
				for _, r := range f.apply(bans, now) {
					fmt.Fprintf(w, "%s\t%v\t%s\t%s\t%v\n", r.ip, r.entry.IPv6,
						formatTime(r.entry.RecordedAt, "-"), formatTime(r.entry.ExpiresAt, "-"), isExpired(r.entry, now))
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().IntVar(&f.top, "top", 0, "Limit output to top N rows (0 = all)")
	cmd.Flags().StringVar(&f.sortBy, "sort", "recorded_at", "Sort by: recorded_at | ip")
	cmd.Flags().DurationVar(&f.expiring, "expiring", 0, "Show only bans expiring within this window (e.g. 24h)")
	cmd.Flags().BoolVar(&f.expired, "expired", false, "Show only already-expired bans")
	return cmd
}

func statusIPCmd(dataDir *string) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "ip <IP>",
		Short: "Show ban details and event history for a specific IP",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			ip := args[0]
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("%q is not a valid IP address", ip)
			}
			return withReadOnlyStore(*dataDir, func(store storage.Store) error {
				entry, err := store.BanGet(ip)
				if err != nil {
					return fmt.Errorf("get ban: %w", err)
				}
				if err := printBan(newTable(), ip, entry); err != nil {
					return err
				}
				events, err := store.ListEventsForIP(ip, limit)
				if err != nil {
					return fmt.Errorf("list events for IP: %w", err)
				}
				if len(events) == 0 {
					return nil
				}
				fmt.Println()
				w := newTable()
				fmt.Fprintln(w, "TIME\tACTION\tORIGIN\tSCENARIO")
				for _, e := range events {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", formatTime(e.RecordedAt, "-"), e.Action, e.Origin, e.Scenario)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum number of history events to show")
	return cmd
}

func printBan(w *tabwriter.Writer, ip string, entry *storage.BanEntry) error {
	if entry == nil {
		fmt.Fprintf(w, "ip\t%s\n", ip)
		fmt.Fprintf(w, "status\tnot banned\n")
		return w.Flush()
	}
	fmt.Fprintln(w, "FIELD\tVALUE")
	fmt.Fprintf(w, "ip\t%s\n", ip)
	fmt.Fprintf(w, "ipv6\t%v\n", entry.IPv6)
	fmt.Fprintf(w, "recorded_at\t%s\n", formatTime(entry.RecordedAt, "-"))
	fmt.Fprintf(w, "expires_at\t%s\n", formatTime(entry.ExpiresAt, "never"))
	fmt.Fprintf(w, "expired\t%v\n", isExpired(*entry, time.Now()))
	return w.Flush()
}

func statusHistoryCmd(dataDir *string) *cobra.Command {
	var limit int
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Show recent ban/unban audit trail events",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			return withReadOnlyStore(*dataDir, func(store storage.Store) error {
				events, err := store.ListEvents(limit)
				if err != nil {
					return fmt.Errorf("list events: %w", err)
				}
				w := newTable()
				fmt.Fprintln(w, "TIME\tACTION\tIP\tORIGIN\tSCENARIO")
				for _, e := range events {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", formatTime(e.RecordedAt, "-"), e.Action, e.IP, e.Origin, e.Scenario)
				}
				return w.Flush()
			})
		},
	}
	cmd.Flags().IntVar(&limit, "limit", 50, "Maximum number of events to show")
	return cmd
}
