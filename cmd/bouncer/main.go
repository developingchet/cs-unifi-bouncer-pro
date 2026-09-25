package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Version, Commit, and BuildDate are set by the build system via -ldflags.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildDate = "unknown"
)

func main() {
	root := &cobra.Command{
		Use:   "cs-unifi-bouncer-pro",
		Short: "CrowdSec bouncer for UniFi firewall management",
		// main prints the error once; usage is only useful for argument errors,
		// which cobra reports before PersistentPreRun runs.
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			cmd.SilenceUsage = true
		},
	}

	root.AddCommand(
		runCmd(),
		healthcheckCmd(),
		versionCmd(),
		reconcileCmd(),
		statusCmd(),
		drainCmd(),
		validateCmd(),
		diagnoseCmd(),
		banCmd(),
		unbanCmd(),
	)

	if err := root.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// runCmd is the main daemon command.
func runCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "Start the bouncer daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDaemon()
		},
	}
}

// versionCmd prints the version, commit, and build date, then exits.
func versionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information and exit",
		Long:  "Print the version, commit hash, and build date, then exit 0.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("cs-unifi-bouncer-pro %s (commit: %s, built: %s)\n",
				Version, Commit, BuildDate)
		},
	}
}
