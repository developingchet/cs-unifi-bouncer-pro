package main

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/spf13/cobra"
)

// buildRoot constructs the root command as main() does, for use in tests.
func buildRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "cs-unifi-bouncer-pro",
		Short: "CrowdSec bouncer for UniFi firewall management",
	}
	root.AddCommand(runCmd(), healthcheckCmd(), versionCmd(), reconcileCmd())
	return root
}

// TestRootSubcommands verifies all expected subcommands are registered.
func TestRootSubcommands(t *testing.T) {
	root := buildRoot()

	registered := make(map[string]bool)
	for _, cmd := range root.Commands() {
		registered[cmd.Use] = true
	}

	for _, want := range []string{"run", "version", "healthcheck", "reconcile"} {
		if !registered[want] {
			t.Errorf("subcommand %q not registered on root command", want)
		}
	}
}

// TestVersionOutput verifies the version subcommand prints the binary name.
func TestVersionOutput(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout := os.Stdout
	os.Stdout = w

	root := buildRoot()
	root.SetArgs([]string{"version"})
	execErr := root.Execute()

	w.Close()
	os.Stdout = oldStdout

	if execErr != nil {
		t.Fatalf("version command returned error: %v", execErr)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(buf.String(), "cs-unifi-bouncer-pro") {
		t.Errorf("version output %q does not contain expected string %q", buf.String(), "cs-unifi-bouncer-pro")
	}
}

// TestRunDaemonMissingConfig verifies runDaemon returns an error (not panics)
// when UNIFI_URL is not set.
func TestRunDaemonMissingConfig(t *testing.T) {
	t.Setenv("UNIFI_URL", "")

	err := runDaemon()
	if err == nil {
		t.Fatal("expected runDaemon() to return an error when UNIFI_URL is missing")
	}
}

// TestLoadMissingRequired verifies config.Load returns a descriptive error
// when required environment variables are absent.
func TestLoadMissingRequired(t *testing.T) {
	t.Setenv("UNIFI_URL", "")

	_, err := config.Load()
	if err == nil {
		t.Fatal("expected config.Load() to return an error with missing required vars")
	}
	if !strings.Contains(err.Error(), "UNIFI_URL") {
		t.Errorf("expected error message to mention UNIFI_URL; got: %v", err)
	}
}
