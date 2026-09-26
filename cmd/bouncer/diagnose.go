package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/lapihttp"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
)

// validateCmd loads and validates config without making any API calls.
func validateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "validate",
		Short: "Validate configuration and exit (no API calls)",
		Long: `Load configuration from environment variables, run all validation rules,
and print a human-readable summary. Exits 0 on success, 1 on error.
No API calls are made — safe to run in CI without network access.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				fmt.Fprintf(os.Stderr, "configuration invalid: %v\n", err)
				os.Exit(1)
			}

			pairs, err := cfg.ParseZonePairs()
			if err != nil {
				fmt.Fprintf(os.Stderr, "configuration invalid: %v\n", err)
				os.Exit(1)
			}
			pairStr := fmt.Sprintf("%d pair(s)", len(pairs))
			if len(pairs) > 0 {
				parts := make([]string, 0, len(pairs))
				for _, p := range pairs {
					parts = append(parts, p.Src+"->"+p.Dst)
				}
				pairStr = strings.Join(parts, ", ")
			}

			v4Cap, _ := resolveCapacities(cfg)

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "FIELD\tVALUE")
			fmt.Fprintf(w, "firewall_mode\t%s\n", cfg.FirewallMode)
			fmt.Fprintf(w, "zone_pairs\t%s\n", pairStr)
			fmt.Fprintf(w, "sites\t%s\n", strings.Join(cfg.UnifiSites, ", "))
			fmt.Fprintf(w, "ban_ttl\t%s\n", cfg.BanTTL)
			fmt.Fprintf(w, "shard_capacity\t%d\n", v4Cap)
			fmt.Fprintf(w, "cb_threshold\t%d\n", cfg.CircuitBreakerThreshold)
			fmt.Fprintf(w, "cb_reset_interval\t%s\n", cfg.CircuitBreakerResetInterval)
			fmt.Fprintf(w, "lapi_url\t%s\n", cfg.CrowdSecLAPIURL)
			fmt.Fprintf(w, "unifi_url\t%s\n", cfg.UnifiURL)
			if cfg.MetricsEnabled {
				fmt.Fprintf(w, "metrics_addr\t%s\n", cfg.MetricsAddr)
			} else {
				fmt.Fprintf(w, "metrics_addr\t(disabled)\n")
			}
			fmt.Fprintf(w, "health_addr\t%s\n", cfg.HealthAddr)
			_ = w.Flush()

			for _, warn := range cfg.DeprecationWarnings {
				fmt.Fprintf(os.Stderr, "WARNING: %s\n", warn)
			}
			if w2 := cfg.InsecureLAPIURLWarning(); w2 != "" {
				fmt.Fprintf(os.Stderr, "WARNING: %s\n", w2)
			}

			fmt.Println("\nconfiguration valid ✓")
			return nil
		},
	}
}

// diagCheck is a single row in the diagnose output table.
type diagCheck struct {
	name   string
	status string // "PASS", "FAIL", or "" for detail-only rows
	detail string
}

// diagnoseCmd runs a structured connectivity probe against LAPI and UniFi.
func diagnoseCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diagnose",
		Short: "Run connectivity checks against LAPI and UniFi controller",
		Long: `Runs three-phase diagnostics:
  1. Load and validate configuration
  2. Probe CrowdSec LAPI reachability
  3. Probe UniFi controller reachability, and if zone mode: discover and list zones

Exits 0 when all checks pass, 1 if any check fails.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var checks []diagCheck
			allPass := true

			cfg, err := config.Load()
			if err != nil {
				checks = append(checks, diagCheck{"config_valid", "FAIL", err.Error()})
				printDiagChecks(checks)
				os.Exit(1)
			}
			checks = append(checks, diagCheck{
				"config_valid", "PASS",
				fmt.Sprintf("mode=%s sites=%v", cfg.FirewallMode, cfg.UnifiSites),
			})

			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			lapiCheck := probeLAPI(ctx, cfg)
			checks = append(checks, lapiCheck)
			allPass = allPass && lapiCheck.status != "FAIL"

			ctrl, ctrlErr := controller.NewClient(ctx, controllerConfig(cfg), zerolog.Nop())
			if ctrlErr != nil {
				checks = append(checks, diagCheck{"unifi_reachable", "FAIL", ctrlErr.Error()})
				allPass = false
				printDiagChecks(checks)
				if !allPass {
					os.Exit(1)
				}
				return nil
			}
			defer ctrl.Close()

			if pingErr := ctrl.Ping(ctx); pingErr != nil {
				checks = append(checks, diagCheck{"unifi_reachable", "FAIL", pingErr.Error()})
				allPass = false
			} else {
				checks = append(checks, diagCheck{"unifi_reachable", "PASS", cfg.UnifiURL + " ping ok"})
			}

			if cfg.FirewallMode != "legacy" {
				for _, site := range cfg.UnifiSites {
					siteChecks, ok := diagnoseSiteZones(ctx, ctrl, cfg.FirewallMode, site)
					checks = append(checks, siteChecks...)
					allPass = allPass && ok
				}
			}

			printDiagChecks(checks)
			if !allPass {
				os.Exit(1)
			}
			return nil
		},
	}
}

// probeLAPI checks that the LAPI answers an authenticated decision query.
// A 401 or 403 fails (CrowdSec answers 403 to an unknown bouncer key); any
// other non-2xx answer is a warning.
func probeLAPI(ctx context.Context, cfg *config.Config) diagCheck {
	const name = "lapi_reachable"
	client, err := lapihttp.NewClient(cfg.CrowdSecLAPIVerifyTLS, cfg.CrowdSecLAPICACert, 10*time.Second)
	if err != nil {
		return diagCheck{name, "FAIL", err.Error()}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.CrowdSecLAPIURL+"/v1/decisions?limit=1", nil)
	if err != nil {
		return diagCheck{name, "FAIL", err.Error()}
	}
	req.Header.Set("X-Api-Key", cfg.CrowdSecLAPIKey)
	resp, err := client.Do(req)
	if err != nil {
		return diagCheck{name, "FAIL", err.Error()}
	}
	_ = resp.Body.Close()
	detail := fmt.Sprintf("%s → %d %s", cfg.CrowdSecLAPIURL, resp.StatusCode, http.StatusText(resp.StatusCode))
	switch {
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return diagCheck{name, "FAIL", detail + " — authentication failed; check CROWDSEC_LAPI_KEY"}
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return diagCheck{name, "PASS", detail}
	default:
		return diagCheck{name, "WARN", detail}
	}
}

// diagnoseSiteZones resolves the firewall mode for one site (in auto mode, the
// same way startup does) and lists its zones when the site uses zone mode.
// Listing zones needs the integration API, so running it against a legacy
// site authenticated by username/password would report a false failure.
func diagnoseSiteZones(ctx context.Context, ctrl controller.Controller, mode, site string) ([]diagCheck, bool) {
	if mode == "auto" {
		hasZones, err := ctrl.HasFeature(ctx, site, controller.FeatureZoneBasedFirewall)
		if err != nil {
			return []diagCheck{{"firewall_mode[" + site + "]", "FAIL", err.Error()}}, false
		}
		if !hasZones {
			return []diagCheck{{"firewall_mode[" + site + "]", "PASS", "legacy (site has no firewall zones)"}}, true
		}
	}
	checks := []diagCheck{{"firewall_mode[" + site + "]", "PASS", "zone"}}
	zones, err := ctrl.DiscoverZones(ctx, site)
	if err != nil {
		return append(checks, diagCheck{"zone_discovery[" + site + "]", "FAIL", err.Error()}), false
	}
	checks = append(checks, diagCheck{"zone_discovery[" + site + "]", "PASS", fmt.Sprintf("%d zones found", len(zones))})
	for _, z := range zones {
		checks = append(checks, diagCheck{"  " + z.Name, "", "id=" + z.ID})
	}
	return checks, true
}

func printDiagChecks(checks []diagCheck) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "CHECK\tSTATUS\tDETAIL")
	for _, c := range checks {
		fmt.Fprintf(w, "%s\t%s\t%s\n", c.name, c.status, c.detail)
	}
	_ = w.Flush()
}
