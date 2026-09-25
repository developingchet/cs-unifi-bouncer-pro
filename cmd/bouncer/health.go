package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/spf13/cobra"
)

// healthcheckCmd probes the local health endpoint.
func healthcheckCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "healthcheck",
		Short: "Check health endpoint and exit",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 5*time.Second)
			defer cancel()
			healthURL, err := localHealthURL(cfg.HealthAddr)
			if err != nil {
				return err
			}
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, healthURL, nil)
			if err != nil {
				return err
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				return fmt.Errorf("healthcheck failed: %w", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("healthcheck returned %d", resp.StatusCode)
			}
			fmt.Println("healthy")
			return nil
		},
	}
}

func localHealthURL(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", fmt.Errorf("invalid HEALTH_ADDR: %w", err)
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "http://" + net.JoinHostPort(host, port) + "/healthz", nil
}
