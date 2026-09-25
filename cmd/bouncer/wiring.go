package main

import (
	"fmt"
	"os"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/controller"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/firewall"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

// nopRecorder is a MetricsRecorder that discards all recordings.
// Used when LAPI_METRICS_PUSH_INTERVAL=0 (reporting disabled).
type nopRecorder struct{}

func (nopRecorder) RecordBan(_, _ string) {}

func (nopRecorder) RecordDeletion() {}

func openStore(cfg *config.Config, log zerolog.Logger) (storage.Store, error) {
	if cfg.DryRun {
		return storage.NewDryRunStore(cfg.DataDir)
	}
	return storage.NewBboltStore(cfg.DataDir, log, cfg.HistoryMaxEvents)
}

func controllerConfig(cfg *config.Config) controller.ClientConfig {
	return controller.ClientConfig{
		BaseURL:       cfg.UnifiURL,
		Username:      cfg.UnifiUsername,
		Password:      cfg.UnifiPassword,
		APIKey:        cfg.UnifiAPIKey,
		VerifyTLS:     cfg.UnifiVerifyTLS,
		CACertPath:    cfg.UnifiCACert,
		Timeout:       cfg.UnifiHTTPTimeout,
		Debug:         cfg.UnifiAPIDebug,
		ReauthMinGap:  cfg.SessionReauthMinGap,
		ReauthTimeout: cfg.SessionReauthTimeout,
		DryRun:        cfg.DryRun,
		EnableIPv6:    cfg.EnableIPv6,
	}
}

// buildFWManager constructs a firewall.Manager from config, controller, store, and logger.
// It does NOT call EnsureInfrastructure — callers do that themselves when needed.
// cbOpen and cbClose are optional callbacks fired when the circuit breaker opens/closes; pass nil for no-op.
func buildFWManager(cfg *config.Config,
	ctrl controller.Controller, store storage.Store, log zerolog.Logger,
	cbOpen, cbClose func(),
) (firewall.Manager, error) {
	namer, err := firewall.NewNamer(
		cfg.GroupNameTemplate,
		cfg.RuleNameTemplate,
		cfg.PolicyNameTemplate)

	if err != nil {
		return nil, fmt.Errorf("build namer: %w", err)
	}

	v4Cap, v6Cap := resolveCapacities(cfg)

	zonePairs, err := cfg.ParseZonePairs()
	if err != nil {
		return nil, fmt.Errorf("parse zone pairs: %w", err)
	}
	connectionStates, err := cfg.ParseFirewallConnectionStates()
	if err != nil {
		return nil, err
	}

	return firewall.NewManager(firewall.ManagerConfig{
		FirewallMode:                cfg.FirewallMode,
		EnableIPv6:                  cfg.FirewallEnableIPv6,
		GroupCapacityV4:             v4Cap,
		GroupCapacityV6:             v6Cap,
		DryRun:                      cfg.DryRun,
		APIShardDelay:               cfg.FirewallAPIShardDelay,
		FlushConcurrency:            cfg.FirewallFlushConcurrency,
		CircuitBreakerThreshold:     cfg.CircuitBreakerThreshold,
		CircuitBreakerResetInterval: cfg.CircuitBreakerResetInterval,
		ShardMergeThreshold:         cfg.ShardMergeThreshold,
		OnCircuitBreakerOpen:        cbOpen,
		OnCircuitBreakerClose:       cbClose,
		LegacyCfg: firewall.LegacyConfig{
			RuleIndexStartV4: cfg.LegacyRuleIndexStartV4,
			RuleIndexStartV6: cfg.LegacyRuleIndexStartV6,
			RulesetV4:        cfg.LegacyRulesetV4,
			RulesetV6:        cfg.LegacyRulesetV6,
			BlockAction:      cfg.FirewallBlockAction,
			LogDrops:         cfg.FirewallLogDrops,
			Description:      cfg.ObjectDescription,
			APIWriteDelay:    cfg.FirewallAPIShardDelay,
		},
		ZoneCfg: firewall.ZoneConfig{
			ZonePairs:        zonePairs,
			Description:      cfg.ObjectDescription,
			LogDrops:         cfg.FirewallLogDrops,
			ConnectionStates: connectionStates,
			APIWriteDelay:    cfg.FirewallAPIShardDelay,
		},
	}, ctrl, store, namer, log), nil
}

// resolveCapacities determines effective v4/v6 group capacities from config,
// applying the per-family overrides and falling back to the shared capacity.
func resolveCapacities(cfg *config.Config) (v4Cap, v6Cap int) {
	v4Cap = cfg.FirewallGroupCapacityV4
	if v4Cap == 0 {
		v4Cap = cfg.FirewallGroupCapacity
	}
	v6Cap = cfg.FirewallGroupCapacityV6
	if v6Cap == 0 {
		v6Cap = v4Cap
	}
	// SHARD_LIMIT is the controller's hard ceiling for each managed list.
	// Per-family capacity settings may lower it but must not exceed it.
	limit := cfg.ShardLimit
	if limit == 0 {
		limit = firewall.ShardLimit
	}
	if v4Cap == 0 || v4Cap > limit {
		v4Cap = limit
	}
	if v6Cap == 0 || v6Cap > limit {
		v6Cap = limit
	}
	return v4Cap, v6Cap
}

// buildLogger constructs a zerolog.Logger based on config.
func buildLogger(cfg *config.Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}

	var base zerolog.Logger
	if cfg.LogFormat == "text" {
		cw := zerolog.NewConsoleWriter()
		cw.Out = logger.NewRedactWriter(os.Stderr)
		base = zerolog.New(cw).Level(level).With().Timestamp().Logger()
	} else {
		redactWriter := logger.NewRedactWriter(os.Stderr)
		base = zerolog.New(redactWriter).Level(level).With().Timestamp().Logger()
	}
	logger.ForwardLogrus(base)
	return base
}
