package lapi_metrics

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/capabilities"
	"github.com/rs/zerolog"
)

const minInterval = 10 * time.Minute

// Reporter pushes usage metrics to the CrowdSec LAPI on a configurable interval.
type Reporter struct {
	lapiURL     string
	apiKey      string
	version     string
	interval    time.Duration
	startupTime time.Time
	log         zerolog.Logger
	httpClient  *http.Client

	mu        sync.Mutex
	blocked   map[originKey]int64
	processed int64
}

type originKey struct {
	origin          string
	remediationType string
}

// NewReporter constructs a Reporter. If interval > 0 and < 10m, it is clamped to 10m.
func NewReporter(lapiURL, apiKey, version string, interval time.Duration, log zerolog.Logger) *Reporter {
	if interval > 0 && interval < minInterval {
		log.Warn().
			Dur("requested", interval).
			Dur("enforced", minInterval).
			Msg("LAPI_METRICS_PUSH_INTERVAL below minimum; clamping to 10m")
		interval = minInterval
	}
	return &Reporter{
		lapiURL:     lapiURL,
		apiKey:      apiKey,
		version:     version,
		interval:    interval,
		startupTime: time.Now(),
		log:         log,
		httpClient:  &http.Client{Timeout: 5 * time.Second},
		blocked:     make(map[originKey]int64),
	}
}

// RecordBan increments the blocked counter for the given origin+type pair and processed.
func (r *Reporter) RecordBan(origin, remediationType string) {
	r.mu.Lock()
	r.blocked[originKey{origin, remediationType}]++
	r.processed++
	r.mu.Unlock()
}

// RecordDeletion increments only the processed counter.
func (r *Reporter) RecordDeletion() {
	r.mu.Lock()
	r.processed++
	r.mu.Unlock()
}

// Run starts the periodic push loop. Returns immediately if interval == 0.
func (r *Reporter) Run(ctx context.Context) {
	if r.interval == 0 {
		return
	}

	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := r.push(ctx); err != nil {
				r.log.Warn().Err(err).Msg("lapi usage-metrics push failed")
			}
		case <-ctx.Done():
			// Drain a pending tick before the final push.
			select {
			case <-ticker.C:
			default:
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := r.push(shutdownCtx); err != nil {
				r.log.Warn().Err(err).Msg("lapi usage-metrics final push failed")
			}
			return
		}
	}
}

// push snapshots and resets counters, then POSTs them to the LAPI.
func (r *Reporter) push(ctx context.Context) error {
	// Snapshot and reset under lock.
	r.mu.Lock()
	blocked := r.blocked
	processed := r.processed
	r.blocked = make(map[originKey]int64)
	r.processed = 0
	r.mu.Unlock()

	now := time.Now()

	// Build per-origin blocked metrics (only entries with count > 0).
	type metricEntry struct {
		Name   string            `json:"name"`
		Value  int64             `json:"value"`
		Unit   string            `json:"unit"`
		Labels map[string]string `json:"labels,omitempty"`
	}

	var metricItems []metricEntry
	for key, count := range blocked {
		if count <= 0 {
			continue
		}
		metricItems = append(metricItems, metricEntry{
			Name:  "blocked",
			Value: count,
			Unit:  "request",
			Labels: map[string]string{
				"origin":           key.origin,
				"remediation_type": key.remediationType,
			},
		})
	}
	metricItems = append(metricItems, metricEntry{
		Name:  "processed",
		Value: processed,
		Unit:  "request",
	})

	osName, osVersion := detectOS()

	type osMeta struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	type windowMeta struct {
		WindowSizeSeconds   int64 `json:"window_size_seconds"`
		UtcStartupTimestamp int64 `json:"utc_startup_timestamp"`
		UtcNowTimestamp     int64 `json:"utc_now_timestamp"`
	}
	type component struct {
		Type     string        `json:"type"`
		Version  string        `json:"version"`
		Os       osMeta        `json:"os"`
		Features []string      `json:"features"`
		Meta     windowMeta    `json:"meta"`
		Metrics  []metricEntry `json:"metrics"`
	}
	type payload struct {
		RemediationComponents []component `json:"remediation_components"`
	}

	body, err := json.Marshal(payload{
		RemediationComponents: []component{
			{
				Type:     capabilities.BouncerType,
				Version:  r.version,
				Os:       osMeta{Name: osName, Version: osVersion},
				Features: []string{},
				Meta: windowMeta{
					WindowSizeSeconds:   int64(r.interval.Seconds()),
					UtcStartupTimestamp: r.startupTime.Unix(),
					UtcNowTimestamp:     now.Unix(),
				},
				Metrics: metricItems,
			},
		},
	})
	if err != nil {
		return fmt.Errorf("marshal usage-metrics payload: %w", err)
	}

	url := strings.TrimRight(r.lapiURL, "/") + "/v1/usage-metrics"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build usage-metrics request: %w", err)
	}
	req.Header.Set("X-Api-Key", r.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "crowdsec-unifi-bouncer/v"+r.version)

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("POST usage-metrics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		r.log.Warn().
			Int("status", resp.StatusCode).
			Str("url", url).
			Msg("lapi usage-metrics returned non-2xx")
	}
	return nil
}

// detectOS returns the OS name from runtime.GOOS and attempts to read VERSION_ID
// from /etc/os-release. On failure the version is empty.
func detectOS() (name, version string) {
	name = runtime.GOOS

	f, err := os.Open("/etc/os-release")
	if err != nil {
		return name, ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "VERSION_ID=") {
			val := strings.TrimPrefix(line, "VERSION_ID=")
			val = strings.Trim(val, `"`)
			return name, val
		}
	}
	return name, ""
}
