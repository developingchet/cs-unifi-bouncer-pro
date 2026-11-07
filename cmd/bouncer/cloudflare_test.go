package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/whitelist"
	"github.com/rs/zerolog"
)

// recordingSyncer records the pairs of each whitelist sync.
type recordingSyncer struct {
	mu     sync.Mutex
	synced [][]whitelist.ZonePairConfig
	done   chan struct{}
}

func (s *recordingSyncer) Sync(_ context.Context, pairs []whitelist.ZonePairConfig) error {
	s.mu.Lock()
	s.synced = append(s.synced, pairs)
	s.mu.Unlock()
	s.done <- struct{}{}
	return nil
}

// A SIGHUP that changes CLOUDFLARE_ZONE_PAIRS_FILE reaches the refresh loop,
// which syncs the whitelist with the new pairs at once.
func TestReloadZonesSyncsChangedCloudflarePairs(t *testing.T) {
	probe := newReconcileProbe(t)
	file := filepath.Join(t.TempDir(), "cloudflare_zone_pairs")
	if err := os.WriteFile(file, []byte("External->Internal\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUDFLARE_WHITELIST_ENABLED", "true")
	t.Setenv("CLOUDFLARE_ZONE_PAIRS_FILE", file)
	running, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	initial, err := cloudflarePairs(running)
	if err != nil {
		t.Fatal(err)
	}
	source := newCloudflarePairSource(initial)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	syncer := &recordingSyncer{done: make(chan struct{}, 1)}
	go runCloudflareRefresh(ctx, syncer, source, time.Hour, nil, zerolog.Nop())

	if err := os.WriteFile(file, []byte("External->Dmz:443\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	reloadZones(context.Background(), running, probe, source, func() bool { return true }, zerolog.New(&out))
	if !strings.Contains(out.String(), "SIGHUP: Cloudflare zone pairs reloaded; the whitelist syncs them now") {
		t.Errorf("log does not report the Cloudflare reload: %s", out.String())
	}
	if strings.Contains(out.String(), "take effect only after a restart") {
		t.Errorf("log lists a setting as needing a restart: %s", out.String())
	}

	select {
	case <-syncer.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the whitelist was not synced after the reload")
	}
	want := []whitelist.ZonePairConfig{{SrcName: "External", DstName: "Dmz", DstPorts: []int{443}}}
	syncer.mu.Lock()
	defer syncer.mu.Unlock()
	if len(syncer.synced) != 1 || !reflect.DeepEqual(syncer.synced[0], want) {
		t.Errorf("synced %+v, want one sync of %+v", syncer.synced, want)
	}
}

// cloudflareReloadFixture loads a running configuration with the Cloudflare
// whitelist on, then points CLOUDFLARE_ZONE_PAIRS at newPairs for the reload.
func cloudflareReloadFixture(t *testing.T, newPairs string) (*reconcileProbe, *config.Config, *cloudflarePairSource) {
	t.Helper()
	probe := newReconcileProbe(t)
	t.Setenv("CLOUDFLARE_WHITELIST_ENABLED", "true")
	t.Setenv("CLOUDFLARE_ZONE_PAIRS", "External->Internal")
	running, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	initial, err := cloudflarePairs(running)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLOUDFLARE_ZONE_PAIRS", newPairs)
	return probe, running, newCloudflarePairSource(initial)
}

// A SIGHUP whose zone reload fails changes neither the zone pairs nor the
// Cloudflare pairs.
func TestReloadZonesKeepsCloudflarePairsWhenZoneReloadFails(t *testing.T) {
	probe, running, source := cloudflareReloadFixture(t, "External->Dmz")
	initial := source.Pairs()
	probe.ctrl.SetError("DiscoverZones", errors.New("controller unavailable"))

	var out bytes.Buffer
	reloadZones(context.Background(), running, probe, source, func() bool { return true }, zerolog.New(&out))

	if !strings.Contains(out.String(), "SIGHUP: zone reload failed") {
		t.Errorf("log does not report the failed zone reload: %s", out.String())
	}
	if strings.Contains(out.String(), "Cloudflare zone pairs reloaded") {
		t.Errorf("log reports a Cloudflare reload after the zone reload failed: %s", out.String())
	}
	if !reflect.DeepEqual(source.Pairs(), initial) {
		t.Errorf("Cloudflare pairs = %+v after a failed reload, want %+v", source.Pairs(), initial)
	}
	select {
	case <-source.Changed():
		t.Error("a failed reload signalled a Cloudflare sync")
	default:
	}
}

// Cloudflare pairs that name a zone the controller does not have refuse the
// whole reload, before the zone pairs change.
func TestReloadZonesRefusesCloudflarePairsWithAnUnknownZone(t *testing.T) {
	probe, running, source := cloudflareReloadFixture(t, "External->Nowhere")
	initial := source.Pairs()

	var out bytes.Buffer
	reloadZones(context.Background(), running, probe, source, func() bool { return true }, zerolog.New(&out))

	if !strings.Contains(out.String(), "SIGHUP: Cloudflare zone pairs refused; keeping the current zone pairs") ||
		!strings.Contains(out.String(), "Nowhere") {
		t.Errorf("log does not name the unknown zone: %s", out.String())
	}
	if !reflect.DeepEqual(source.Pairs(), initial) {
		t.Errorf("Cloudflare pairs = %+v after a refused reload, want %+v", source.Pairs(), initial)
	}
	if probe.reconciled != 0 || probe.repaired != 0 {
		t.Errorf("reconciled %d, repaired %d; want neither", probe.reconciled, probe.repaired)
	}
}

func TestCloudflarePairSourceSignalsOnlyChanges(t *testing.T) {
	pairs := []whitelist.ZonePairConfig{{SrcName: "External", DstName: "Internal"}}
	source := newCloudflarePairSource(pairs)
	if source.Set([]whitelist.ZonePairConfig{{SrcName: "External", DstName: "Internal"}}) {
		t.Error("Set reported a change for the same pairs")
	}
	select {
	case <-source.Changed():
		t.Error("unchanged pairs were signalled")
	default:
	}
	if !source.Set(nil) {
		t.Error("Set did not report a change")
	}
	select {
	case <-source.Changed():
	default:
		t.Error("changed pairs were not signalled")
	}
}

// Settings other than the zone pairs are read again on SIGHUP but not
// applied; the reload names them.
func TestReloadZonesNamesSettingsThatNeedARestart(t *testing.T) {
	probe := newReconcileProbe(t)
	running, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LOG_LEVEL", "debug")
	t.Setenv("CROWDSEC_LAPI_KEY", "rotated-key")
	var out bytes.Buffer
	reloadZones(context.Background(), running, probe, nil, func() bool { return true }, zerolog.New(&out))
	want := `{"level":"info","settings":["CROWDSEC_LAPI_KEY","LOG_LEVEL"],"message":"SIGHUP: changed settings take effect only after a restart"}`
	if !strings.Contains(out.String(), want) {
		t.Errorf("log lacks %s\nlog: %s", want, out.String())
	}
	if strings.Contains(out.String(), "rotated-key") {
		t.Errorf("log shows a secret value: %s", out.String())
	}
}
