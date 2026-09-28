package blocklist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/banstate"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/logger"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
	"github.com/rs/zerolog"
)

func TestMigrateLegacySources(t *testing.T) {
	const token = "private-path-token"
	url := "https://feed.example/" + token + "/list?key=query-secret"
	plain := Feed{URL: url}
	abuse := Feed{URL: url, SourceKind: SourceKindAbuseIPDB}
	legacy := "blocklist:" + logger.SafeURL(url)
	expiry := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	for _, tc := range []struct {
		name  string
		feeds []Feed
		want  string
	}{
		{"single owner", []Feed{plain}, plain.sourceKey()},
		{"shared legacy key", []Feed{plain, abuse}, "blocklist:legacy:sha256:"},
		{"removed feed", nil, "blocklist:legacy:sha256:"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, err := storage.NewBboltStore(t.TempDir(), zerolog.Nop(), 0)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			if err := store.BanPut("203.0.113.7", storage.BanEntry{
				ExpiresAt: expiry,
				Claims: map[string]time.Time{
					legacy:           expiry,
					"crowdsec:other": expiry.Add(-time.Minute),
				},
			}); err != nil {
				t.Fatal(err)
			}
			for range 2 { // repeat to prove the conversion is stable on restart
				if err := MigrateLegacySources(store, tc.feeds); err != nil {
					t.Fatal(err)
				}
			}
			entry, err := store.BanGet("203.0.113.7")
			if err != nil || entry == nil {
				t.Fatalf("BanGet = %v, %v", entry, err)
			}
			if len(entry.Claims) != 2 || !entry.ExpiresAt.Equal(expiry) {
				t.Fatalf("migration changed ban ownership or expiry: %+v", entry)
			}
			for source, got := range entry.Claims {
				if strings.Contains(source, token) || strings.Contains(source, "query-secret") || source == legacy {
					t.Fatalf("URL credential remains in stored claim: %q", source)
				}
				if source == "crowdsec:other" {
					continue
				}
				if !strings.HasPrefix(source, tc.want) || !got.Equal(expiry) {
					t.Fatalf("migrated claim = %q %s, want %q at %s", source, got, tc.want, expiry)
				}
			}
		})
	}
}

func TestMigrateLegacySourceKeepsBanThroughFeedOutage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	feed := Feed{URL: srv.URL + "/private-path-token/list"}
	store, err := storage.NewBboltStore(t.TempDir(), zerolog.Nop(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	expiry := time.Now().Add(time.Minute).UTC()
	if err := store.BanPut("203.0.113.8", storage.BanEntry{
		ExpiresAt: expiry,
		Claims:    map[string]time.Time{"blocklist:" + logger.SafeURL(feed.URL): expiry},
	}); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacySources(store, []Feed{feed}); err != nil {
		t.Fatal(err)
	}
	claims := banstate.New(store, &mockFWManager{}, []string{"default"}, false)
	mgr := NewFeedManager([]Feed{feed}, time.Hour, 24*time.Hour, claims, nil, false, zerolog.Nop())
	mgr.fetchAndApply(context.Background())
	entry, err := store.BanGet("203.0.113.8")
	if err != nil || entry == nil {
		t.Fatalf("BanGet = %v, %v", entry, err)
	}
	if got := entry.Claims[feed.sourceKey()]; !got.After(expiry) {
		t.Fatalf("migrated claim not extended on outage: %s, original %s", got, expiry)
	}
}
