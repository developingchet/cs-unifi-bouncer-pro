package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// loadWith loads the configuration from baseEnv plus env.
func loadWith(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	baseEnv(t)
	for k, v := range env {
		t.Setenv(k, v)
	}
	return Load()
}

func TestLoadSettingChecks(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		wantErr string
	}{
		{
			name:    "unparsable FIREWALL_BATCH_WINDOW",
			env:     map[string]string{"FIREWALL_BATCH_WINDOW": "soon"},
			wantErr: `FIREWALL_BATCH_WINDOW (deprecated; use SYNC_INTERVAL) must be a duration such as 30s; got "soon"`,
		},
		{
			name: "unparsable FIREWALL_BATCH_WINDOW shadowed by SYNC_INTERVAL",
			env:  map[string]string{"FIREWALL_BATCH_WINDOW": "soon", "SYNC_INTERVAL": "30s"},
		},
		{
			name:    "metrics on the wildcard host of the health port",
			env:     map[string]string{"METRICS_ADDR": "0.0.0.0:8081", "HEALTH_ADDR": ":8081"},
			wantErr: `METRICS_ADDR "0.0.0.0:8081" and HEALTH_ADDR ":8081" listen on the same port; give them different ports`,
		},
		{
			name:    "identical listen addresses",
			env:     map[string]string{"METRICS_ADDR": ":8081", "HEALTH_ADDR": ":8081"},
			wantErr: `METRICS_ADDR and HEALTH_ADDR must differ; both are ":8081"`,
		},
		{
			name: "same port with metrics disabled",
			env:  map[string]string{"METRICS_ENABLED": "false", "METRICS_ADDR": "0.0.0.0:8081", "HEALTH_ADDR": ":8081"},
		},
		{
			name:    "negative LAPI_METRICS_PUSH_INTERVAL",
			env:     map[string]string{"LAPI_METRICS_PUSH_INTERVAL": "-1m"},
			wantErr: "LAPI_METRICS_PUSH_INTERVAL must not be negative; got -1m0s",
		},
		{
			name: "LAPI_METRICS_PUSH_INTERVAL disabled",
			env:  map[string]string{"LAPI_METRICS_PUSH_INTERVAL": "0"},
		},
		{
			name:    "negative BLOCK_MIN_DURATION",
			env:     map[string]string{"BLOCK_MIN_DURATION": "-1h"},
			wantErr: "BLOCK_MIN_DURATION must not be negative; got -1h0m0s",
		},
		{
			name:    "IPv6 ruleset for IPv4 rules",
			env:     map[string]string{"FIREWALL_MODE": "legacy", "LEGACY_RULESET_V4": "WANv6_IN"},
			wantErr: `LEGACY_RULESET_V4 must be one of WAN_IN,WAN_OUT,WAN_LOCAL,LAN_IN,LAN_OUT,LAN_LOCAL,GUEST_IN,GUEST_OUT,GUEST_LOCAL; got "WANv6_IN"`,
		},
		{
			name:    "unknown IPv6 ruleset in auto mode",
			env:     map[string]string{"LEGACY_RULESET_V6": "WAN_IN"},
			wantErr: `LEGACY_RULESET_V6 must be one of WANv6_IN,WANv6_OUT,WANv6_LOCAL,LANv6_IN,LANv6_OUT,LANv6_LOCAL,GUESTv6_IN,GUESTv6_OUT,GUESTv6_LOCAL; got "WAN_IN"`,
		},
		{
			name: "other valid rulesets",
			env:  map[string]string{"FIREWALL_MODE": "legacy", "LEGACY_RULESET_V4": "WAN_LOCAL", "LEGACY_RULESET_V6": "LANv6_IN"},
		},
		{
			name: "legacy settings are not used in zone mode",
			env:  map[string]string{"FIREWALL_MODE": "zone", "LEGACY_RULESET_V4": "nonsense", "LEGACY_RULE_INDEX_START_V4": "0"},
		},
		{
			name:    "zero rule index",
			env:     map[string]string{"FIREWALL_MODE": "legacy", "LEGACY_RULE_INDEX_START_V4": "0"},
			wantErr: "LEGACY_RULE_INDEX_START_V4 must be between 1 and 99999; got 0",
		},
		{
			name:    "rule index too large",
			env:     map[string]string{"LEGACY_RULE_INDEX_START_V6": "100000"},
			wantErr: "LEGACY_RULE_INDEX_START_V6 must be between 1 and 99999; got 100000",
		},
		{
			name:    "missing UNIFI_CA_CERT",
			env:     map[string]string{"UNIFI_CA_CERT": "/nonexistent/unifi-ca.pem"},
			wantErr: "UNIFI_CA_CERT: cannot read /nonexistent/unifi-ca.pem: ",
		},
		{
			name:    "missing CROWDSEC_LAPI_CA_CERT",
			env:     map[string]string{"CROWDSEC_LAPI_CA_CERT": "/nonexistent/lapi-ca.pem"},
			wantErr: "CROWDSEC_LAPI_CA_CERT: cannot read /nonexistent/lapi-ca.pem: ",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadWith(t, tc.env)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("Load = %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadCACertMustHoldACertificate(t *testing.T) {
	dir := t.TempDir()
	notPEM := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(notPEM, []byte("not a certificate\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	valid := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(valid, selfSignedPEM(t), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, setting := range []string{"UNIFI_CA_CERT", "CROWDSEC_LAPI_CA_CERT"} {
		t.Run(setting, func(t *testing.T) {
			_, err := loadWith(t, map[string]string{setting: notPEM})
			if want := setting + ": " + notPEM + " contains no PEM certificates"; err == nil || err.Error() != want {
				t.Errorf("Load = %v, want %q", err, want)
			}
			if _, err := loadWith(t, map[string]string{setting: valid}); err != nil {
				t.Errorf("Load with a valid CA certificate: %v", err)
			}
		})
	}
}

func selfSignedPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestListenAddrsClash(t *testing.T) {
	tests := []struct {
		a, b  string
		clash bool
	}{
		{":8081", ":8081", true},
		{"0.0.0.0:8081", ":8081", true},
		{"[::]:8081", "127.0.0.1:8081", true},
		{"127.0.0.1:8081", "127.0.0.1:8081", true},
		{"localhost:8081", "127.0.0.1:8081", true},
		{"[::1]:8081", "[0:0::1]:8081", true},
		{"127.0.0.1:8081", "192.168.1.2:8081", false},
		{"0.0.0.0:9090", ":8081", false},
		{":0", ":0", false},
	}
	for _, tc := range tests {
		if got := listenAddrsClash(tc.a, tc.b); got != tc.clash {
			t.Errorf("listenAddrsClash(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.clash)
		}
	}
}

func TestLoadWarnsWhenControllerCertificateIsNotVerified(t *testing.T) {
	cfg, err := loadWith(t, map[string]string{"UNIFI_VERIFY_TLS": "false"})
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := "UNIFI_VERIFY_TLS=false disables controller certificate validation"
	for _, w := range cfg.DeprecationWarnings {
		if strings.HasPrefix(w, want) {
			return
		}
	}
	t.Errorf("warnings %q do not include %q", cfg.DeprecationWarnings, want)
}
