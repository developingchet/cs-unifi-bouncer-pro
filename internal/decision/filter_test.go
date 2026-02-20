package decision

import (
	"testing"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
	"github.com/rs/zerolog"
)

func strPtr(s string) *string { return &s }

func makeDecision(action, scope, value, scenario, origin, duration string) *models.Decision {
	return &models.Decision{
		Type:     strPtr(action),
		Scope:    strPtr(scope),
		Value:    strPtr(value),
		Scenario: strPtr(scenario),
		Origin:   strPtr(origin),
		Duration: strPtr(duration),
	}
}

func TestStage1_UnsupportedAction(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("captcha", "ip", "1.2.3.4", "test", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if r.Passed {
		t.Error("captcha action should be filtered")
	}
}

func TestStage1_BanAllowed(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "ip", "1.2.3.4", "test", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Errorf("ban action should pass; action=%s scope=%s value=%s", "ban", "ip", "1.2.3.4")
	}
}

func TestStage2_ScenarioExclude(t *testing.T) {
	cfg := NewFilterConfig()
	cfg.BlockScenarioExclude = []string{"impossible-travel", "test-scenario"}

	d := makeDecision("ban", "ip", "1.2.3.4", "test-scenario-brute-force", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if r.Passed {
		t.Error("excluded scenario should be filtered")
	}

	d2 := makeDecision("ban", "ip", "1.2.3.4", "ssh-brute-force", "crowdsec", "24h")
	r2 := Filter(d2, cfg, zerolog.Nop())
	if !r2.Passed {
		t.Error("non-excluded scenario should pass")
	}
}

func TestStage3_OriginFilter(t *testing.T) {
	cfg := NewFilterConfig()
	cfg.AllowedOrigins = []string{"crowdsec", "lists"}

	d := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "cscli", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if r.Passed {
		t.Error("cscli origin should be filtered when not in allowed list")
	}

	d2 := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "24h")
	r2 := Filter(d2, cfg, zerolog.Nop())
	if !r2.Passed {
		t.Error("crowdsec origin should pass")
	}
}

func TestStage3_EmptyOriginsAllowsAll(t *testing.T) {
	cfg := NewFilterConfig()
	// Empty origins = all allowed
	d := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "anything", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("all origins should pass when AllowedOrigins is empty")
	}
}

func TestStage4_UnsupportedScope(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "country", "FR", "geoip", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if r.Passed {
		t.Error("country scope should be filtered")
	}
}

func TestStage5_InvalidIP(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "ip", "not-an-ip", "ssh-bf", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if r.Passed {
		t.Error("invalid IP should be filtered")
	}
}

func TestStage5_IPv4MappedIPv6Normalized(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "ip", "::ffff:1.2.3.4", "ssh-bf", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("IPv4-mapped IPv6 should pass (normalizes to IPv4)")
	}
	if r.IPv6 {
		t.Errorf("normalized IPv4-mapped should be classified as IPv4, got IPv6=%v", r.IPv6)
	}
}

func TestStage6_PrivateIP(t *testing.T) {
	cfg := NewFilterConfig()
	privates := []string{"10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1", "::1", "fe80::1"}
	for _, ip := range privates {
		d := makeDecision("ban", "ip", ip, "ssh-bf", "crowdsec", "24h")
		r := Filter(d, cfg, zerolog.Nop())
		if r.Passed {
			t.Errorf("private IP %s should be filtered", ip)
		}
	}
}

func TestStage7_Whitelist(t *testing.T) {
	cfg := NewFilterConfig()
	wl, err := ParseWhitelist([]string{"10.0.0.0/8", "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	cfg.Whitelist = wl

	// 10.x.x.x is in whitelist but also private — both filters would catch it
	d := makeDecision("ban", "ip", "203.0.113.5", "ssh-bf", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if r.Passed {
		t.Error("whitelisted CIDR member should be filtered")
	}

	d2 := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "24h")
	r2 := Filter(d2, cfg, zerolog.Nop())
	if !r2.Passed {
		t.Error("non-whitelisted IP should pass")
	}
}

func TestStage8_MinBanDuration(t *testing.T) {
	cfg := NewFilterConfig()
	cfg.MinBanDuration = 2 * time.Hour

	// 30 min ban — should be filtered
	d := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "30m")
	r := Filter(d, cfg, zerolog.Nop())
	if r.Passed {
		t.Error("short ban should be filtered by min duration")
	}

	// 4h ban — should pass
	d2 := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "4h")
	r2 := Filter(d2, cfg, zerolog.Nop())
	if !r2.Passed {
		t.Error("long ban should pass min duration check")
	}
}

func TestStage8_DeleteIgnoresMinDuration(t *testing.T) {
	cfg := NewFilterConfig()
	cfg.MinBanDuration = 24 * time.Hour

	// delete actions are always allowed regardless of duration
	d := makeDecision("delete", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "1m")
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("delete action should pass regardless of min duration")
	}
}

func TestCIDRDecision(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "range", "203.0.113.0/24", "ssh-bf", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("valid CIDR should pass")
	}
	if r.Value != "203.0.113.0/24" {
		t.Errorf("CIDR value: got %q", r.Value)
	}
}

func TestIPv6Decision(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "ip", "2001:db9::1", "ssh-bf", "crowdsec", "24h")
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("public IPv6 should pass")
	}
	if !r.IPv6 {
		t.Error("should be classified as IPv6")
	}
}

func TestNilDuration_NoAstray(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "24h")
	d.Duration = nil // nil Duration pointer must not panic
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("nil Duration should not prevent the decision from passing")
	}
}

func TestNilScenario_NoAstray(t *testing.T) {
	cfg := NewFilterConfig()
	d := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "24h")
	d.Scenario = nil // nil Scenario pointer must not panic
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("nil Scenario should not prevent the decision from passing")
	}
}

func TestNilOrigin_NoAstray(t *testing.T) {
	cfg := NewFilterConfig()
	// AllowedOrigins is empty so all origins (including nil) are allowed.
	d := makeDecision("ban", "ip", "1.2.3.4", "ssh-bf", "crowdsec", "24h")
	d.Origin = nil // nil Origin pointer must not panic
	r := Filter(d, cfg, zerolog.Nop())
	if !r.Passed {
		t.Error("nil Origin should not prevent the decision from passing (empty AllowedOrigins)")
	}
}
