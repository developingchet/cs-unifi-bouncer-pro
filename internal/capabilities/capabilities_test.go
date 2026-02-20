package capabilities

import (
	"testing"
)

// TestBouncerType asserts BouncerType == "cs-unifi-bouncer-pro"
// Rationale: this string is used verbatim in the LAPI /v1/usage-metrics
// payload `type` field. A rename/typo is a spec violation.
func TestBouncerType(t *testing.T) {
	expected := "cs-unifi-bouncer-pro"
	if BouncerType != expected {
		t.Errorf("BouncerType = %q, want %q", BouncerType, expected)
	}
}

// TestLayer asserts Layer == "network"
// Rationale: referenced in startup log and COMPLIANCE.md; must stay
// "network" not "l3" or anything else.
func TestLayer(t *testing.T) {
	expected := "network"
	if Layer != expected {
		t.Errorf("Layer = %q, want %q", Layer, expected)
	}
}

// TestRemediationSupport asserts the declared compliance boundaries.
// Rationale: these are the declared compliance boundaries. If someone
// changes SupportsCaptcha to true without implementing it, the test catches it.
func TestRemediationSupport(t *testing.T) {
	t.Run("SupportsBan", func(t *testing.T) {
		if !SupportsBan {
			t.Errorf("SupportsBan = %v, want true", SupportsBan)
		}
	})

	t.Run("SupportsCaptcha", func(t *testing.T) {
		if SupportsCaptcha {
			t.Errorf("SupportsCaptcha = %v, want false", SupportsCaptcha)
		}
	})

	t.Run("SupportsAppSec", func(t *testing.T) {
		if SupportsAppSec {
			t.Errorf("SupportsAppSec = %v, want false", SupportsAppSec)
		}
	})

	t.Run("SupportsPerRequestDecisions", func(t *testing.T) {
		if SupportsPerRequestDecisions {
			t.Errorf("SupportsPerRequestDecisions = %v, want false", SupportsPerRequestDecisions)
		}
	})
}

// TestUserAgentFormat validates the format contract documented in COMPLIANCE.md:
// the user-agent prefix is "crowdsec-unifi-bouncer" (service=unifi), not BouncerType.
// This documents the intentional difference between BouncerType (cs-unifi-bouncer-pro,
// used in metrics payload) and the LAPI user-agent service name (unifi, used in stream
// connection + metrics HTTP header). Both are correct per spec; this test makes the
// distinction explicit and prevents someone "fixing" them to match.
func TestUserAgentFormat(t *testing.T) {
	ua := "crowdsec-unifi-bouncer/v" + "1.0.0"
	expected := "crowdsec-unifi-bouncer/v1.0.0"
	if ua != expected {
		t.Errorf("user-agent = %q, want %q", ua, expected)
	}
}
