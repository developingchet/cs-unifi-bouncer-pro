package decision

import (
	"testing"
)

func TestParseAndSanitize(t *testing.T) {
	cases := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{"1.2.3.4", "1.2.3.4", false},
		{"::ffff:1.2.3.4", "1.2.3.4", false}, // IPv4-mapped IPv6 normalized
		{"2001:db8::1", "2001:db8::1", false},
		{"192.168.1.0/24", "192.168.1.0/24", false},
		{"not-an-ip", "", true},
		{"300.1.1.1", "", true},
	}
	for _, c := range cases {
		got, _, err := ParseAndSanitize(c.input)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseAndSanitize(%q): expected error", c.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseAndSanitize(%q): unexpected error: %v", c.input, err)
			continue
		}
		if got != c.want {
			t.Errorf("ParseAndSanitize(%q): got %q, want %q", c.input, got, c.want)
		}
	}
}

func TestIsIPv6(t *testing.T) {
	if IsIPv6("1.2.3.4") {
		t.Error("1.2.3.4 should not be IPv6")
	}
	if !IsIPv6("2001:db8::1") {
		t.Error("2001:db8::1 should be IPv6")
	}
	if IsIPv6("192.168.0.0/24") {
		t.Error("IPv4 CIDR should not be IPv6")
	}
	if !IsIPv6("2001:db8::/32") {
		t.Error("IPv6 CIDR should be IPv6")
	}
}

func TestIsPrivate(t *testing.T) {
	privates := []string{
		"10.0.0.1", "172.16.0.1", "192.168.1.1",
		"127.0.0.1", "169.254.0.1",
		"::1", "fe80::1", "fd00::1",
	}
	for _, ip := range privates {
		if !IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) should be true", ip)
		}
	}

	publics := []string{"1.2.3.4", "8.8.8.8", "2001:db8::1", "203.0.113.1"}
	for _, ip := range publics {
		if IsPrivate(ip) {
			t.Errorf("IsPrivate(%q) should be false", ip)
		}
	}
}

func TestIsWhitelisted(t *testing.T) {
	wl, err := ParseWhitelist([]string{"10.0.0.0/8", "203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	if !IsWhitelisted("10.1.2.3", wl) {
		t.Error("10.1.2.3 should be whitelisted")
	}
	if !IsWhitelisted("203.0.113.50", wl) {
		t.Error("203.0.113.50 should be whitelisted")
	}
	if IsWhitelisted("1.2.3.4", wl) {
		t.Error("1.2.3.4 should not be whitelisted")
	}
}

func TestParseWhitelistInvalid(t *testing.T) {
	_, err := ParseWhitelist([]string{"not-a-cidr"})
	if err == nil {
		t.Error("expected error for invalid whitelist entry")
	}
}

func TestParseWhitelistSingleIP(t *testing.T) {
	wl, err := ParseWhitelist([]string{"1.2.3.4"})
	if err != nil {
		t.Fatal(err)
	}
	if !IsWhitelisted("1.2.3.4", wl) {
		t.Error("single IP whitelist should match exact IP")
	}
	if IsWhitelisted("1.2.3.5", wl) {
		t.Error("single IP whitelist should not match other IPs")
	}
}

func TestParseWhitelistIPv6(t *testing.T) {
	wl, err := ParseWhitelist([]string{"2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if !IsWhitelisted("2001:db8::1", wl) {
		t.Error("IPv6 CIDR member should be whitelisted")
	}
}

func TestIsPrivate_CGNAT(t *testing.T) {
	// 100.64.0.0/10 is CGNAT space (RFC 6598) — should be treated as private.
	if !IsPrivate("100.64.0.1") {
		t.Error("IsPrivate(100.64.0.1) should be true (CGNAT RFC 6598)")
	}
}

func TestIsPrivate_TestNet(t *testing.T) {
	// 192.0.2.0/24 is TEST-NET-1 (RFC 5737) — publicly routable address space
	// used only in documentation. Not in any private block.
	if IsPrivate("192.0.2.1") {
		t.Error("IsPrivate(192.0.2.1) should be false (TEST-NET, not private)")
	}
}

func TestIsPrivate_Multicast(t *testing.T) {
	// 224.0.0.0/4 is multicast — not a private unicast range.
	if IsPrivate("224.0.0.1") {
		t.Error("IsPrivate(224.0.0.1) should be false (multicast, not private)")
	}
}

func TestParseAndSanitize_IPv4Mapped(t *testing.T) {
	// ::ffff:192.168.1.1 is an IPv4-mapped IPv6 address. ParseAndSanitize must
	// normalize it to its IPv4 form and report isCIDR=false.
	got, isCIDR, err := ParseAndSanitize("::ffff:192.168.1.1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "192.168.1.1" {
		t.Errorf("want 192.168.1.1, got %q", got)
	}
	if isCIDR {
		t.Error("IPv4-mapped plain IP should not be flagged as CIDR")
	}
	if IsIPv6(got) {
		t.Error("sanitized IPv4-mapped address should not be classified as IPv6")
	}
}
