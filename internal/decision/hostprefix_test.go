package decision

import (
	"testing"

	"github.com/rs/zerolog"
)

func TestParseAndSanitize_HostPrefixIsBareAddress(t *testing.T) {
	tests := []struct {
		in       string
		want     string
		wantCIDR bool
	}{
		{"203.0.113.77/32", "203.0.113.77", false},
		{"2001:db8:6::1/128", "2001:db8:6::1", false},
		{"::ffff:203.0.113.5/128", "203.0.113.5", false},
		{"203.0.113.0/24", "203.0.113.0/24", true},
		{"203.0.113.9/24", "203.0.113.0/24", true},
		{"2001:db8:5::/64", "2001:db8:5::/64", true},
		{"203.0.113.77", "203.0.113.77", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, isCIDR, err := ParseAndSanitize(tt.in)
			if err != nil || got != tt.want || isCIDR != tt.wantCIDR {
				t.Fatalf("ParseAndSanitize(%q) = %q, %v, %v; want %q, %v", tt.in, got, isCIDR, err, tt.want, tt.wantCIDR)
			}
		})
	}
}

func TestFilter_RangeDecisionForOneHost(t *testing.T) {
	d := makeDecision("ban", "range", "2001:db8:6::1/128", "manual", "cscli", "1h")
	r := Filter(d, NewFilterConfig(), zerolog.Nop())
	if !r.Passed || r.Value != "2001:db8:6::1" || !r.IPv6 {
		t.Fatalf("Filter = %+v, want bare IPv6 address", r)
	}
}
