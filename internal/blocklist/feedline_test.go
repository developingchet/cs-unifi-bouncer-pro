package blocklist

import "testing"

func TestFeedLineValue(t *testing.T) {
	tests := map[string]string{
		"203.0.113.9":              "203.0.113.9",
		"  203.0.113.9  ":          "203.0.113.9",
		"192.0.2.0/24 ; SBL123":    "192.0.2.0/24",
		"203.0.113.101 # scanner":  "203.0.113.101",
		"203.0.113.102\tsome note": "203.0.113.102",
		"# full comment":           "",
		"; Spamhaus header":        "",
		"":                         "",
		"203.0.113.103,evil":       "203.0.113.103,evil",
	}
	for in, want := range tests {
		if got := feedLineValue(in); got != want {
			t.Errorf("feedLineValue(%q) = %q, want %q", in, got, want)
		}
	}
}
