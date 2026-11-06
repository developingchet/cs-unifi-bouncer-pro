package decision

import (
	"strings"
	"testing"

	"github.com/rs/zerolog"
)

func TestBanTypes(t *testing.T) {
	withCaptcha := NewFilterConfig()
	withCaptcha.BanTypes = []string{"ban", "captcha"}
	captchaOnly := NewFilterConfig()
	captchaOnly.BanTypes = []string{"captcha"}

	tests := []struct {
		name       string
		cfg        FilterConfig
		typ        string
		value      string
		deleted    bool
		wantPassed bool
		wantAction string
	}{
		{"default drops captcha", NewFilterConfig(), "captcha", "203.0.113.9", false, false, ""},
		{"default bans ban", NewFilterConfig(), "ban", "203.0.113.9", false, true, "ban"},
		{"captcha listed is banned", withCaptcha, "captcha", "203.0.113.9", false, true, "ban"},
		{"type matching is case-insensitive", withCaptcha, "Captcha", "203.0.113.9", false, true, "ban"},
		{"ban still banned with captcha listed", withCaptcha, "ban", "203.0.113.9", false, true, "ban"},
		{"unlisted type still dropped", withCaptcha, "throttle", "203.0.113.9", false, false, ""},
		{"listed type keeps the private range guard", withCaptcha, "captcha", "10.0.0.5", false, false, ""},
		{"listed type keeps the range limit", withCaptcha, "captcha", "203.0.0.0/7", false, false, ""},
		{"deleted captcha releases its ban", withCaptcha, "captcha", "203.0.113.9", true, true, "delete"},
		{"deleted ban still releases", withCaptcha, "ban", "203.0.113.9", true, true, "delete"},
		{"deleted captcha ignored when not listed", NewFilterConfig(), "captcha", "203.0.113.9", true, false, ""},
		{"ban unlisted is not banned", captchaOnly, "ban", "203.0.113.9", false, false, ""},
		{"ban unlisted still releases", captchaOnly, "ban", "203.0.113.9", true, true, "delete"},
		{"new delete type is never a ban", withCaptcha, "delete", "203.0.113.9", false, false, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := "ip"
			if strings.Contains(tt.value, "/") {
				scope = "range"
			}
			d := makeDecision(tt.typ, scope, tt.value, "crowdsecurity/http-probing", "crowdsec", "4h")
			filter := Filter
			if tt.deleted {
				filter = FilterDeleted
			}
			got := filter(d, tt.cfg, zerolog.Nop())
			if got.Passed != tt.wantPassed || got.Action != tt.wantAction {
				t.Fatalf("result = passed %v action %q, want passed %v action %q", got.Passed, got.Action, tt.wantPassed, tt.wantAction)
			}
		})
	}
}
