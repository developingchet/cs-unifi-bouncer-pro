package logger

import (
	"errors"
	"fmt"
	"net/url"
)

// SafeURL returns raw without credentials that commonly ride in feed and
// webhook URLs: user info, the query string, and the fragment. The path is
// kept so operators can tell feeds apart; use SafeHost when the path itself
// carries a secret (Slack, Discord and similar webhooks).
func SafeURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable URL>"
	}
	redacted := url.URL{Scheme: u.Scheme, Host: u.Host, Path: u.Path}
	s := redacted.String()
	if u.RawQuery != "" {
		s += "?<redacted>"
	}
	return s
}

// SafeHost returns only the scheme and host of raw.
func SafeHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return "<unparseable URL>"
	}
	return (&url.URL{Scheme: u.Scheme, Host: u.Host}).String()
}

// SafeURLError removes the request URL that net/http embeds in transport
// errors and replaces it with display, keeping the underlying cause.
func SafeURLError(err error, display string) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s %s: %w", ue.Op, display, ue.Err)
	}
	return err
}
