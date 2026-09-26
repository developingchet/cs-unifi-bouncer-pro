package lapihttp

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// UserAgent is the LAPI user agent, crowdsec-unifi-bouncer/v<version>. Release
// builds pass a version that already starts with "v".
func UserAgent(version string) string {
	return "crowdsec-unifi-bouncer/v" + strings.TrimPrefix(version, "v")
}

// NewClient returns an HTTP client for the LAPI that never follows redirects.
func NewClient(verifyTLS bool, caPath string, timeout time.Duration) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: !verifyTLS} //nolint:gosec // controlled by TLS verification setting
	if caPath != "" {
		cert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read LAPI CA certificate: %w", err)
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			return nil, fmt.Errorf("load system CA certificates: %w", err)
		}
		if !roots.AppendCertsFromPEM(cert) {
			return nil, fmt.Errorf("LAPI CA certificate contains no valid PEM certificates")
		}
		tlsConfig.RootCAs = roots
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{
		Transport:     transport,
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}, nil
}
