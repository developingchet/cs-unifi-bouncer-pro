package whitelist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/feedhttp"
)

// CloudflareProvider fetches Cloudflare IP ranges from the public API.
type CloudflareProvider struct {
	IPv4URL    string
	IPv6URL    string
	HTTPClient *http.Client
}

// NewCloudflareProvider creates a provider with a 15-second timeout.
func NewCloudflareProvider(ipv4URL, ipv6URL string) *CloudflareProvider {
	return &CloudflareProvider{
		IPv4URL:    ipv4URL,
		IPv6URL:    ipv6URL,
		HTTPClient: &http.Client{Timeout: 15 * time.Second, CheckRedirect: feedhttp.CheckRedirect},
	}
}

// FetchIPv4 returns the current list of Cloudflare IPv4 CIDRs.
func (p *CloudflareProvider) FetchIPv4(ctx context.Context) ([]string, error) {
	return p.fetch(ctx, p.IPv4URL, false)
}

// FetchIPv6 returns the current list of Cloudflare IPv6 CIDRs.
func (p *CloudflareProvider) FetchIPv6(ctx context.Context) ([]string, error) {
	return p.fetch(ctx, p.IPv6URL, true)
}

func (p *CloudflareProvider) fetch(ctx context.Context, url string, ipv6 bool) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request for %s: %w", url, err)
	}
	resp, err := p.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch %s: HTTP %d", url, resp.StatusCode)
	}

	const maxFeedBytes = 64 * 1024
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}
	if len(body) > maxFeedBytes {
		return nil, fmt.Errorf("cloudflare feed %s exceeds %d bytes", url, maxFeedBytes)
	}

	var result []string
	for _, line := range strings.Split(string(body), "\n") {
		cidr := strings.TrimSpace(line)
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil || prefix.Addr().Is6() != ipv6 {
			return nil, fmt.Errorf("invalid Cloudflare CIDR %q in %s", cidr, url)
		}
		result = append(result, cidr)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("cloudflare feed %s contains no CIDRs", url)
	}
	return result, nil
}
