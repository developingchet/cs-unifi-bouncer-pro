package whitelist

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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
		HTTPClient: &http.Client{Timeout: 15 * time.Second},
	}
}

// FetchIPv4 returns the current list of Cloudflare IPv4 CIDRs.
func (p *CloudflareProvider) FetchIPv4(ctx context.Context) ([]string, error) {
	return p.fetch(ctx, p.IPv4URL)
}

// FetchIPv6 returns the current list of Cloudflare IPv6 CIDRs.
func (p *CloudflareProvider) FetchIPv6(ctx context.Context) ([]string, error) {
	return p.fetch(ctx, p.IPv6URL)
}

func (p *CloudflareProvider) fetch(ctx context.Context, url string) ([]string, error) {
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

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", url, err)
	}

	var result []string
	for _, line := range strings.Split(string(body), "\n") {
		cidr := strings.TrimSpace(line)
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}
		result = append(result, cidr)
	}
	return result, nil
}
