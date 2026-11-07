package controller

import "context"

type metricSiteKey struct{}

// withMetricSite returns ctx carrying the site that requests made with it are
// counted under in the API metrics.
func withMetricSite(ctx context.Context, site string) context.Context {
	return context.WithValue(ctx, metricSiteKey{}, site)
}

// metricSite returns the site ctx carries for the API metrics, or "" for a
// request that belongs to no site, such as a login, a ping or the site list.
func metricSite(ctx context.Context) string {
	site, _ := ctx.Value(metricSiteKey{}).(string)
	return site
}
