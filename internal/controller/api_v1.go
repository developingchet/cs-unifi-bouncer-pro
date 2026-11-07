package controller

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
)

// --- Integration v1 helpers -------------------------------------------------

const (
	// maxV1Pages and maxV1Items bound a paginated listing so that a controller
	// which never reports the end of a list cannot hold the caller in the loop
	// or grow the result without limit. Real sites hold a few hundred objects
	// per collection.
	maxV1Pages = 500
	maxV1Items = 100_000
)

// listAllV1Pages fetches all pages from an integration v1 paginated endpoint.
// It fails once a listing exceeds maxV1Pages pages or maxV1Items items.
func listAllV1Pages(ctx context.Context, c *unifiClient, endpointURL, metricEndpoint string) ([]json.RawMessage, error) {
	const pageLimit = 200
	base, err := url.Parse(endpointURL)
	if err != nil {
		return nil, fmt.Errorf("parse URL %q: %w", endpointURL, err)
	}
	var all []json.RawMessage
	offset := 0
	for pages := 1; ; pages++ {
		if pages > maxV1Pages {
			return nil, fmt.Errorf("%s pagination exceeded %d pages without reaching the end of the list", metricEndpoint, maxV1Pages)
		}
		u := *base
		q := u.Query()
		q.Set("offset", strconv.Itoa(offset))
		q.Set("limit", strconv.Itoa(pageLimit))
		u.RawQuery = q.Encode()

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return nil, err
		}
		var page apiV1Page
		err = c.withReauth(ctx, func() error {
			resp, err := c.apiDo(ctx, req, metricEndpoint)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			return json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&page)
		})
		if err != nil {
			return nil, err
		}
		if len(all)+len(page.Data) > maxV1Items {
			return nil, fmt.Errorf("%s pagination exceeded %d items", metricEndpoint, maxV1Items)
		}
		all = append(all, page.Data...)
		if len(page.Data) == 0 || (page.TotalCount > 0 && offset+page.Count >= page.TotalCount) {
			break
		}
		if page.Count <= 0 {
			return nil, fmt.Errorf("%s pagination returned %d items with count %d at offset %d", metricEndpoint, len(page.Data), page.Count, offset)
		}
		offset += page.Count
	}
	return all, nil
}

// v1CollectionHasID reports whether any object in the integration v1
// collection at endpointURL has the given id.
func v1CollectionHasID(ctx context.Context, c *unifiClient, endpointURL, metricEndpoint, id string) (bool, error) {
	data, err := listAllV1Pages(ctx, c, endpointURL, metricEndpoint)
	if err != nil {
		return false, err
	}
	for _, raw := range data {
		var obj struct {
			ID string `json:"id"`
		}
		if json.Unmarshal(raw, &obj) == nil && obj.ID == id {
			return true, nil
		}
	}
	return false, nil
}
