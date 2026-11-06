package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// maxResponseBodyBytes caps the response body read to prevent runaway allocations.
const maxResponseBodyBytes = 32 * 1024 * 1024 // 32 MB

// --- Generic HTTP helpers ---------------------------------------------------

func doGET(ctx context.Context, c *unifiClient, url, endpoint string) ([]json.RawMessage, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	var result []json.RawMessage
	return result, c.withReauth(ctx, func() error {
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var body apiResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&body); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		if err := checkLegacyResponse(body.Meta.RC, body.Meta.Msg); err != nil {
			return err
		}
		result = body.Data
		return nil
	})
}

func doPOST(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	err = c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		var body apiResponse
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&body); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		if err := checkLegacyResponse(body.Meta.RC, body.Meta.Msg); err != nil {
			return err
		}
		if len(body.Data) > 0 {
			result = body.Data[0]
		}
		return nil
	})
	return result, err
}

func checkLegacyResponse(code, message string) error {
	if code == "" || code == "ok" {
		return nil
	}
	if message == "" {
		message = code
	}
	return fmt.Errorf("UniFi API error: %s", message)
}

func doPOSTv2(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) (json.RawMessage, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	var result json.RawMessage
	err = c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBodyBytes)).Decode(&result); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
		return nil
	})
	return result, err
}

func doPUT(ctx context.Context, c *unifiClient, url, endpoint string, payload interface{}) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	return c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(b))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	})
}

func doDELETE(ctx context.Context, c *unifiClient, url, endpoint string) error {
	return c.withReauth(ctx, func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, url, nil)
		if err != nil {
			return err
		}
		resp, err := c.apiDo(ctx, req, endpoint)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	})
}

// requireSegment rejects a value that cannot name a single object in a URL
// path. An empty ID turns an object URL into its collection URL, so a DELETE
// or PUT would hit the whole collection, and "." or ".." lets a path climb
// out of the endpoint.
func requireSegment(label, value string) error {
	switch value {
	case "":
		return fmt.Errorf("%s is empty", label)
	case ".", "..":
		return fmt.Errorf("%s %q is not a valid path segment", label, value)
	}
	return nil
}

// requireSegments applies requireSegment to label, value pairs in order.
func requireSegments(labelValuePairs ...string) error {
	for i := 0; i+1 < len(labelValuePairs); i += 2 {
		if err := requireSegment(labelValuePairs[i], labelValuePairs[i+1]); err != nil {
			return err
		}
	}
	return nil
}
