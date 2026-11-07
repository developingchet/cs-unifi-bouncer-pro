package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/developingchet/cs-unifi-bouncer-pro/internal/bouncer"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/config"
	"github.com/developingchet/cs-unifi-bouncer-pro/internal/storage"
)

// maxControlResponse bounds a control or sync status answer.
const maxControlResponse = 1 << 20

// daemonRunning reports whether a running bouncer holds the database in
// dataDir, the way status decides to read a snapshot: the read-only open
// fails with ErrDatabaseLocked while the daemon holds its lock. A database
// that does not exist yet means no daemon has it.
func daemonRunning(dataDir string) bool {
	store, err := storage.NewBboltStoreReadOnly(dataDir)
	if errors.Is(err, storage.ErrDatabaseLocked) {
		return true
	}
	if err == nil {
		_ = store.Close()
	}
	return false
}

// statusEndpoint returns the URL of path on the local health server and the
// token its guarded endpoints require.
func statusEndpoint(dataDir, path string) (string, string, error) {
	healthURL, err := localHealthURL(config.HealthAddrFromEnv())
	if err != nil {
		return "", "", err
	}
	token, err := os.ReadFile(filepath.Join(dataDir, bouncer.SnapshotTokenFile))
	if err != nil {
		return "", "", fmt.Errorf("read status token: %w", err)
	}
	return strings.TrimSuffix(healthURL, "/healthz") + path, strings.TrimSpace(string(token)), nil
}

// callControl sends body (nil for none) to path on the running bouncer and
// decodes its JSON answer into out.
func callControl(ctx context.Context, dataDir, method, path string, body, out any) error {
	url, token, err := statusEndpoint(dataDir, path)
	if err != nil {
		return err
	}
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, reqBody)
	if err != nil {
		return err
	}
	req.Header.Set(bouncer.SnapshotTokenHeader, token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("reach the running bouncer: %w", err)
	}
	defer resp.Body.Close()
	return decodeControlResponse(resp, path, out)
}

// decodeControlResponse decodes a successful answer into out, or turns an
// error answer into an error that carries the daemon's message.
func decodeControlResponse(resp *http.Response, path string, out any) error {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxControlResponse))
	if err != nil {
		return fmt.Errorf("read %s answer: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		var e bouncer.ErrorResponse
		if json.Unmarshal(data, &e) == nil && e.Error != "" {
			return fmt.Errorf("the running bouncer refused the request: %s", printable(e.Error))
		}
		return fmt.Errorf("%s returned HTTP %d", path, resp.StatusCode)
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decode %s answer: %w", path, err)
	}
	return nil
}
