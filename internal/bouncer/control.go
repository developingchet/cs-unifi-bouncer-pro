package bouncer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
)

// Paths of the control and sync status endpoints on HEALTH_ADDR. Like the
// database snapshot, they answer only a same-host caller that presents the
// token from SnapshotTokenFile.
const (
	ControlBanPath       = "/control/ban"
	ControlUnbanPath     = "/control/unban"
	ControlReconcilePath = "/control/reconcile"
	SyncStatusPath       = "/status/sync"
)

const (
	// maxControlBody bounds a control request body; a request names one
	// address and a duration.
	maxControlBody = 4 << 10
	// controlBanTimeout bounds a manual ban or unban, including its write
	// to UniFi.
	controlBanTimeout = 2 * time.Minute
	// controlReconcileTimeout bounds a reconcile requested through the
	// control endpoint.
	controlReconcileTimeout = 30 * time.Minute
)

// ControlBanRequest is the body of a POST to ControlBanPath. Duration is a
// Go duration ("24h"); empty or "0" means BAN_TTL.
type ControlBanRequest struct {
	IP       string `json:"ip"`
	Duration string `json:"duration,omitempty"`
}

// ControlUnbanRequest is the body of a POST to ControlUnbanPath.
type ControlUnbanRequest struct {
	IP string `json:"ip"`
}

// ControlResponse answers a manual ban or unban.
type ControlResponse struct {
	IP        string     `json:"ip"`
	Sites     int        `json:"sites"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
	Lifted    *bool      `json:"lifted,omitempty"`
	SyncError string     `json:"sync_error,omitempty"`
}

// ReconcileResponse answers a reconcile. Error lists the sites or objects a
// partial reconcile could not repair.
type ReconcileResponse struct {
	Added          int     `json:"added"`
	Removed        int     `json:"removed"`
	ElapsedSeconds float64 `json:"elapsed_seconds"`
	Error          string  `json:"error,omitempty"`
}

// ErrorResponse is the body of every failed control or status request.
type ErrorResponse struct {
	Error string `json:"error"`
}

// controlState is what the control endpoints act on once the daemon has
// built it.
type controlState struct {
	actions *ManualActions
	// reconcileAllowed reports whether the startup gate lets reconciles run.
	reconcileAllowed func() bool
}

// control serves the control and sync status endpoints.
type control struct {
	state       atomic.Pointer[controlState]
	reconciling sync.Mutex
	synced      func() bool
	log         zerolog.Logger
}

// register adds the endpoints to mux, each behind the same-host and token
// check of the database snapshot.
func (c *control) register(mux *http.ServeMux, token string) {
	mux.Handle(ControlBanPath, guarded(http.MethodPost, token, c.ban))
	mux.Handle(ControlUnbanPath, guarded(http.MethodPost, token, c.unban))
	mux.Handle(ControlReconcilePath, guarded(http.MethodPost, token, c.reconcile))
	mux.Handle(SyncStatusPath, guarded(http.MethodGet, token, c.syncStatus))
}

// guarded answers only method, from the same host, with the token.
func guarded(method, token string, next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != method {
			w.Header().Set("Allow", method)
			writeJSON(w, http.StatusMethodNotAllowed, ErrorResponse{Error: "method not allowed"})
			return
		}
		if !authorizedStatusRequest(r, token) {
			writeJSON(w, http.StatusForbidden, ErrorResponse{Error: "forbidden"})
			return
		}
		next(w, r)
	})
}

// ready returns the control state, or answers 503 while the daemon is still
// starting.
func (c *control) ready(w http.ResponseWriter) *controlState {
	state := c.state.Load()
	if state == nil {
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{Error: "the bouncer is still starting"})
	}
	return state
}

func (c *control) ban(w http.ResponseWriter, r *http.Request) {
	state := c.ready(w)
	if state == nil {
		return
	}
	var req ControlBanRequest
	if !decodeControlRequest(w, r, &req) {
		return
	}
	dur, err := parseControlDuration(req.Duration)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	ctx, cancel := c.extendDeadline(w, r, controlBanTimeout)
	defer cancel()
	res, err := state.actions.Ban(ctx, req.IP, dur)
	if err != nil {
		c.writeActionError(w, err)
		return
	}
	resp := ControlResponse{IP: res.IP, Sites: len(state.actions.Sites), ExpiresAt: &res.ExpiresAt}
	writeJSON(w, http.StatusOK, withSyncError(resp, res.SyncErr))
}

func (c *control) unban(w http.ResponseWriter, r *http.Request) {
	state := c.ready(w)
	if state == nil {
		return
	}
	var req ControlUnbanRequest
	if !decodeControlRequest(w, r, &req) {
		return
	}
	ctx, cancel := c.extendDeadline(w, r, controlBanTimeout)
	defer cancel()
	res, err := state.actions.Unban(ctx, req.IP)
	if err != nil {
		c.writeActionError(w, err)
		return
	}
	lifted := res.Changed
	resp := ControlResponse{IP: res.IP, Sites: len(state.actions.Sites), Lifted: &lifted}
	writeJSON(w, http.StatusOK, withSyncError(resp, res.SyncErr))
}

func (c *control) reconcile(w http.ResponseWriter, r *http.Request) {
	state := c.ready(w)
	if state == nil {
		return
	}
	if state.reconcileAllowed != nil && !state.reconcileAllowed() {
		// Until the first CrowdSec batch is stored, the ban database may be
		// missing bans, and a reconcile would remove them from UniFi.
		writeJSON(w, http.StatusServiceUnavailable, ErrorResponse{
			Error: "reconcile is not allowed until the first CrowdSec decision batch has been applied"})
		return
	}
	if !c.reconciling.TryLock() {
		writeJSON(w, http.StatusConflict, ErrorResponse{Error: "a reconcile requested through this endpoint is already running"})
		return
	}
	defer c.reconciling.Unlock()
	ctx, cancel := c.extendDeadline(w, r, controlReconcileTimeout)
	defer cancel()
	result, err := state.actions.Reconcile(ctx)
	if result == nil {
		if err == nil {
			err = errors.New("no result")
		}
		c.writeActionError(w, fmt.Errorf("reconcile: %w", err))
		return
	}
	resp := ReconcileResponse{Added: result.Added, Removed: result.Removed, ElapsedSeconds: result.Elapsed.Seconds()}
	if err != nil {
		resp.Error = err.Error()
	}
	writeJSON(w, http.StatusOK, resp)
}

// extendDeadline lifts the health server's short write timeout for an action
// that may run for up to timeout, and bounds the action's context by it.
func (c *control) extendDeadline(w http.ResponseWriter, r *http.Request, timeout time.Duration) (context.Context, context.CancelFunc) {
	if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(timeout + 10*time.Second)); err != nil {
		c.log.Debug().Err(err).Msg("cannot extend the write deadline of a control request")
	}
	return context.WithTimeout(r.Context(), timeout)
}

func (c *control) writeActionError(w http.ResponseWriter, err error) {
	if IsInvalidRequest(err) {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	c.log.Warn().Err(err).Msg("control request failed")
	writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
}

func withSyncError(resp ControlResponse, err error) ControlResponse {
	if err != nil {
		resp.SyncError = err.Error()
	}
	return resp
}

// parseControlDuration parses a ban duration; empty means 0 (BAN_TTL).
func parseControlDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	dur, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q: use a Go duration such as 24h", raw)
	}
	if dur < 0 {
		return 0, fmt.Errorf("ban duration must not be negative")
	}
	return dur, nil
}

// decodeControlRequest reads a JSON body of at most maxControlBody bytes into
// dst, refusing unknown fields and trailing data. On failure it answers the
// request and returns false.
func decodeControlRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, ErrorResponse{Error: "Content-Type must be application/json"})
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxControlBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body: " + err.Error()})
		return false
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body: trailing data after the JSON object"})
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
