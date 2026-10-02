package bouncer

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/rs/zerolog"
)

// snapshotWriteTimeout replaces the health server's short write timeout for a
// snapshot, which grows with the ban list. It also bounds how long the
// snapshot's database read transaction stays open: a client that reads
// slowly is cut off rather than holding the transaction, and with it the
// database file's free pages, for longer.
const snapshotWriteTimeout = 30 * time.Second

const (
	// DBSnapshotPath serves a consistent copy of the ban database to the
	// status command, which cannot open the file while this process holds
	// its lock.
	DBSnapshotPath = "/status/db"
	// SnapshotTokenHeader carries the token from SnapshotTokenFile.
	SnapshotTokenHeader = "X-Status-Token"
	// SnapshotTokenFile, in the data directory, holds the token a snapshot
	// request must present. Reading it takes the same access as reading the
	// database itself, which is what the snapshot hands out.
	SnapshotTokenFile = "status.token"
)

// snapshotWriter is implemented by stores that can copy their database while
// it is open.
type snapshotWriter interface {
	WriteSnapshot(w io.Writer) (int64, error)
}

// snapshotServer answers DBSnapshotPath, one request at a time.
type snapshotServer struct {
	store        snapshotWriter
	token        string
	busy         chan struct{}
	writeTimeout time.Duration
	log          zerolog.Logger
}

// newSnapshotServer writes a fresh token to dataDir. It returns nil when the
// store cannot take snapshots.
func newSnapshotServer(store any, dataDir string, log zerolog.Logger) (*snapshotServer, error) {
	sw, ok := store.(snapshotWriter)
	if !ok {
		return nil, nil
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate status token: %w", err)
	}
	token := hex.EncodeToString(raw)
	if err := writeTokenFile(filepath.Join(dataDir, SnapshotTokenFile), token); err != nil {
		return nil, err
	}
	RemoveStaleSnapshots(dataDir, log)
	return &snapshotServer{store: sw, token: token, busy: make(chan struct{}, 1), writeTimeout: snapshotWriteTimeout, log: log}, nil
}

// writeTokenFile writes token to path, readable by its owner only. Opening
// with a mode leaves an existing file's mode alone, so the open file is
// restricted with fchmod (the seccomp profile allows it, not fchmodat).
func writeTokenFile(path, token string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("write status token: %w", err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return fmt.Errorf("restrict status token: %w", err)
	}
	if _, err := f.WriteString(token); err != nil {
		_ = f.Close()
		return fmt.Errorf("write status token: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("write status token: %w", err)
	}
	return nil
}

// ServeHTTP writes the database to a caller that presents the token from the
// same host. The address check alone is not enough: a sidecar proxy or a
// local reverse proxy makes remote callers appear to come from loopback.
func (s *snapshotServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	given := r.Header.Get(SnapshotTokenHeader)
	if !sameHostRequest(r) || subtle.ConstantTimeCompare([]byte(given), []byte(s.token)) != 1 {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	select {
	case s.busy <- struct{}{}:
		defer func() { <-s.busy }()
	default:
		http.Error(w, "a snapshot is already being written", http.StatusTooManyRequests)
		return
	}
	deadline := time.Now().Add(s.writeTimeout)
	if err := http.NewResponseController(w).SetWriteDeadline(deadline); err != nil {
		s.log.Warn().Err(err).Msg("cannot set the write deadline for a database snapshot; a slow client is cut off between writes only")
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := s.store.WriteSnapshot(&deadlineWriter{w: w, deadline: deadline}); err != nil {
		s.log.Warn().Err(err).Msg("database snapshot for status failed")
	}
}

// sameHostRequest reports whether r comes from loopback or from the address
// it was received on.
func sameHostRequest(r *http.Request) bool {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	remoteIP := net.ParseIP(remote)
	if remoteIP == nil {
		return false
	}
	if remoteIP.IsLoopback() {
		return true
	}
	local, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
	if !ok {
		return false
	}
	localHost, _, err := net.SplitHostPort(local.String())
	return err == nil && remoteIP.Equal(net.ParseIP(localHost))
}
