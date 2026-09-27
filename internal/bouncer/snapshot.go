package bouncer

import (
	"io"
	"net"
	"net/http"
)

// DBSnapshotPath serves a consistent copy of the ban database to the status
// command, which cannot open the file while this process holds its lock.
const DBSnapshotPath = "/status/db"

// snapshotWriter is implemented by stores that can copy their database while
// it is open.
type snapshotWriter interface {
	WriteSnapshot(w io.Writer) (int64, error)
}

// dbSnapshot writes the database to a caller on the same host. Callers from
// elsewhere, including other containers and a published port, are refused.
func (b *Bouncer) dbSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !sameHostRequest(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	snap, ok := b.store.(snapshotWriter)
	if !ok {
		http.Error(w, "snapshot not supported by this store", http.StatusNotImplemented)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	if _, err := snap.WriteSnapshot(w); err != nil {
		b.log.Warn().Err(err).Msg("database snapshot for status failed")
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
