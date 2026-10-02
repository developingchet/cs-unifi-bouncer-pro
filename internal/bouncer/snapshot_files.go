package bouncer

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/rs/zerolog"
)

const (
	// SnapshotTempPrefix starts the name of the temporary file the status
	// command saves a database snapshot to; os.CreateTemp appends digits.
	SnapshotTempPrefix = "bouncer.db.status-"
	// snapshotStaleAfter is how old a snapshot file must be before it counts
	// as abandoned. A live download is bounded by snapshotWriteTimeout.
	snapshotStaleAfter = 5 * time.Minute
)

var errSnapshotDeadline = errors.New("database snapshot exceeded its time limit")

var snapshotTempName = regexp.MustCompile(`^` + regexp.QuoteMeta(SnapshotTempPrefix) + `[0-9]+$`)

// RemoveStaleSnapshots deletes snapshot files in dir that a status command
// left behind when it was killed before it could remove them. Only regular
// files named exactly like the status command's temporary files and untouched
// for snapshotStaleAfter are removed, so a snapshot being downloaded is left
// alone. It returns the number of files removed.
func RemoveStaleSnapshots(dir string, log zerolog.Logger) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		log.Warn().Err(err).Str("dir", dir).Msg("cannot scan for stale status snapshots")
		return 0
	}
	cutoff := time.Now().Add(-snapshotStaleAfter)
	removed := 0
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !snapshotTempName.MatchString(entry.Name()) {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := os.Remove(path); err != nil {
			log.Warn().Err(err).Str("file", path).Msg("cannot remove stale status snapshot")
			continue
		}
		removed++
	}
	if removed > 0 {
		log.Info().Int("files", removed).Msg("removed stale status snapshots")
	}
	return removed
}

// deadlineWriter fails writes made after deadline. A snapshot holds a
// database read transaction open for as long as it is being written, and a
// slow reader must not keep that transaction open indefinitely.
type deadlineWriter struct {
	w        io.Writer
	deadline time.Time
}

func (d *deadlineWriter) Write(p []byte) (int, error) {
	if time.Now().After(d.deadline) {
		return 0, errSnapshotDeadline
	}
	return d.w.Write(p)
}
