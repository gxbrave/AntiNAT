// Terminal decommission marker (docs/state-model.md §3.4, v0.8 §9.2).
//
// The marker is a separate file from bbolt and is loaded first: it records
// whether the Agent is ACTIVE, DECOMMISSIONING (written before any Forward
// stops), or DECOMMISSIONED (only cleanup is allowed). It is written
// atomically — temp file + fsync + rename + parent-directory fsync — with
// mode 0600 so a crash never leaves a torn marker and an interrupted write
// cannot be mistaken for a terminal state.
package localstate

import (
	"fmt"
	"os"
	"path/filepath"
)

// markerFile is the terminal marker filename inside the Agent state directory.
const markerFile = "terminal.marker"

// MarkerState is the durable terminal lifecycle state.
type MarkerState string

const (
	// MarkerActive means no terminal marker exists; the Agent runs normally.
	MarkerActive MarkerState = ""
	// MarkerDecommissioning is written first (before any Forward stops); no
	// concurrent desired apply may start a new actor from this point on.
	MarkerDecommissioning MarkerState = "DECOMMISSIONING"
	// MarkerDecommissioned means the node is decommissioned; only
	// CLEANUP_ONLY sessions are allowed.
	MarkerDecommissioned MarkerState = "DECOMMISSIONED"
)

func (m MarkerState) String() string {
	if m == "" {
		return "ACTIVE"
	}
	return string(m)
}

var validMarkerStates = map[MarkerState]bool{
	MarkerDecommissioning: true,
	MarkerDecommissioned:  true,
}

// LoadMarker reads the terminal marker. Absent file means ACTIVE; any other
// content fails closed.
func LoadMarker(dir string) (MarkerState, error) {
	raw, err := os.ReadFile(filepath.Join(dir, markerFile))
	if err != nil {
		if errNotExist(err) {
			return MarkerActive, nil
		}
		return "", fmt.Errorf("localstate: read terminal marker: %w", err)
	}
	state := MarkerState(string(raw))
	if !validMarkerStates[state] {
		return "", fmt.Errorf("localstate: invalid terminal marker %q", string(raw))
	}
	return state, nil
}

// WriteMarker atomically writes a terminal marker state: temp file in the
// same directory, fsync, rename over the marker, then parent-directory fsync.
// The rename is what makes the state durable and the temp prefix keeps an
// interrupted write from being mistaken for a marker.
func WriteMarker(dir string, state MarkerState) error {
	if !validMarkerStates[state] {
		return fmt.Errorf("localstate: refusing to write invalid terminal marker %q", string(state))
	}
	if err := ensurePrivateDirectory(dir); err != nil {
		return err
	}
	path := filepath.Join(dir, markerFile)
	temporary, err := os.CreateTemp(dir, ".antinat-marker-*")
	if err != nil {
		return fmt.Errorf("localstate: create marker temp: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: marker chmod: %w", err)
	}
	if _, err := temporary.WriteString(string(state)); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: marker write: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("localstate: marker fsync: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("localstate: marker close: %w", err)
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("localstate: marker rename: %w", err)
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("localstate: marker parent fsync: %w", err)
	}
	return nil
}
