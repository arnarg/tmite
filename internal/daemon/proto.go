// Package daemon implements the tmite daemon: a Unix-socket server
// speaking NDJSON (one JSON object per line) that manages pairing
// sessions. code starts a session and streams its state changes; list
// snapshots them; cancel ends one that has not connected yet.
package daemon

// Request is one NDJSON command line sent to the daemon.
type Request struct {
	// Cmd is "code", "list", or "cancel".
	Cmd string `json:"cmd"`
	// ID selects a session (cancel).
	ID string `json:"id,omitempty"`
	// Paths requests per-connection path detail in a list response.
	Paths bool `json:"paths,omitempty"`
	// All includes terminal (done/expired/cancelled/failed) sessions.
	All bool `json:"all,omitempty"`
}

// Response is one NDJSON reply line. The OK field is always present;
// the rest are command-specific.
type Response struct {
	OK      bool          `json:"ok"`
	Error   string        `json:"error,omitempty"`
	Words   []string      `json:"words,omitempty"`
	ID      string        `json:"id,omitempty"`
	Expires string        `json:"expires,omitempty"`
	List    []SessionInfo `json:"sessions,omitempty"`
}

// SessionInfo is one entry of a list response.
type SessionInfo struct {
	ID      string `json:"id"`
	State   string `json:"state"`
	AgeSecs int    `json:"age_secs"`
	// Paths carries connection path detail when "paths" was requested.
	Paths []PathInfo `json:"paths,omitempty"`
}

// PathInfo is one iroh connection path of a session.
type PathInfo struct {
	Addr     string `json:"addr"`
	Relayed  bool   `json:"relayed"`
	Selected bool   `json:"selected"`
	RTTSecs  int64  `json:"rtt_secs,omitempty"` // nanoseconds
}

// Event is an asynchronous session state change, streamed to a code
// connection after its initial response: waiting, verifying,
// connected, done, expired, cancelled, or failed. The verifying event
// carries the session's SAS for display.
type Event struct {
	Event string `json:"event"`
	SAS   string `json:"sas,omitempty"`
}
