package daemon

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/arnarg/tmite/internal/code"
	"github.com/arnarg/tmite/internal/discovery"
	"github.com/arnarg/tmite/internal/forward"
	"github.com/arnarg/tmite/internal/session"
)

// Defaults.
const (
	// DefaultSocket is the daemon Unix socket path.
	DefaultSocket = "/run/tmite/daemon"
	// DefaultSessionTimeout is the session lifetime without a client.
	DefaultSessionTimeout = 5 * time.Minute
	// DefaultSocketMode lets any local user create sessions (the
	// pairing code and SAS still authenticate); tighten for
	// multi-user machines.
	DefaultSocketMode fs.FileMode = 0o666
	// maxRequestSize bounds one NDJSON command line.
	maxRequestSize = 64 * 1024
)

// Config configures the daemon.
type Config struct {
	// SocketPath is the Unix socket to listen on.
	SocketPath string
	// SocketMode is the permission of the socket file. Zero uses
	// DefaultSocketMode.
	SocketMode fs.FileMode
	// AllowForward restricts which targets sessions may forward to.
	// Required: New returns nil without at least one pattern.
	AllowForward forward.Allowlist
	// SessionTimeout is the per-session lifetime without a client.
	SessionTimeout time.Duration
	// Disc selects the iroh infrastructure for session endpoints.
	Disc discovery.Config
	// Bind and ExternalAddrs fix each session endpoint's local UDP
	// address and pinned public NAT traversal candidates. Zero/empty
	// select the OS defaults.
	Bind          netip.AddrPort
	ExternalAddrs []netip.AddrPort
	// SessionTune mutates every new session's config (tests).
	SessionTune func(*session.ServerConfig)
}

// Daemon manages pairing sessions behind a Unix socket.
type Daemon struct {
	cfg Config
	ctx context.Context

	mu       sync.Mutex
	sessions map[string]*session.Server
}

// New returns a daemon with defaults filled in, or nil if the config
// is invalid (no forward allowlist).
func New(cfg Config) *Daemon {
	if len(cfg.AllowForward) == 0 {
		return nil
	}
	if cfg.SocketPath == "" {
		cfg.SocketPath = DefaultSocket
	}
	if cfg.SocketMode == 0 {
		cfg.SocketMode = DefaultSocketMode
	}
	if cfg.SessionTimeout == 0 {
		cfg.SessionTimeout = DefaultSessionTimeout
	}
	return &Daemon{cfg: cfg, sessions: make(map[string]*session.Server)}
}

// Run listens on the socket and serves connections until ctx is done.
func (d *Daemon) Run(ctx context.Context) error {
	d.ctx = ctx

	dir := filepath.Dir(d.cfg.SocketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("daemon: creating %s: %w", dir, err)
	}
	// Remove a stale socket from a previous run.
	if err := os.Remove(d.cfg.SocketPath); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("daemon: removing stale socket: %w", err)
	}
	ln, err := net.Listen("unix", d.cfg.SocketPath)
	if err != nil {
		return fmt.Errorf("daemon: listening on %s: %w", d.cfg.SocketPath, err)
	}
	if err := os.Chmod(d.cfg.SocketPath, d.cfg.SocketMode); err != nil {
		ln.Close()
		return fmt.Errorf("daemon: setting socket mode: %w", err)
	}

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("daemon: accept: %w", err)
		}
		go d.handleConn(conn)
	}
}

// handleConn serves one NDJSON connection. Commands may arrive on the
// same connection while pair is streaming events, so pair is served in
// its own goroutine; writes are serialized by the conn writer.
func (d *Daemon) handleConn(conn net.Conn) {
	defer conn.Close()
	cctx, cancel := context.WithCancel(d.ctx)
	defer cancel()

	w := newConnWriter(conn)
	sc := bufio.NewScanner(conn)
	sc.Buffer(make([]byte, 0, 4096), maxRequestSize)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			w.write(Response{OK: false, Error: "bad request: " + err.Error()})
			continue
		}
		switch req.Cmd {
		case "code":
			go d.handleCode(cctx, w)
		case "list":
			w.write(d.listResponse(req.Paths, req.All))
		case "cancel":
			w.write(d.cancelResponse(req))
		case "":
			w.write(Response{OK: false, Error: "missing cmd"})
		default:
			w.write(Response{OK: false, Error: fmt.Sprintf("unknown command %q", req.Cmd)})
		}
	}
	// Connection closed (or broke): stop streaming to it. Sessions
	// themselves are tied to the daemon lifetime and keep running.
	cancel()
	// A scanner error (e.g. oversized line) ends the loop the same way
	// as a close; nothing to report either way.
	_ = sc.Err()
}

// connWriter serializes NDJSON lines onto a connection.
type connWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newConnWriter(conn net.Conn) *connWriter {
	return &connWriter{enc: json.NewEncoder(conn)}
}

func (w *connWriter) write(v any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(v)
}

// handleCode generates a code, starts a session, and once the endpoint
// is published replies with the words. It then streams state changes —
// including the SAS on the verifying transition — until the tunnel is
// established or the session ends: code is a subscription, not a
// one-shot.
func (d *Daemon) handleCode(ctx context.Context, w *connWriter) {
	words, err := code.GenerateWords()
	if err != nil {
		w.write(Response{OK: false, Error: err.Error()})
		return
	}
	c, err := code.Decode(words)
	if err != nil {
		w.write(Response{OK: false, Error: err.Error()})
		return
	}

	cfg := session.ServerConfig{
		Code:          c,
		AllowForward:  d.cfg.AllowForward,
		Timeout:       d.cfg.SessionTimeout,
		Disc:          d.cfg.Disc,
		Bind:          d.cfg.Bind,
		ExternalAddrs: d.cfg.ExternalAddrs,
	}
	if d.cfg.SessionTune != nil {
		d.cfg.SessionTune(&cfg)
	}
	s := session.StartServer(d.ctx, cfg)
	d.addSession(s)

	if err := s.AwaitWaiting(context.Background()); err != nil {
		w.write(Response{OK: false, Error: "session failed to start: " + err.Error()})
		return
	}
	resp := Response{OK: true, Words: words, ID: s.ID()}
	if exp := s.ExpiresAt(); !exp.IsZero() {
		resp.Expires = exp.UTC().Format(time.RFC3339)
	}
	if err := w.write(resp); err != nil {
		return
	}

	events := s.Subscribe()
	defer s.Unsubscribe(events)
	for {
		select {
		case <-ctx.Done():
			return
		case st, ok := <-events:
			if !ok {
				return
			}
			ev := Event{Event: st.String()}
			if st == session.StateVerifying {
				ev.SAS = s.SAS()
			}
			if err := w.write(ev); err != nil {
				return
			}
			// code hangs until the tunnel is established or the
			// session ended without one.
			if st == session.StateConnected || st.Terminal() {
				return
			}
		}
	}
}

func (d *Daemon) addSession(s *session.Server) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sessions[s.ID()] = s
}

func (d *Daemon) listResponse(withPaths, all bool) Response {
	d.mu.Lock()
	type entry struct {
		info session.Info
		srv  *session.Server
	}
	entries := make([]entry, 0, len(d.sessions))
	for _, s := range d.sessions {
		in := s.Info()
		if !all && in.State.Terminal() {
			continue
		}
		entries = append(entries, entry{info: in, srv: s})
	}
	d.mu.Unlock()
	// Keep the paths snapshot aligned with its Info: capture both
	// under the same lock. Servers are keyed by ID so re-sorting is
	// deterministic.
	sort.Slice(entries, func(i, j int) bool { return entries[i].info.ID < entries[j].info.ID })
	list := make([]SessionInfo, 0, len(entries))
	for _, e := range entries {
		si := SessionInfo{ID: e.info.ID, State: e.info.State.String(), AgeSecs: e.info.AgeSecs}
		if withPaths {
			si.Paths = daemonPaths(e.srv.Paths())
		}
		list = append(list, si)
	}
	return Response{OK: true, List: list}
}

// daemonPaths converts session path snapshots to the wire form.
func daemonPaths(paths []session.PathInfo) []PathInfo {
	if len(paths) == 0 {
		return nil
	}
	out := make([]PathInfo, 0, len(paths))
	for _, p := range paths {
		out = append(out, PathInfo{
			Addr:     p.Addr,
			Relayed:  p.Relayed,
			Selected: p.Selected,
			RTTSecs:  int64(p.RTT),
		})
	}
	return out
}

func (d *Daemon) cancelResponse(req Request) Response {
	d.mu.Lock()
	s := d.sessions[req.ID]
	d.mu.Unlock()
	switch {
	case s == nil:
		return Response{OK: false, Error: "session not found"}
	case s.Cancel():
		return Response{OK: true}
	case s.State() == session.StateConnected:
		return Response{OK: false, Error: "session already connected"}
	default:
		return Response{OK: false, Error: "session already ended (" + s.State().String() + ")"}
	}
}
