// Package session runs one pairing session end to end. The server
// side binds an ephemeral iroh endpoint whose identity is derived from
// the pairing code, publishes its addressing, waits for the single
// expected client, runs the version/SAS handshake on the control
// stream, and forwards accepted data streams to the declared TCP
// targets. The client side resolves and dials the server, declares its
// forward targets, confirms the SAS, and pipes local TCP listeners
// through data streams.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"

	"github.com/arnarg/tmite/internal/code"
	"github.com/arnarg/tmite/internal/discovery"
	"github.com/arnarg/tmite/internal/forward"
	"github.com/arnarg/tmite/internal/keys"
	"github.com/arnarg/tmite/internal/sas"
	"github.com/arnarg/tmite/internal/wire"
)

// Timeouts. The session lifetime bound (Timeout in ServerConfig) is a
// daemon flag; these bound the sub-steps of one session.
const (
	// DefaultOnlineTimeout bounds coming online (relay connect, NAT
	// discovery) after Bind.
	DefaultOnlineTimeout = 45 * time.Second
	// DefaultHandshakeTimeout bounds each side's version read.
	DefaultHandshakeTimeout = 30 * time.Second
	// DefaultDialTimeout bounds the TCP dial to a forward target.
	DefaultDialTimeout = 10 * time.Second
	// PreConfirmTimeout bounds each read of the SAS handshake.
	PreConfirmTimeout = 30 * time.Second
	// SASConfirmTimeout bounds the wait for the client's CONFIRM once
	// the SAS is computed.
	SASConfirmTimeout = 30 * time.Second
)

// State is the lifecycle state of a server session.
//
//	generating → waiting → verifying → connected → done
//	                ↓          ↓
//	            expired/cancelled/failed
type State int32

// Session states.
const (
	StateGenerating State = iota
	StateWaiting
	StateVerifying
	StateConnected
	StateDone
	StateExpired
	StateCancelled
	StateFailed
)

// String returns the wire name of the state.
func (s State) String() string {
	switch s {
	case StateGenerating:
		return "generating"
	case StateWaiting:
		return "waiting"
	case StateVerifying:
		return "verifying"
	case StateConnected:
		return "connected"
	case StateDone:
		return "done"
	case StateExpired:
		return "expired"
	case StateCancelled:
		return "cancelled"
	case StateFailed:
		return "failed"
	default:
		return fmt.Sprintf("state(%d)", int(s))
	}
}

// Terminal reports whether the state ends the session.
func (s State) Terminal() bool {
	switch s {
	case StateDone, StateExpired, StateCancelled, StateFailed:
		return true
	default:
		return false
	}
}

// ServerConfig configures one server session. Zero-value durations
// take the package defaults.
type ServerConfig struct {
	// Code is the pairing code; the session's identities are derived
	// from it.
	Code [code.TotalLen]byte
	// AllowForward restricts which targets the client may declare.
	AllowForward forward.Allowlist
	// Timeout is the session lifetime without a client. Zero means no
	// bound (daemon always sets one).
	Timeout time.Duration
	// Disc selects the iroh infrastructure (relays, pkarr).
	Disc discovery.Config
	// Bind, when valid, fixes the endpoint's local UDP address (an
	// empty host selects ::, so ":port" is a port-only bind). Zero
	// means an OS-assigned port on the unspecified address.
	Bind netip.AddrPort
	// ExternalAddrs pins public addresses advertised as NAT traversal
	// candidates (QNT) in addition to those net_report discovers.
	ExternalAddrs []netip.AddrPort
	// OnlineTimeout, HandshakeTimeout, DialTimeout override defaults.
	OnlineTimeout    time.Duration
	HandshakeTimeout time.Duration
	DialTimeout      time.Duration
	// OnSAS is called with the computed SAS as the session enters the
	// verifying state; nil skips the notification (tests that confirm
	// blindly).
	OnSAS func(sas string)
	// Publisher builds the address publisher for the session key; the
	// default publishes to pkarr per Disc. Tests substitute an
	// in-memory publisher.
	Publisher func(disc discovery.Config, sk key.SecretKey) (iroh.AddressPublisher, error)
	// ExtraOptions are appended to the endpoint options (tests: bind
	// loopback, disable relays).
	ExtraOptions []iroh.Option
}

// Server is one pairing session on the daemon: a goroutine, an
// ephemeral endpoint, and an observable lifecycle.
type Server struct {
	id      string
	cfg     ServerConfig
	started time.Time
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan struct{}
	ready   sync.Once
	readyCh chan struct{}

	mu              sync.Mutex
	state           State
	err             error
	cancelRequested bool
	sas             string
	subs            map[chan State]struct{}

	// paths stores the last observed iroh network paths, once the
	// connection is established. *Conn.Paths is safe to read after
	// Connected, so the value is snapshotted under mu in storePaths
	// and copied out under atomic for List.
	paths atomic.Value // []iroh.PathInfo
}

// Info is a point-in-time snapshot of a session.
type Info struct {
	ID      string
	State   State
	AgeSecs int
}

// StartServer starts a session goroutine. The session ends when parent
// is cancelled, cfg.Timeout elapses without a client, or the piped
// session finishes.
func StartServer(parent context.Context, cfg ServerConfig) *Server {
	baseCtx, baseCancel := context.WithCancel(parent)
	ctx, cancel := baseCtx, baseCancel
	if cfg.Timeout > 0 {
		tctx, tcancel := context.WithTimeout(baseCtx, cfg.Timeout)
		ctx, cancel = tctx, func() { tcancel(); baseCancel() }
	}

	s := &Server{
		id:      newID(),
		cfg:     cfg,
		started: time.Now(),
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
		readyCh: make(chan struct{}),
		subs:    make(map[chan State]struct{}),
	}
	s.state = StateGenerating
	go s.run()
	return s
}

// newID returns a random session ID, unrelated to the pairing code so
// it leaks nothing about it.
func newID() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("session: crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// ID returns the session ID.
func (s *Server) ID() string { return s.id }

// ExpiresAt returns the deadline for a client to connect, or the zero
// time when unbounded.
func (s *Server) ExpiresAt() time.Time {
	if s.cfg.Timeout > 0 {
		return s.started.Add(s.cfg.Timeout)
	}
	return time.Time{}
}

// State returns the current session state.
func (s *Server) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.state
}

// SAS returns the session's short authentication string once the
// session is verifying (or later), "" before.
func (s *Server) SAS() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sas
}

// Err returns the failure reason once the session is terminal, nil
// otherwise.
func (s *Server) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Info returns a snapshot for listing.
func (s *Server) Info() Info {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Info{
		ID:      s.id,
		State:   s.state,
		AgeSecs: int(time.Since(s.started).Round(time.Second).Seconds()),
	}
}

// PathInfo is a compact snapshot of one iroh connection path.
type PathInfo struct {
	Addr     string
	Relayed  bool
	Selected bool
	RTT      time.Duration
}

func (p PathInfo) String() string {
	kind := "direct"
	if p.Relayed {
		kind = "relayed"
	}
	s := kind + " " + p.Addr
	if p.RTT > 0 {
		s += " rtt=" + p.RTT.Round(time.Millisecond).String()
	}
	if p.Selected {
		s += " [active]"
	}
	return s
}

// Paths returns the last stored iroh connection paths, or nil before
// the client's connection is established. Copied out atomically so the
// accept loop's snapshot is never mutated under a reader.
func (s *Server) Paths() []PathInfo {
	v := s.paths.Load()
	if v == nil {
		return nil
	}
	return v.([]PathInfo)
}

// storePaths snapshots the live connection paths once the session is
// connected. Called under s.mu from the accept loop so it is ordered
// before the connected transition.
func (s *Server) storePaths(paths []iroh.PathInfo) {
	out := make([]PathInfo, 0, len(paths))
	for _, p := range paths {
		addr := ""
		if p.HasAddr {
			addr = p.Addr.String()
		}
		out = append(out, PathInfo{
			Addr:     addr,
			Relayed:  p.Relayed,
			Selected: p.Selected,
			RTT:      p.RTT,
		})
	}
	s.paths.Store(out)
}

// Done is closed when the session goroutine exits.
func (s *Server) Done() <-chan struct{} { return s.done }

// AwaitWaiting blocks until the endpoint is online and published (the
// words are safe to display), the session ends first, or ctx is done.
func (s *Server) AwaitWaiting(ctx context.Context) error {
	select {
	case <-s.readyCh:
		return nil
	case <-s.done:
		if err := s.Err(); err != nil {
			return err
		}
		return fmt.Errorf("session %s ended before ready: %s", s.id, s.State())
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Subscribe returns a channel receiving the current state followed by
// every subsequent transition. The channel is closed when the session
// becomes terminal.
func (s *Server) Subscribe() chan State {
	ch := make(chan State, 8)
	s.mu.Lock()
	defer s.mu.Unlock()
	ch <- s.state
	if s.subs == nil { // already terminal
		close(ch)
		return ch
	}
	s.subs[ch] = struct{}{}
	return ch
}

// Unsubscribe removes a subscription early.
func (s *Server) Unsubscribe(ch chan State) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.subs, ch)
}

// Cancel cancels a session that has not connected yet — generating,
// waiting, or verifying; it returns false for connected or terminal
// sessions.
func (s *Server) Cancel() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state != StateGenerating && s.state != StateWaiting && s.state != StateVerifying {
		return false
	}
	s.cancelRequested = true
	s.cancel()
	return true
}

func (s *Server) setState(next State) {
	s.mu.Lock()
	if s.state.Terminal() {
		s.mu.Unlock()
		return
	}
	s.state = next
	for ch := range s.subs {
		select {
		case ch <- next:
		default: // stalled subscriber; State() stays authoritative
		}
	}
	s.mu.Unlock()
}

// finish moves the session to a terminal state, records err, and
// closes every subscription.
func (s *Server) finish(st State, err error) {
	s.mu.Lock()
	if s.state.Terminal() {
		st, err = s.state, s.err
	} else {
		s.state, s.err = st, err
	}
	subs := s.subs
	s.subs = nil
	s.mu.Unlock()
	for ch := range subs {
		select {
		case ch <- st:
		default:
		}
		close(ch)
	}
}

// terminalCause classifies a ctx-driven end: explicit cancel wins,
// then the session deadline (expired), anything else failed.
func (s *Server) terminalCause(err error) State {
	s.mu.Lock()
	requested := s.cancelRequested
	s.mu.Unlock()
	switch {
	case requested:
		return StateCancelled
	case errors.Is(err, context.DeadlineExceeded):
		return StateExpired
	default:
		return StateFailed
	}
}

func (s *Server) markReady() { s.ready.Do(func() { close(s.readyCh) }) }

func (s *Server) run() {
	ctx := s.ctx
	defer s.cancel()
	defer close(s.done)

	serverKey, err := keys.DeriveServer(s.cfg.Code)
	if err != nil {
		s.finish(StateFailed, err)
		return
	}
	clientID, err := keys.ClientID(s.cfg.Code)
	if err != nil {
		s.finish(StateFailed, err)
		return
	}
	relayMode, err := discovery.RelayMode(s.cfg.Disc)
	if err != nil {
		s.finish(StateFailed, err)
		return
	}

	lookup := &iroh.AddressLookupServices{}
	opts := append([]iroh.Option{
		iroh.WithSecretKey(serverKey),
		iroh.WithALPNs(wire.ALPN),
		iroh.WithAddressLookup(lookup),
		iroh.WithRelayMode(relayMode),
		iroh.WithNetReport(),
	}, s.cfg.ExtraOptions...)
	if s.cfg.Bind.IsValid() {
		opts = append(opts, iroh.WithBindAddr(s.cfg.Bind))
	}
	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		s.finish(s.terminalCause(err), fmt.Errorf("bind: %w", err))
		return
	}
	defer func() { _ = ep.Shutdown(context.Background()) }()
	for _, addr := range s.cfg.ExternalAddrs {
		ep.AddExternalAddr(addr)
	}

	pub, err := s.newPublisher(serverKey)
	if err != nil {
		s.finish(StateFailed, err)
		return
	}
	lookup.AddPublisher(pub)
	if c, ok := pub.(io.Closer); ok {
		defer c.Close()
	}

	online := s.cfg.OnlineTimeout
	if online == 0 {
		online = DefaultOnlineTimeout
	}
	octx, cancelOnline := context.WithTimeout(ctx, online)
	err = ep.Online(octx)
	cancelOnline()
	if err != nil && !errors.Is(err, iroh.ErrNoRelay) {
		s.finish(s.terminalCause(err), fmt.Errorf("coming online: %w", err))
		return
	}

	// The endpoint does not auto-publish to AddressLookupServices;
	// feed it our addressing explicitly, and republish whenever the
	// advertised address changes.
	publish := func(addr netaddr.EndpointAddr) {
		lookup.Publish(dns.EndpointDataFromAddr(addr))
	}
	publish(ep.Addr())
	go func() {
		for addr := range ep.WatchAddr().Stream(ctx) {
			publish(addr)
		}
	}()

	s.setState(StateWaiting)
	s.markReady()

	for {
		conn, err := ep.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				s.finish(s.terminalCause(ctx.Err()), nil)
			} else {
				s.finish(StateFailed, fmt.Errorf("accept: %w", err))
			}
			return
		}
		if !conn.RemoteID().Equal(clientID) {
			_ = conn.CloseWithError(0, "tmite: unknown client")
			continue
		}
		connected, err := s.serve(ctx, conn)
		switch {
		case connected:
			s.finish(StateDone, nil)
		default:
			s.finish(s.terminalCause(err), err)
		}
		return
	}
}

func (s *Server) newPublisher(sk key.SecretKey) (iroh.AddressPublisher, error) {
	if s.cfg.Publisher != nil {
		return s.cfg.Publisher(s.cfg.Disc, sk)
	}
	return discovery.NewPublisher(s.cfg.Disc, sk)
}

// serve runs the single expected connection: version handshake,
// forward declaration, SAS handshake, then the data-stream accept
// loop. connected reports whether the session reached the connected
// state (CONFIRM received). The connection is not closed here; the
// session ends when the client closes the connection.
func (s *Server) serve(ctx context.Context, conn *iroh.Conn) (connected bool, err error) {
	ctrl, err := conn.AcceptStream(ctx)
	if err != nil {
		return false, fmt.Errorf("accept control stream: %w", err)
	}

	htimeout := s.cfg.HandshakeTimeout
	if htimeout == 0 {
		htimeout = DefaultHandshakeTimeout
	}
	_ = ctrl.SetReadDeadline(time.Now().Add(htimeout))
	err = wire.ServerHandshake(ctrl)
	if err != nil {
		return false, fmt.Errorf("handshake: %w", err)
	}

	// Forward declaration: non-empty and within the allowlist.
	_ = ctrl.SetReadDeadline(time.Now().Add(PreConfirmTimeout))
	targets, err := wire.ReadForwardLine(ctrl)
	if err != nil {
		return false, fmt.Errorf("forward line: %w", err)
	}
	for _, target := range targets {
		if !s.cfg.AllowForward.Allows(target) {
			return false, fmt.Errorf("forward target %q not allowed", target)
		}
	}

	// SAS handshake: read the client's commitment, reveal our key,
	// read the client's key, verify the commitment.
	commitment, err := wire.ReadCommitment(ctrl)
	if err != nil {
		return false, fmt.Errorf("sas commitment: %w", err)
	}
	serverKP, err := sas.Generate()
	if err != nil {
		return false, err
	}
	if err := wire.WritePub(ctrl, serverKP.Public()); err != nil {
		return false, fmt.Errorf("sas reveal: %w", err)
	}
	_ = ctrl.SetReadDeadline(time.Now().Add(PreConfirmTimeout))
	clientPub, err := wire.ReadPub(ctrl)
	if err != nil {
		return false, fmt.Errorf("sas client key: %w", err)
	}
	if commitment != sas.Commitment(clientPub) {
		return false, wire.ErrCommitmentMismatch
	}
	ss, err := serverKP.Shared(clientPub)
	if err != nil {
		return false, fmt.Errorf("sas key agreement: %w", err)
	}
	fwdLine := wire.ForwardLine(targets)
	sasCode := sas.Compute(ss, []byte(fwdLine), clientPub, serverKP.Public())

	// Snapshot the connection's live paths before publishing the
	// verifying state, so list --paths sees path data as soon as the
	// session reports progress. Paths() is safe to call now that the
	// QUIC handshake is complete.
	s.storePaths(conn.Paths())
	// The relay path is selected first; hole-punching migrates to a
	// direct path shortly after. Keep the snapshot current by following
	// path events until the connection ends, so list --paths reports
	// the eventual direct path instead of the stale relayed one.
	go func() {
		stream, err := conn.WatchPaths(ctx)
		if err != nil {
			return
		}
		for paths := range stream {
			if len(paths) > 0 {
				s.storePaths(paths)
			}
		}
	}()

	s.mu.Lock()
	s.sas = sasCode
	s.mu.Unlock()
	if s.cfg.OnSAS != nil {
		s.cfg.OnSAS(sasCode)
	}
	s.setState(StateVerifying)

	// Wait for the human-gated CONFIRM (or an explicit REJECT).
	_ = ctrl.SetReadDeadline(time.Now().Add(SASConfirmTimeout))
	if err := wire.ReadConfirm(ctrl); err != nil {
		if errors.Is(err, wire.ErrSASRejected) {
			return false, err
		}
		return false, fmt.Errorf("sas confirm: %w", err)
	}
	_ = ctrl.SetReadDeadline(time.Time{})
	s.setState(StateConnected)

	// Accept data streams until the connection closes. The semaphore
	// bounds concurrent streams; over the limit a stream is rejected
	// immediately.
	sem := make(chan struct{}, wire.MaxStreams)
	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return true, ctx.Err()
			}
			// The client closed the connection: the session is done.
			return true, nil
		}
		select {
		case sem <- struct{}{}:
		default:
			_ = stream.Close()
			continue
		}
		go func() {
			defer func() { <-sem }()
			s.serveStream(ctx, stream, targets)
		}()
	}
}

// serveStream runs one data stream: target declaration, membership
// check against the SAS-bound forward set, TCP dial, then the
// bidirectional pipe. The stream is closed only after the pipe's FIN
// has had a moment to reach the client, so the client sees EOF
// instead of a reset.
func (s *Server) serveStream(ctx context.Context, stream *iroh.Stream, targets []string) {
	dtimeout := s.cfg.DialTimeout
	if dtimeout == 0 {
		dtimeout = DefaultDialTimeout
	}
	_ = stream.SetReadDeadline(time.Now().Add(dtimeout))
	target, err := wire.ReadDataForward(stream)
	if err != nil {
		_ = wire.WriteDataErr(stream, "bad forward line")
		_ = stream.Close()
		return
	}
	_ = stream.SetReadDeadline(time.Time{})

	allowed := slices.Contains(targets, target)
	if !allowed {
		_ = wire.WriteDataErr(stream, "target not in session forward list")
		_ = stream.Close()
		return
	}

	dialer := net.Dialer{Timeout: dtimeout}
	tcpConn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		_ = wire.WriteDataErr(stream, err.Error())
		_ = stream.Close()
		return
	}
	defer tcpConn.Close()
	tcp := tcpConn.(*net.TCPConn)
	if err := wire.WriteDataOK(stream); err != nil {
		_ = stream.Close()
		return
	}
	_ = pipe(stream, tcp)
	// Give the stream FIN a beat to reach the client before the
	// (deferred, goroutine-exit) cleanup path can tear anything down.
	time.Sleep(100 * time.Millisecond)
	_ = stream.Close()
}

// pipe copies bidirectionally between the iroh stream and the target
// TCP connection, forwarding half-closes: when one peer finishes
// sending, the write side towards the other peer is closed so EOF
// propagates, and copying continues in the remaining direction until
// it ends too.
func pipe(stream *iroh.Stream, tcp *net.TCPConn) error {
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(tcp, stream)
		_ = tcp.CloseWrite() // forward the client's FIN to the target
		errc <- err
	}()
	go func() {
		_, err := io.Copy(stream, tcp)
		_ = stream.Close() // graceful FIN to the client
		errc <- err
	}()
	err1, err2 := <-errc, <-errc
	for _, err := range []error{err1, err2} {
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
	}
	return nil
}
