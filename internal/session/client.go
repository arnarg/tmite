package session

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"

	"github.com/arnarg/tmite/internal/code"
	"github.com/arnarg/tmite/internal/discovery"
	"github.com/arnarg/tmite/internal/forward"
	"github.com/arnarg/tmite/internal/keys"
	"github.com/arnarg/tmite/internal/sas"
	"github.com/arnarg/tmite/internal/wire"
)

// DefaultClientWait is the client dial backoff budget (the --wait flag
// default).
const DefaultClientWait = 10 * time.Minute

// Client errors, mapped to distinct exit codes by the join command:
// ErrTimeout → exit 2, ErrSASMismatch → exit 3, ErrRejected → exit 4.
var (
	ErrTimeout = errors.New("session: server did not come online within the wait budget")
	// ErrSASMismatch means the human rejected the SAS (or the
	// confirmation timed out).
	ErrSASMismatch = errors.New("session: SAS not confirmed")
	// ErrRejected means the server closed the connection during the
	// handshake: wrong client identity, expired session, disallowed or
	// empty forward list, or commitment mismatch.
	ErrRejected = errors.New("session: server rejected the connection")
)

// ClientConfig configures one client session. Zero-value durations
// take the package defaults.
type ClientConfig struct {
	// Code is the pairing code; the client identity and the expected
	// server identity are derived from it.
	Code [code.TotalLen]byte
	// Forwards are the local listeners and their remote targets. At
	// least one is required.
	Forwards []forward.Spec
	// SASConfirmer is called with the computed SAS; it must return
	// true only when the human confirms the SAS matches the server's
	// console. Nil rejects (fails closed).
	SASConfirmer func(sas string) bool
	// OnConnected, when set, is called with the established
	// connection right after CONFIRM, before the local listeners
	// start (tests use it to open raw data streams).
	OnConnected func(conn *iroh.Conn)
	// SASConfirmTimeout bounds the human at the SAS gate. Zero uses
	// SASConfirmTimeout.
	SASConfirmTimeout time.Duration
	// Wait is the dial backoff budget.
	Wait time.Duration
	// Disc selects the iroh infrastructure; it must match the
	// daemon's for resolution to work.
	Disc discovery.Config
	// Bind, when valid, fixes the endpoint's local UDP address (an
	// empty host selects ::). Zero means an OS-assigned port.
	Bind netip.AddrPort
	// ExternalAddrs pins public addresses advertised as NAT traversal
	// candidates (QNT) in addition to those net_report discovers.
	ExternalAddrs []netip.AddrPort
	// HandshakeTimeout overrides DefaultHandshakeTimeout.
	HandshakeTimeout time.Duration
	// Logf receives progress updates (attempts, backoffs); nil is
	// silent.
	Logf func(format string, args ...any)
	// Lookup overrides the address resolvers (tests). Nil builds them
	// from Disc.
	Lookup *iroh.AddressLookupServices
	// ExtraOptions are appended to the endpoint options (tests: bind
	// loopback, disable relays).
	ExtraOptions []iroh.Option
}

// Connect resolves and dials the server derived from the pairing code,
// performs the version and SAS handshake, and forwards local listeners
// through the tunnel until the connection ends. It returns nil on a
// clean end, ErrTimeout if the wait budget elapses first,
// ErrSASMismatch if the human rejects the SAS, and ErrRejected if the
// server closes the connection during the handshake.
func Connect(ctx context.Context, cfg ClientConfig) error {
	if len(cfg.Forwards) == 0 {
		return errors.New("session: no forwards configured")
	}
	clientKey, err := keys.DeriveClient(cfg.Code)
	if err != nil {
		return err
	}
	serverID, err := keys.ServerID(cfg.Code)
	if err != nil {
		return err
	}

	lookup := cfg.Lookup
	if lookup == nil {
		lookup, err = discovery.NewResolvers(cfg.Disc)
		if err != nil {
			return err
		}
	}
	relayMode, err := discovery.RelayMode(cfg.Disc)
	if err != nil {
		return err
	}

	opts := append([]iroh.Option{
		iroh.WithSecretKey(clientKey),
		iroh.WithALPNs(wire.ALPN),
		iroh.WithAddressLookup(lookup),
		iroh.WithRelayMode(relayMode),
		iroh.WithNetReport(),
	}, cfg.ExtraOptions...)
	if cfg.Bind.IsValid() {
		opts = append(opts, iroh.WithBindAddr(cfg.Bind))
	}
	ep, err := iroh.Bind(ctx, opts...)
	if err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	defer func() { _ = ep.Shutdown(context.Background()) }()
	for _, addr := range cfg.ExternalAddrs {
		ep.AddExternalAddr(addr)
	}

	wait := cfg.Wait
	if wait == 0 {
		wait = DefaultClientWait
	}
	dctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	logf(cfg.Logf, "connecting to server %s (waiting up to %s)", serverID.Short(), wait)
	conn, err := dialRetry(dctx, ep, lookup, serverID, cfg.Logf)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || dctx.Err() != nil {
			return fmt.Errorf("%w (budget %s)", ErrTimeout, wait)
		}
		return err
	}
	defer conn.CloseWithError(0, "")

	ctrl, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return fmt.Errorf("open control stream: %w", err)
	}

	if err := clientHandshake(ctrl, cfg); err != nil {
		return err
	}
	if cfg.OnConnected != nil {
		cfg.OnConnected(conn)
	}
	return serveForwards(ctx, conn, cfg)
}

// clientHandshake runs the control-stream protocol up to CONFIRM:
// version, forward declaration, SAS commitment exchange, human gate.
func clientHandshake(ctrl *iroh.Stream, cfg ClientConfig) error {
	htimeout := cfg.HandshakeTimeout
	if htimeout == 0 {
		htimeout = DefaultHandshakeTimeout
	}
	_ = ctrl.SetReadDeadline(time.Now().Add(htimeout))
	err := wire.ClientHandshake(ctrl)
	if err != nil {
		_ = ctrl.SetReadDeadline(time.Time{})
		return classifyHandshakeErr(err)
	}

	targets := make([]string, 0, len(cfg.Forwards))
	for _, f := range cfg.Forwards {
		targets = append(targets, f.Target)
	}
	if err := wire.WriteForwardLine(ctrl, targets); err != nil {
		_ = ctrl.SetReadDeadline(time.Time{})
		return fmt.Errorf("forward line: %w", err)
	}

	// SAS handshake: commit to our key before learning the server's,
	// reveal after.
	clientKP, err := sas.Generate()
	if err != nil {
		_ = ctrl.SetReadDeadline(time.Time{})
		return err
	}
	if err := wire.WriteCommitment(ctrl, sas.Commitment(clientKP.Public())); err != nil {
		_ = ctrl.SetReadDeadline(time.Time{})
		return fmt.Errorf("sas commitment: %w", err)
	}
	_ = ctrl.SetReadDeadline(time.Now().Add(PreConfirmTimeout))
	serverPub, err := wire.ReadPub(ctrl)
	if err != nil {
		_ = ctrl.SetReadDeadline(time.Time{})
		return fmt.Errorf("%w: sas server key: %v", ErrRejected, err)
	}
	if err := wire.WritePub(ctrl, clientKP.Public()); err != nil {
		_ = ctrl.SetReadDeadline(time.Time{})
		return fmt.Errorf("sas reveal: %w", err)
	}
	ss, err := clientKP.Shared(serverPub)
	if err != nil {
		_ = ctrl.SetReadDeadline(time.Time{})
		return fmt.Errorf("sas key agreement: %w", err)
	}
	_ = ctrl.SetReadDeadline(time.Time{})

	sasCode := sas.Compute(ss, []byte(wire.ForwardLine(targets)), clientKP.Public(), serverPub)
	if !confirmSAS(cfg, sasCode) {
		// Best effort: tell the server so it fails fast instead of
		// waiting out the confirmation timeout.
		_ = wire.WriteReject(ctrl)
		return ErrSASMismatch
	}
	if err := wire.WriteConfirm(ctrl); err != nil {
		return fmt.Errorf("sas confirm: %w", err)
	}
	return nil
}

// classifyHandshakeErr maps version-exchange failures: a version
// mismatch is a real protocol error, a timeout is a hung server;
// anything else means the server dropped us before the session
// started.
func classifyHandshakeErr(err error) error {
	if errors.Is(err, wire.ErrVersionMismatch) {
		return err
	}
	var te interface{ Timeout() bool }
	if errors.As(err, &te) && te.Timeout() {
		return fmt.Errorf("handshake: %w", err)
	}
	return fmt.Errorf("%w: %v", ErrRejected, err)
}

// confirmSAS runs the human confirmer bounded by the confirmation
// timeout: the confirmer runs in its own goroutine, raced against the
// clock. A nil confirmer or a timeout rejects (fails closed).
func confirmSAS(cfg ClientConfig, sasCode string) bool {
	if cfg.SASConfirmer == nil {
		return false
	}
	timeout := cfg.SASConfirmTimeout
	if timeout == 0 {
		timeout = SASConfirmTimeout
	}
	okc := make(chan bool, 1)
	go func() { okc <- cfg.SASConfirmer(sasCode) }()
	select {
	case ok := <-okc:
		return ok
	case <-time.After(timeout):
		return false
	}
}

// serveForwards listens on each forward's local address and pipes every
// accepted connection through a new data stream, until ctx ends or the
// connection closes.
func serveForwards(ctx context.Context, conn *iroh.Conn, cfg ClientConfig) error {
	// One listener group: any fatal error (a bind failure counts —
	// partial forwarding is worse than none) tears the group down.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var listeners []net.Listener
	closeAll := func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}
	var wg sync.WaitGroup
	for _, f := range cfg.Forwards {
		ln, err := new(net.ListenConfig).Listen(ctx, "tcp", f.Bind)
		if err != nil {
			closeAll()
			return fmt.Errorf("listen %s: %w", f.Bind, err)
		}
		listeners = append(listeners, ln)
		logf(cfg.Logf, "forwarding %s -> %s", f.Bind, f.Target)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				tcp, err := ln.Accept()
				if err != nil {
					return
				}
				go serveConn(ctx, conn, tcp.(*net.TCPConn), f.Target, cfg.Logf)
			}
		}()
	}
	defer closeAll()

	// The session ends when the connection closes or ctx is done.
	select {
	case <-conn.Context().Done():
	case <-ctx.Done():
	}
	closeAll()
	wg.Wait()
	return nil
}

// serveConn opens one data stream for tcp, declares the target, waits
// for the server's OK, then pipes bidirectionally.
func serveConn(ctx context.Context, conn *iroh.Conn, tcp *net.TCPConn, target string, log func(string, ...any)) {
	defer tcp.Close()
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		logf(log, "open stream for %s: %v", target, err)
		return
	}
	dtimeout := DefaultDialTimeout
	_ = stream.SetReadDeadline(time.Now().Add(dtimeout))
	if err := wire.WriteDataForward(stream, target); err != nil {
		logf(log, "declare %s: %v", target, err)
		_ = stream.Close()
		return
	}
	err = wire.ReadDataReply(stream)
	_ = stream.SetReadDeadline(time.Time{})
	if err != nil {
		logf(log, "forward %s: %v", target, err)
		_ = stream.Close()
		return
	}
	_ = pipe(stream, tcp)
	_ = stream.Close()
}

func logf(f func(string, ...any), format string, args ...any) {
	if f != nil {
		f(format, args...)
	}
}

// dialRetry dials with exponential backoff (1s → 10s) within the ctx
// budget. go-iroh's Connect does not consult AddressLookupServices for
// a bare EndpointAddr before dialing, so we resolve the server ID
// ourselves each round. A connect that completes but yields the wrong
// RemoteID (stale or mis-signed pkarr data) is a failed attempt: the
// connection is dropped and the dial retried, never surfaced as a
// session.
func dialRetry(ctx context.Context, ep *iroh.Endpoint, lookup *iroh.AddressLookupServices, serverID key.EndpointID, log func(string, ...any)) (*iroh.Conn, error) {
	delay := time.Second
	for attempt := 1; ; attempt++ {
		addr, resErr := discovery.ResolveID(ctx, lookup, serverID)
		if resErr == nil {
			conn, err := ep.Connect(ctx, addr, wire.ALPN)
			switch {
			case err == nil && conn.RemoteID().Equal(serverID):
				return conn, nil
			case err == nil:
				_ = conn.CloseWithError(0, "tmite: resolved peer has unexpected ID")
				err = fmt.Errorf("resolution returned wrong peer for %s", serverID.Short())
			}
			if log != nil {
				log("connect failed (attempt %d): %v; retrying in %s", attempt, err, delay)
			}
		} else if log != nil {
			log("server not found yet (attempt %d): %v; retrying in %s", attempt, resErr, delay)
		}
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
		}
		if delay < 10*time.Second {
			delay *= 2
			if delay > 10*time.Second {
				delay = 10 * time.Second
			}
		}
	}
}
