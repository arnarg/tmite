// Package wire implements the tmite stream protocols. The control
// stream carries version negotiation, the forward declaration, and the
// SAS handshake; after CONFIRM it stays open as a session heartbeat.
// Data streams (one per forwarded TCP connection) carry a minimal
// FWD/OK framing followed by a raw bidirectional pipe.
//
//	Client                                   Server
//	  │ ── "TMITE1\n" ────────────────────────► │  version check
//	  │ ◄─────────────────── "TMITE1\n" ─────── │  (both abort on mismatch)
//	  │ ── "FWD localhost:80,localhost:5432\n"─► │  forward targets
//	  │ ── SHA-256 commitment (32B) ──────────► │  SAS agreement
//	  │ ◄──────────────── X25519 pub (32B) ──── │  (hash commitment:
//	  │ ── X25519 pub (32B) ──────────────────► │   server picks blind)
//	  │ ── "CONFIRM\n" ───────────────────────► │  SAS-gated
//	  │                                          │
//	  │ ── "FWD host:port\n" ─────────────────► │  data stream
//	  │ ◄── "OK\n" / "ERR ...\n" ────────────── │
//	  │ ◄════════ raw bidirectional ══════════► │
package wire

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/arnarg/tmite/internal/sas"
)

// ALPN is the iroh transport-level ALPN for protocol v1.
const ALPN = "tmite/1"

// Version is the wire protocol version string exchanged first.
const Version = "TMITE1"

// ConfirmLine is the client's SAS confirmation on the control stream.
const ConfirmLine = "CONFIRM"

// RejectLine is the client's SAS rejection on the control stream; it
// lets the server fail the session immediately instead of waiting out
// the confirmation timeout.
const RejectLine = "REJECT"

// MaxStreams bounds concurrent data streams per session on the server.
const MaxStreams = 64

// maxLineLen bounds any protocol line; anything longer is rejected
// without buffering.
const maxLineLen = 4096

// Handshake errors.
var (
	ErrVersionMismatch = errors.New("wire: version mismatch")
	ErrPeerClosed      = errors.New("wire: peer closed")
	ErrLineTooLong     = errors.New("wire: line too long")
	// ErrEmptyForward means the client declared no forward targets.
	ErrEmptyForward = errors.New("wire: empty forward list")
	// ErrCommitmentMismatch means the client's revealed key does not
	// match its earlier commitment (protocol violation or attack).
	ErrCommitmentMismatch = errors.New("wire: SAS commitment mismatch")
	// ErrBadConfirm means the client sent something other than
	// CONFIRM after the SAS exchange.
	ErrBadConfirm = errors.New("wire: expected CONFIRM")
	// ErrSASRejected means the client sent REJECT after the SAS
	// exchange: the human declined.
	ErrSASRejected = errors.New("wire: SAS rejected by the client")
)

// ClientHandshake sends our version and verifies the server's. The
// client speaks first.
func ClientHandshake(rw io.ReadWriter) error {
	if err := writeLine(rw, Version); err != nil {
		return fmt.Errorf("wire: write version: %w", err)
	}
	if err := readExpect(rw, Version); err != nil {
		return fmt.Errorf("wire: read version: %w", err)
	}
	return nil
}

// ServerHandshake verifies the client's version and sends ours. The
// server reads first so the exchange also works over synchronous pipes
// in tests.
func ServerHandshake(rw io.ReadWriter) error {
	if err := readExpect(rw, Version); err != nil {
		return fmt.Errorf("wire: read version: %w", err)
	}
	if err := writeLine(rw, Version); err != nil {
		return fmt.Errorf("wire: write version: %w", err)
	}
	return nil
}

// ForwardLine returns the control-stream forward declaration for the
// given targets: "FWD host:port,host:port".
func ForwardLine(targets []string) string {
	return "FWD " + strings.Join(targets, ",")
}

// WriteForwardLine declares the session's forward targets.
func WriteForwardLine(w io.Writer, targets []string) error {
	return writeLine(w, ForwardLine(targets))
}

// ReadForwardLine reads and parses the client's forward declaration.
// It returns the declared targets; ErrEmptyForward if the list is
// empty.
func ReadForwardLine(r io.Reader) ([]string, error) {
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	rest, ok := strings.CutPrefix(line, "FWD ")
	if !ok {
		return nil, fmt.Errorf("wire: expected FWD line, got %q", line)
	}
	targets := strings.Split(rest, ",")
	for _, target := range targets {
		if target == "" {
			return nil, ErrEmptyForward
		}
	}
	if len(targets) == 0 {
		return nil, ErrEmptyForward
	}
	return targets, nil
}

// WriteCommitment sends the client's 32-byte SAS key commitment.
func WriteCommitment(w io.Writer, c [sas.CommitmentSize]byte) error {
	_, err := w.Write(c[:])
	return err
}

// ReadCommitment reads the client's 32-byte SAS key commitment.
func ReadCommitment(r io.Reader) ([sas.CommitmentSize]byte, error) {
	var c [sas.CommitmentSize]byte
	_, err := io.ReadFull(r, c[:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = ErrPeerClosed
		}
		return c, err
	}
	return c, nil
}

// WritePub sends a 32-byte X25519 public key.
func WritePub(w io.Writer, pub [sas.PublicKeySize]byte) error {
	_, err := w.Write(pub[:])
	return err
}

// ReadPub reads a 32-byte X25519 public key.
func ReadPub(r io.Reader) ([sas.PublicKeySize]byte, error) {
	var pub [sas.PublicKeySize]byte
	_, err := io.ReadFull(r, pub[:])
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = ErrPeerClosed
		}
		return pub, err
	}
	return pub, nil
}

// WriteConfirm sends the SAS confirmation, committing the session.
func WriteConfirm(w io.Writer) error {
	return writeLine(w, ConfirmLine)
}

// WriteReject declines the SAS, aborting the session.
func WriteReject(w io.Writer) error {
	return writeLine(w, RejectLine)
}

// ReadConfirm waits for the client's CONFIRM line. A REJECT line maps
// to ErrSASRejected; anything else is ErrBadConfirm.
func ReadConfirm(r io.Reader) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	switch line {
	case ConfirmLine:
		return nil
	case RejectLine:
		return ErrSASRejected
	default:
		return fmt.Errorf("%w: got %q", ErrBadConfirm, line)
	}
}

// WriteDataForward writes a data stream's target declaration.
func WriteDataForward(w io.Writer, target string) error {
	return writeLine(w, "FWD "+target)
}

// ReadDataForward reads a data stream's target declaration. The raw
// line is returned alongside for logging; callers validate membership
// in the session's forward set.
func ReadDataForward(r io.Reader) (target string, err error) {
	line, err := readLine(r)
	if err != nil {
		return "", err
	}
	target, ok := strings.CutPrefix(line, "FWD ")
	if !ok || target == "" {
		return "", fmt.Errorf("wire: expected FWD line, got %q", line)
	}
	return target, nil
}

// WriteDataOK acknowledges a data stream's target dial.
func WriteDataOK(w io.Writer) error {
	return writeLine(w, "OK")
}

// WriteDataErr rejects a data stream with a human-readable reason.
func WriteDataErr(w io.Writer, msg string) error {
	return writeLine(w, "ERR "+msg)
}

// ReadDataReply reads the server's data-stream reply: nil error on OK,
// a descriptive error on ERR.
func ReadDataReply(r io.Reader) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if line == "OK" {
		return nil
	}
	if msg, ok := strings.CutPrefix(line, "ERR "); ok {
		return fmt.Errorf("wire: server: %s", msg)
	}
	return fmt.Errorf("wire: expected OK or ERR, got %q", line)
}

func writeLine(w io.Writer, s string) error {
	_, err := io.WriteString(w, s+"\n")
	return err
}

// readExpect reads one line and requires it to equal want, mapping a
// mismatch to ErrVersionMismatch.
func readExpect(r io.Reader, want string) error {
	return readExpectErr(r, want, ErrVersionMismatch)
}

func readExpectErr(r io.Reader, want string, mismatch error) error {
	line, err := readLine(r)
	if err != nil {
		return err
	}
	if line != want {
		return fmt.Errorf("%w: got %q", mismatch, line)
	}
	return nil
}

// readLine reads one newline-terminated line one byte at a time so no
// bytes past the newline are ever buffered away from the caller:
// everything after the protocol framing is raw tunneled traffic that
// must not be swallowed by a read-ahead buffer.
func readLine(r io.Reader) (string, error) {
	line := make([]byte, 0, 64)
	b := make([]byte, 1)
	for {
		_, err := r.Read(b)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return "", ErrPeerClosed
			}
			return "", err
		}
		if b[0] == '\n' {
			return string(line), nil
		}
		line = append(line, b[0])
		if len(line) > maxLineLen {
			return "", fmt.Errorf("%w (limit %d)", ErrLineTooLong, maxLineLen)
		}
	}
}
