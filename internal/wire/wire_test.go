package wire

import (
	"bytes"
	"errors"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/arnarg/tmite/internal/sas"
)

// bufRW is an in-memory ReadWriter with separate read and write
// sides: any read-ahead buffering bug in the handshake becomes visible
// because bytes past the framing stay available to the caller.
type bufRW struct {
	r bytes.Buffer
	w bytes.Buffer
}

func (rw *bufRW) Read(p []byte) (int, error)  { return rw.r.Read(p) }
func (rw *bufRW) Write(p []byte) (int, error) { return rw.w.Write(p) }

func TestHandshakeBothSides(t *testing.T) {
	c, s := net.Pipe()
	errc := make(chan error, 2)
	go func() { errc <- ServerHandshake(s) }()
	errc <- ClientHandshake(c)
	for range 2 {
		if err := <-errc; err != nil {
			t.Fatalf("handshake: %v", err)
		}
	}
}

func TestHandshakeVersionMismatch(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString("TMITE0\n")
	err := ServerHandshake(rw)
	if !errors.Is(err, ErrVersionMismatch) {
		t.Fatalf("err = %v, want ErrVersionMismatch", err)
	}
}

func TestHandshakeVersionMismatchLongLine(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString(strings.Repeat("X", maxLineLen+1) + "\n")
	err := ServerHandshake(rw)
	if !errors.Is(err, ErrLineTooLong) {
		t.Fatalf("err = %v, want ErrLineTooLong", err)
	}
}

func TestHandshakePeerClosed(t *testing.T) {
	rw := &bufRW{} // empty: immediate EOF
	err := ServerHandshake(rw)
	if !errors.Is(err, ErrPeerClosed) {
		t.Fatalf("err = %v, want ErrPeerClosed", err)
	}
}

func TestHandshakePeerClosedMidLine(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString("TMI") // EOF before newline
	err := ServerHandshake(rw)
	if !errors.Is(err, ErrPeerClosed) {
		t.Fatalf("err = %v, want ErrPeerClosed", err)
	}
}

// TestHandshakeNoOverread is the critical property: tunneled bytes
// that arrive pipelined behind the version line must survive the
// handshake.
func TestHandshakeNoOverread(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString(Version + "\n" + "SSH-2.0-laptop\n")
	if err := ServerHandshake(rw); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if got := rw.w.String(); got != Version+"\n" {
		t.Fatalf("server wrote %q, want its version", got)
	}
	rest, err := io.ReadAll(rw)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "SSH-2.0-laptop\n" {
		t.Fatalf("bytes after version = %q, want SSH banner", rest)
	}
}

func TestForwardLineRoundTrip(t *testing.T) {
	targets := []string{"localhost:22", "example.com:5432"}
	rw := &bufRW{}
	if err := WriteForwardLine(rw, targets); err != nil {
		t.Fatal(err)
	}
	got, err := ReadForwardLine(&rw.w)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != strings.Join(targets, ",") {
		t.Fatalf("targets = %v, want %v", got, targets)
	}
}

func TestForwardLineEmpty(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString("FWD \n")
	if _, err := ReadForwardLine(rw); !errors.Is(err, ErrEmptyForward) {
		t.Fatalf("err = %v, want ErrEmptyForward", err)
	}
}

func TestForwardLineMissing(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString("HELLO\n")
	if _, err := ReadForwardLine(rw); err == nil {
		t.Fatal("expected error for non-FWD line")
	}
}

func TestCommitmentAndPubRoundTrip(t *testing.T) {
	kp, err := sas.Generate()
	if err != nil {
		t.Fatal(err)
	}
	rw := &bufRW{}
	if err := WriteCommitment(rw, sas.Commitment(kp.Public())); err != nil {
		t.Fatal(err)
	}
	if err := WritePub(rw, kp.Public()); err != nil {
		t.Fatal(err)
	}
	c, err := ReadCommitment(&rw.w)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ReadPub(&rw.w)
	if err != nil {
		t.Fatal(err)
	}
	if c != sas.Commitment(pub) {
		t.Fatal("commitment does not match revealed key")
	}
}

func TestConfirmRoundTrip(t *testing.T) {
	rw := &bufRW{}
	if err := WriteConfirm(rw); err != nil {
		t.Fatal(err)
	}
	if err := ReadConfirm(&rw.w); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmRejectsOther(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString("BOGUS\n")
	if err := ReadConfirm(rw); !errors.Is(err, ErrBadConfirm) {
		t.Fatalf("err = %v, want ErrBadConfirm", err)
	}
}

func TestConfirmMapsReject(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString(RejectLine + "\n")
	if err := ReadConfirm(rw); !errors.Is(err, ErrSASRejected) {
		t.Fatalf("err = %v, want ErrSASRejected", err)
	}
}

func TestDataFramingRoundTrip(t *testing.T) {
	rw := &bufRW{}
	if err := WriteDataForward(rw, "localhost:22"); err != nil {
		t.Fatal(err)
	}
	target, err := ReadDataForward(&rw.w)
	if err != nil {
		t.Fatal(err)
	}
	if target != "localhost:22" {
		t.Fatalf("target = %q", target)
	}

	rw2 := &bufRW{}
	if err := WriteDataOK(rw2); err != nil {
		t.Fatal(err)
	}
	if err := ReadDataReply(&rw2.w); err != nil {
		t.Fatal(err)
	}

	rw3 := &bufRW{}
	if err := WriteDataErr(rw3, "connection refused"); err != nil {
		t.Fatal(err)
	}
	err = ReadDataReply(&rw3.w)
	if err == nil || !strings.Contains(err.Error(), "connection refused") {
		t.Fatalf("err = %v, want server reason", err)
	}
}

// TestDataFramingNoOverread: tunneled bytes pipelined behind the OK
// reply must survive.
func TestDataFramingNoOverread(t *testing.T) {
	rw := &bufRW{}
	rw.r.WriteString("OK\n" + "SSH-2.0-server\n")
	if err := ReadDataReply(rw); err != nil {
		t.Fatal(err)
	}
	rest, err := io.ReadAll(rw)
	if err != nil {
		t.Fatal(err)
	}
	if string(rest) != "SSH-2.0-server\n" {
		t.Fatalf("bytes after OK = %q, want SSH banner", rest)
	}
}
