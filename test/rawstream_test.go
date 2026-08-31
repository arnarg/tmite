package test

import (
	"context"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/netaddr"
	"github.com/tmc/go-iroh/relay"
)

// TestRawStreamHalfClose checks whether bytes written right before
// Stream.Close() (FIN) survive to the peer.
func TestRawStreamHalfClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	var aSeed, bSeed [key.SeedSize]byte
	aSeed[0], bSeed[1] = 1, 2
	a, err := iroh.Bind(ctx,
		iroh.WithSecretKey(key.NewSecretKey(aSeed)),
		iroh.WithALPNs("x/1"),
		iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
		iroh.WithRelayMode(relay.ModeDisabled()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Shutdown(context.Background())
	b, err := iroh.Bind(ctx,
		iroh.WithSecretKey(key.NewSecretKey(bSeed)),
		iroh.WithALPNs("x/1"),
		iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
		iroh.WithRelayMode(relay.ModeDisabled()),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Shutdown(context.Background())

	stages := make(chan string, 8)
	go func() {
		conn, err := b.Accept(ctx)
		if err != nil {
			stages <- "accept: " + err.Error()
			return
		}
		stages <- "accepted"
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			stages <- "accept stream: " + err.Error()
			return
		}
		stages <- "stream accepted"
		data, err := io.ReadAll(stream)
		if err != nil {
			stages <- "readall: " + err.Error()
			return
		}
		conn.CloseWithError(0, "")
		stages <- "data: " + string(data)
	}()

	addr := netaddr.NewEndpointAddr(b.ID(),
		netaddr.IPAddr{Addr: netip.MustParseAddrPort(b.LocalAddr().String())})
	conn, err := a.Connect(ctx, addr, "x/1")
	if err != nil {
		t.Fatal(err)
	}
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Exercise both the plain Write path and the io.Copy (ReadFrom) path.
	if _, err := stream.Write([]byte("plain\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(stream, strings.NewReader("copied\n")); err != nil {
		t.Fatal(err)
	}
	if err := stream.Close(); err != nil {
		t.Fatal(err)
	}

	select {
	case <-time.After(2 * time.Second):
		t.Log("stage check after 2s")
	} // let the connection establish
	deadline := time.After(5 * time.Second)
	for {
		select {
		case s := <-stages:
			t.Logf("stage: %s", s)
			if strings.HasPrefix(s, "data: ") {
				if s != "data: plain\ncopied\n" {
					t.Fatalf("server received %q", s)
				}
				return
			}
			if strings.Contains(s, ":") && !strings.HasPrefix(s, "data") {
				t.Fatalf("server error at %s", s)
			}
		case <-deadline:
			t.Fatal("server did not finish")
		}
	}
}
