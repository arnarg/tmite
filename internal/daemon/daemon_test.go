package daemon

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tmc/go-iroh/dns"
	"github.com/tmc/go-iroh/iroh"
	"github.com/tmc/go-iroh/key"
	"github.com/tmc/go-iroh/relay"

	"github.com/arnarg/tmite/internal/discovery"
	"github.com/arnarg/tmite/internal/forward"
	"github.com/arnarg/tmite/internal/session"
)

// startTestDaemon runs a daemon on a temp socket whose sessions bind
// loopback endpoints with relays disabled and a no-op publisher, so
// the protocol tests never touch the network.
func startTestDaemon(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	d := New(Config{
		SocketPath:     filepath.Join(t.TempDir(), "daemon.sock"),
		AllowForward:   forward.Allowlist{"*:*"},
		SessionTimeout: time.Minute,
		SessionTune: func(c *session.ServerConfig) {
			c.Publisher = func(_ discovery.Config, _ key.SecretKey) (iroh.AddressPublisher, error) {
				return iroh.AddressPublisherFunc(func(dns.EndpointData) {}), nil
			}
			c.ExtraOptions = []iroh.Option{
				iroh.WithBindAddr(netip.MustParseAddrPort("127.0.0.1:0")),
				iroh.WithRelayMode(relay.ModeDisabled()),
			}
		},
	})
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("daemon run: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	})

	socket := d.cfg.SocketPath
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(socket); err == nil {
			return socket
		}
		if time.Now().After(deadline) {
			t.Fatal("socket never appeared")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// call opens a fresh connection, sends one command, and reads one
// response (code streams events afterwards; callers wanting those use
// Dial directly).
func call(t *testing.T, socket string, req Request) *Response {
	t.Helper()
	cl, err := Dial(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if err := cl.Send(req); err != nil {
		t.Fatal(err)
	}
	resp, _, err := cl.Recv()
	if err != nil {
		t.Fatalf("recv: %v", err)
	}
	return resp
}

func TestCodeListCancel(t *testing.T) {
	socket := startTestDaemon(t)

	resp := call(t, socket, Request{Cmd: "code"})
	if !resp.OK {
		t.Fatalf("code: %s", resp.Error)
	}
	if len(resp.Words) != 5 {
		t.Fatalf("code words = %v", resp.Words)
	}
	if resp.ID == "" || resp.Expires == "" {
		t.Fatalf("code response missing id/expires: %+v", resp)
	}

	list := call(t, socket, Request{Cmd: "list"})
	if !list.OK || len(list.List) != 1 {
		t.Fatalf("list = %+v", list)
	}
	if got := list.List[0]; got.ID != resp.ID || got.State != "waiting" {
		t.Fatalf("list entry = %+v", got)
	}

	if r := call(t, socket, Request{Cmd: "cancel", ID: resp.ID}); !r.OK {
		t.Fatalf("cancel: %s", r.Error)
	}
	// Give the session goroutine a beat to reach the terminal state.
	deadline := time.Now().Add(5 * time.Second)
	for {
		list = call(t, socket, Request{Cmd: "list", All: true})
		if list.OK && len(list.List) == 1 && list.List[0].State == "cancelled" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("session never cancelled: %+v", list.List)
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Default list hides terminal sessions.
	active := call(t, socket, Request{Cmd: "list"})
	if !active.OK || len(active.List) != 0 {
		t.Fatalf("default list after cancel = %+v", active)
	}

	again := call(t, socket, Request{Cmd: "cancel", ID: resp.ID})
	if again.OK || again.Error == "" {
		t.Fatalf("cancel of terminal session = %+v, want error", again)
	}
}

func TestNewRequiresAllowlist(t *testing.T) {
	if d := New(Config{}); d != nil {
		t.Fatal("New without AllowForward must return nil")
	}
}

func TestCancelUnknown(t *testing.T) {
	socket := startTestDaemon(t)
	r := call(t, socket, Request{Cmd: "cancel", ID: "nope"})
	if r.OK || r.Error != "session not found" {
		t.Fatalf("cancel unknown = %+v", r)
	}
}

func TestBadRequests(t *testing.T) {
	socket := startTestDaemon(t)

	cl, err := Dial(context.Background(), socket)
	if err != nil {
		t.Fatal(err)
	}
	defer cl.Close()
	if _, err := cl.conn.Write([]byte("this is not json\n")); err != nil {
		t.Fatal(err)
	}
	resp, _, err := cl.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatalf("garbage line accepted: %+v", resp)
	}

	if err := cl.Send(Request{Cmd: "frobnicate"}); err != nil {
		t.Fatal(err)
	}
	resp, _, err = cl.Recv()
	if err != nil {
		t.Fatal(err)
	}
	if resp.OK {
		t.Fatalf("unknown command accepted: %+v", resp)
	}
}

func TestEmptyList(t *testing.T) {
	socket := startTestDaemon(t)
	r := call(t, socket, Request{Cmd: "list"})
	if !r.OK || len(r.List) != 0 {
		t.Fatalf("empty list = %+v", r)
	}
}
