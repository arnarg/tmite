// Package code implements the tmite code command: ask the daemon for
// a one-shot session, print the words, and hang until the tunnel is
// established (or the session ends without one).
package code

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/arnarg/tmite/internal/daemon"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitFatal       = 1
	ExitNoSession   = 2
	ExitInterrupted = 130 // 128 + SIGINT
)

var Command = &cli.Command{
	Name:  "code",
	Usage: "Create a one-shot session and print its pairing words",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "socket",
			Value:   daemon.DefaultSocket,
			Usage:   "daemon socket path",
			Sources: cli.EnvVars("TMITE_SOCKET"),
		},
	},
	Action: runCode,
}

func runCode(ctx context.Context, cmd *cli.Command) error {
	cl, err := daemon.Dial(ctx, cmd.String("socket"))
	if err != nil {
		return cli.Exit(err.Error(), ExitFatal)
	}
	defer cl.Close()

	if err := cl.Send(daemon.Request{Cmd: "code"}); err != nil {
		return cli.Exit("sending code: "+err.Error(), ExitFatal)
	}
	resp, _, err := cl.Recv()
	if err != nil {
		return cli.Exit("daemon closed connection: "+err.Error(), ExitFatal)
	}
	if !resp.OK {
		return cli.Exit(resp.Error, ExitFatal)
	}

	// The words are the payload; everything else is diagnostics.
	fmt.Println(strings.Join(resp.Words, " "))
	info := fmt.Sprintf("session %s", resp.ID)
	if resp.Expires != "" {
		info += ", expires " + resp.Expires
	}
	fmt.Fprintf(os.Stderr, "%s\nwaiting for client (ctrl-C cancels)…\n", info)

	// Events stream in on the background reader; ctx cancellation
	// (SIGINT/SIGTERM) cancels the session over the same socket.
	type msg struct {
		resp  *daemon.Response
		event *daemon.Event
		err   error
	}
	msgs := make(chan msg, 1)
	go func() {
		for {
			r, e, err := cl.Recv()
			msgs <- msg{r, e, err}
			if err != nil {
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return interrupt(cl, resp.ID)
		case m := <-msgs:
			if m.err != nil {
				return cli.Exit("daemon closed connection: "+m.err.Error(), ExitFatal)
			}
			if m.resp != nil {
				if !m.resp.OK {
					return cli.Exit(m.resp.Error, ExitFatal)
				}
				continue
			}
			switch m.event.Event {
			case "waiting":
				// Already reported above.
			case "verifying":
				fmt.Fprintf(os.Stderr, "\n  SAS code (client should see the same):\n")
				fmt.Fprintf(os.Stderr, "                    \033[1m%s\033[0m\n\n", m.event.SAS)
			case "connected":
				fmt.Fprintln(os.Stderr, "tunnel established")
				return nil
			case "done":
				return nil
			case "expired":
				return cli.Exit("no client connected before the session expired", ExitNoSession)
			case "cancelled":
				return cli.Exit("session cancelled", ExitNoSession)
			case "failed":
				return cli.Exit("session failed", ExitFatal)
			default:
				fmt.Fprintf(os.Stderr, "session %s\n", m.event.Event)
			}
		}
	}
}

// interrupt cancels the session over the existing socket and exits.
// The daemon only cancels sessions that have not connected yet
// (generating, waiting, or verifying). A second signal aborts without
// waiting.
func interrupt(cl *daemon.Client, id string) error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		os.Exit(ExitInterrupted)
	}()

	fmt.Fprintln(os.Stderr, "cancelling session…")
	if err := cl.Send(daemon.Request{Cmd: "cancel", ID: id}); err != nil {
		return cli.Exit("could not cancel session (it keeps running on the daemon): "+err.Error(), ExitInterrupted)
	}
	// The cancel response races the event reader; either way the
	// daemon processes the request. Buffered socket data survives our
	// close.
	return cli.Exit("cancelled", ExitInterrupted)
}
