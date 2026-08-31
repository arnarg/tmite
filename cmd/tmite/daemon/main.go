// Package daemon implements the tmite daemon command: a persistent
// process that owns pairing sessions behind a Unix socket.
package daemon

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"github.com/urfave/cli/v3"

	srv "github.com/arnarg/tmite/internal/daemon"
	"github.com/arnarg/tmite/internal/discovery"
	"github.com/arnarg/tmite/internal/session"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFatal = 1
)

var Command = &cli.Command{
	Name:  "daemon",
	Usage: "Run the tmite daemon",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "listen",
			Value:   srv.DefaultSocket,
			Usage:   "Unix socket to listen on",
			Sources: cli.EnvVars("TMITE_SOCKET"),
		},
		&cli.StringSliceFlag{
			Name:    "allow-forward",
			Usage:   "glob pattern for allowed forward targets, matched against host:port (repeatable, at least one required; e.g. \"localhost:*\")",
			Sources: cli.EnvVars("TMITE_ALLOW_FORWARD"),
		},
		&cli.DurationFlag{
			Name:    "session-timeout",
			Value:   srv.DefaultSessionTimeout,
			Usage:   "session lifetime without a client",
			Sources: cli.EnvVars("TMITE_SESSION_TIMEOUT"),
		},
		&cli.StringSliceFlag{
			Name:    "relay",
			Usage:   "custom relay URL (repeatable; default: n0 production relays)",
			Sources: cli.EnvVars("TMITE_RELAY"),
		},
		&cli.StringFlag{
			Name:    "pkarr",
			Usage:   "custom pkarr HTTP relay URL (default: n0 production pkarr relay)",
			Sources: cli.EnvVars("TMITE_PKARR"),
		},
		&cli.StringFlag{
			Name:    "bind",
			Usage:   "local UDP address to bind (ip:port or :port; default: OS-assigned port on ::)",
			Sources: cli.EnvVars("TMITE_BIND"),
		},
		&cli.StringSliceFlag{
			Name:    "external-addr",
			Usage:   "public ip:port to advertise for NAT traversal (repeatable; default: discovered via net report)",
			Sources: cli.EnvVars("TMITE_EXTERNAL_ADDR"),
		},
	},
	Action: runDaemon,
}

func runDaemon(ctx context.Context, cmd *cli.Command) error {
	allow := cmd.StringSlice("allow-forward")
	if len(allow) == 0 {
		return cli.Exit("no forward allowlist; pass at least one --allow-forward (e.g. --allow-forward='localhost:*')", ExitFatal)
	}

	var bind netip.AddrPort
	if s := cmd.String("bind"); s != "" {
		var err error
		bind, err = session.ParseAddrPort(s)
		if err != nil {
			return cli.Exit(fmt.Sprintf("bad --bind %q: %v", s, err), ExitFatal)
		}
	}
	var ext []netip.AddrPort
	for _, s := range cmd.StringSlice("external-addr") {
		a, err := session.ParseAddrPort(s)
		if err != nil {
			return cli.Exit(fmt.Sprintf("bad --external-addr %q: %v", s, err), ExitFatal)
		}
		ext = append(ext, a)
	}

	d := srv.New(srv.Config{
		SocketPath:     cmd.String("listen"),
		AllowForward:   allow,
		SessionTimeout: cmd.Duration("session-timeout"),
		Disc: discovery.Config{
			Relays:   cmd.StringSlice("relay"),
			PkarrURL: cmd.String("pkarr"),
		},
		Bind:          bind,
		ExternalAddrs: ext,
	})
	if d == nil {
		return cli.Exit("no forward allowlist; pass at least one --allow-forward", ExitFatal)
	}
	fmt.Fprintf(os.Stderr, "tmite daemon on %s (allow-forward %v, session timeout %s)\n",
		cmd.String("listen"), allow, cmd.Duration("session-timeout"))
	if err := d.Run(ctx); err != nil {
		return cli.Exit(err.Error(), ExitFatal)
	}
	return nil
}
