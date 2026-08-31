// Package cancel implements the tmite cancel command: end a session
// that has not connected yet.
package cancel

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"github.com/arnarg/tmite/internal/daemon"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFatal = 1
)

var Command = &cli.Command{
	Name:      "cancel",
	Usage:     "Cancel a session that has not connected yet",
	ArgsUsage: "<id>",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "socket",
			Value:   daemon.DefaultSocket,
			Usage:   "daemon socket path",
			Sources: cli.EnvVars("TMITE_SOCKET"),
		},
	},
	Action: runCancel,
}

func runCancel(ctx context.Context, cmd *cli.Command) error {
	args := cmd.Args().Slice()
	if len(args) != 1 {
		return cli.Exit("want exactly one session id", ExitFatal)
	}

	cl, err := daemon.Dial(ctx, cmd.String("socket"))
	if err != nil {
		return cli.Exit(err.Error(), ExitFatal)
	}
	defer cl.Close()

	if err := cl.Send(daemon.Request{Cmd: "cancel", ID: args[0]}); err != nil {
		return cli.Exit("sending cancel: "+err.Error(), ExitFatal)
	}
	resp, _, err := cl.Recv()
	if err != nil {
		return cli.Exit("daemon closed connection: "+err.Error(), ExitFatal)
	}
	if !resp.OK {
		return cli.Exit(resp.Error, ExitFatal)
	}
	fmt.Println("cancelled")
	return nil
}
