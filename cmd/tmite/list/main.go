// Package list implements the tmite list command: snapshot of the
// daemon's sessions.
package list

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/urfave/cli/v3"

	"github.com/arnarg/tmite/internal/daemon"
)

// Exit codes.
const (
	ExitOK    = 0
	ExitFatal = 1
)

var Command = &cli.Command{
	Name:  "list",
	Usage: "List the daemon's sessions",
	Flags: []cli.Flag{
		&cli.StringFlag{
			Name:    "socket",
			Value:   daemon.DefaultSocket,
			Usage:   "daemon socket path",
			Sources: cli.EnvVars("TMITE_SOCKET"),
		},
		&cli.BoolFlag{
			Name:    "paths",
			Usage:   "show each connected session's iroh network paths (direct vs relayed, RTT)",
			Sources: cli.EnvVars("TMITE_PATHS"),
		},
		&cli.BoolFlag{
			Name:    "all",
			Aliases: []string{"A"},
			Usage:   "include done sessions",
			Sources: cli.EnvVars("TMITE_ALL"),
		},
	},
	Action: runList,
}

func runList(ctx context.Context, cmd *cli.Command) error {
	cl, err := daemon.Dial(ctx, cmd.String("socket"))
	if err != nil {
		return cli.Exit(err.Error(), ExitFatal)
	}
	defer cl.Close()

	if err := cl.Send(daemon.Request{Cmd: "list", Paths: cmd.Bool("paths"), All: cmd.Bool("all")}); err != nil {
		return cli.Exit("sending list: "+err.Error(), ExitFatal)
	}
	resp, _, err := cl.Recv()
	if err != nil {
		return cli.Exit("daemon closed connection: "+err.Error(), ExitFatal)
	}
	if !resp.OK {
		return cli.Exit(resp.Error, ExitFatal)
	}
	if len(resp.List) == 0 {
		fmt.Fprintln(os.Stderr, "no sessions")
		return nil
	}
	fmt.Printf("%-10s %-11s %s\n", "ID", "STATE", "AGE")
	for _, s := range resp.List {
		fmt.Printf("%-10s %-11s %ds\n", s.ID, s.State, s.AgeSecs)
		for _, p := range s.Paths {
			fmt.Printf("           %s\n", pathLine(p))
		}
	}
	return nil
}

// pathLine renders one connection path for --paths output.
func pathLine(p daemon.PathInfo) string {
	kind := "direct"
	if p.Relayed {
		kind = "relayed"
	}
	s := kind + " " + p.Addr
	if p.RTTSecs > 0 {
		s += " rtt=" + (time.Duration(p.RTTSecs)).Round(time.Millisecond).String()
	}
	if p.Selected {
		s += " [active]"
	}
	return s
}
