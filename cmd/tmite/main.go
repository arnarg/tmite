package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/urfave/cli/v3"

	"github.com/arnarg/tmite/cmd/tmite/cancel"
	"github.com/arnarg/tmite/cmd/tmite/code"
	"github.com/arnarg/tmite/cmd/tmite/daemon"
	"github.com/arnarg/tmite/cmd/tmite/join"
	"github.com/arnarg/tmite/cmd/tmite/list"
)

var version = "unknown"

func main() {
	app := &cli.Command{
		Name:    "tmite",
		Version: version,
		Usage:   "One-shot TCP tunnels to firewalled hosts over iroh",
		Commands: []*cli.Command{
			daemon.Command,
			code.Command,
			join.Command,
			list.Command,
			cancel.Command,
		},
	}

	ctx, cancel := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer cancel()

	if err := app.Run(ctx, os.Args); err != nil {
		cli.HandleExitCoder(err)
	}
}
