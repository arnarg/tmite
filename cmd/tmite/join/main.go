// Package join implements the tmite join command: the client side.
// It connects to a pairing session, verifies the SAS with the human,
// and forwards local ports through the tunnel.
package join

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"strings"

	"github.com/urfave/cli/v3"

	"github.com/arnarg/tmite/internal/code"
	"github.com/arnarg/tmite/internal/discovery"
	"github.com/arnarg/tmite/internal/forward"
	"github.com/arnarg/tmite/internal/session"
)

// Exit codes.
const (
	ExitOK          = 0
	ExitFatal       = 1
	ExitTimeout     = 2
	ExitSASMismatch = 3
	ExitRejected    = 4
)

var Command = &cli.Command{
	Name:      "join",
	Usage:     "Join a pairing session and forward local ports through the tunnel",
	ArgsUsage: "<word1> <word2> <word3> <word4> <word5>",
	Flags: []cli.Flag{
		&cli.StringSliceFlag{
			Name:    "fwd",
			Usage:   "port forward [bind_addr:]port:host:hostport (repeatable, at least one required)",
			Sources: cli.EnvVars("TMITE_FWD"),
		},
		&cli.DurationFlag{
			Name:    "wait",
			Value:   session.DefaultClientWait,
			Usage:   "how long to keep retrying the dial",
			Sources: cli.EnvVars("TMITE_WAIT"),
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
			Name:    "dns-origin",
			Usage:   "custom DNS discovery origin for TXT resolution (default: dns.iroh.link)",
			Sources: cli.EnvVars("TMITE_DNS_ORIGIN"),
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
	Action: runJoin,
}

// askpassEnv names the GUI helper invoked for the pairing code when no
// words are given as arguments (SSH_ASKPASS-style).
const askpassEnv = "TMITE_ASKPASS"

func runJoin(ctx context.Context, cmd *cli.Command) error {
	words, err := resolveWords(cmd.Args().Slice())
	if err != nil {
		return cli.Exit(err.Error(), ExitFatal)
	}
	c, err := code.Decode(words)
	if err != nil {
		return cli.Exit(fmt.Sprintf("invalid pairing code: %v", err), ExitFatal)
	}

	fwdFlags := cmd.StringSlice("fwd")
	if len(fwdFlags) == 0 {
		return cli.Exit("no forwards given; pass at least one --fwd", ExitFatal)
	}
	forwards := make([]forward.Spec, 0, len(fwdFlags))
	for _, s := range fwdFlags {
		f, err := forward.Parse(s)
		if err != nil {
			return cli.Exit(fmt.Sprintf("bad --fwd %q: %v", s, err), ExitFatal)
		}
		forwards = append(forwards, f)
	}

	var bind netip.AddrPort
	if s := cmd.String("bind"); s != "" {
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

	err = session.Connect(ctx, session.ClientConfig{
		Code:     c,
		Forwards: forwards,
		Wait:     cmd.Duration("wait"),
		Disc: discovery.Config{
			Relays:    cmd.StringSlice("relay"),
			PkarrURL:  cmd.String("pkarr"),
			DNSOrigin: cmd.String("dns-origin"),
		},
		Bind:          bind,
		ExternalAddrs: ext,
		SASConfirmer:  confirmSAS,
		Logf: func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, format+"\n", args...)
		},
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, session.ErrTimeout):
		return cli.Exit(err.Error(), ExitTimeout)
	case errors.Is(err, session.ErrSASMismatch):
		return cli.Exit("SAS mismatch", ExitSASMismatch)
	case errors.Is(err, session.ErrRejected):
		return cli.Exit(err.Error(), ExitRejected)
	default:
		return cli.Exit(err.Error(), ExitFatal)
	}
}

// confirmSAS displays the SAS and asks the human to compare it against
// the server's console. The answer is read as a single line from
// stdin; only "y"/"Y" accepts, anything else (including EOF) rejects.
func confirmSAS(sas string) bool {
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Fprintf(os.Stderr, "  SAS: \033[1m%s\033[0m\n\n", sas)
	fmt.Fprintf(os.Stderr, "Does this match the server's console? [y/N] ")
	var answer string
	fmt.Fscanln(os.Stdin, &answer)
	return strings.EqualFold(strings.TrimSpace(answer), "y")
}

// resolveWords returns the pairing words. Five positional arguments win;
// with no arguments, the helper named by TMITE_ASKPASS is invoked and
// its stdout is split into words. Anything else is an error.
func resolveWords(args []string) ([]string, error) {
	switch {
	case len(args) == code.WordCount:
		return args, nil
	case len(args) == 0:
		helper := os.Getenv(askpassEnv)
		if helper == "" {
			return nil, fmt.Errorf("no pairing code given; pass %d words as arguments or set %s to a helper program", code.WordCount, askpassEnv)
		}
		return askpass(helper)
	default:
		return nil, fmt.Errorf("expected %d words, got %d", code.WordCount, len(args))
	}
}

// askpass runs the GUI helper and reads the code from its stdout. The
// helper is invoked with no arguments; stderr is passed through so the
// user sees helper errors (cancelled dialog, etc.).
func askpass(helper string) ([]string, error) {
	if _, err := exec.LookPath(helper); err != nil {
		return nil, fmt.Errorf("%s: helper not found: %w", askpassEnv, err)
	}
	cmd := exec.Command(helper)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s: %s failed: %w", askpassEnv, helper, err)
	}
	words := strings.Fields(string(out))
	if len(words) != code.WordCount {
		return nil, fmt.Errorf("%s: %s printed %d words, want %d", askpassEnv, helper, len(words), code.WordCount)
	}
	return words, nil
}
