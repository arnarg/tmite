#!/usr/bin/env bash
# Manual smoke script (design §14.4).
#
# Run the daemon on a box, invite in one SSH pane, pair on a laptop, allow,
# connect, then `ssh -p 2222 localhost` and `exit` — the shell must return
# promptly (the half-close check, by hand). Open a second SSH session over the
# same tunnel concurrently to exercise the multiplexed path.
#
# Usage:
#   ./docs/smoke.sh server          # on the server: starts the daemon
#   ./docs/smoke.sh invite          # on the server: prints a pairing code
#   ./docs/smoke.sh pair CODE       # on the laptop: pairs
#   ./docs/smoke.sh allow           # on the server: grants localhost:22
#   ./docs/smoke.sh connect         # on the laptop: starts the tunnel
#   ./docs/smoke.sh test            # on the laptop: ssh over the tunnel
set -euo pipefail

DATA="--data-dir ./data"
SOCK="--socket-path ./run/daemon.sock"
SRV_ARGS="$DATA $SOCK"

case "${1:-}" in
  server)
    mkdir -p data run
    tmite daemon $SRV_ARGS
    ;;
  invite)
    tmite peer invite $SRV_ARGS --name laptop
    ;;
  pair)
    # Run on the laptop with the code from `invite`.
    tmite pair "${2:?usage: smoke.sh pair CODE}"
    ;;
  allow)
    tmite peer allow $SRV_ARGS laptop localhost:22
    tmite status $SRV_ARGS
    ;;
  connect)
    tmite connect laptop --fwd 2222:localhost:22
    ;;
  test)
    ssh -o StrictHostKeyChecking=no -p 2222 localhost 'echo tunnel-works; exit'
    echo "half-close OK (shell returned promptly)"
    ;;
  *)
    echo "usage: $0 {server|invite|pair CODE|allow|connect|test}" >&2
    exit 1
    ;;
esac
