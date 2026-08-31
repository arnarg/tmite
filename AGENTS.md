# AGENTS.md

Guidance for AI agents working in the tmite repository.

## What this is

`tmite` is a Go CLI that creates one-shot TCP tunnels to firewalled hosts over
[iroh](https://github.com/tmc/go-iroh) (P2P QUIC over relays / hole-punching).
A persistent daemon on the server side manages short-lived pairing sessions,
each keyed by a 5-word code from which both sides derive their ephemeral iroh
identities. A human compares a 6-digit SAS (Short Authentication String) to
gate the tunnel.

**`docs/design.md` is the authoritative spec.** It covers the wire protocol,
SAS commitment scheme, daemon NDJSON protocol, session state machine, security
model, and protocol constants. Read it before changing anything in
`internal/wire`, `internal/sas`, `internal/keys`, `internal/code`, or
`internal/session` — these implement that spec almost line-for-line, and
behavior changes must stay consistent with it (or update it).

## Commands

```sh
go build ./...          # build (module: github.com/arnarg/tmite, Go 1.26)
go test ./...           # all tests; unit tests are in-package *_test.go files
go test -race ./...     # race detector (session/daemon code is heavily concurrent)
go vet ./...            # lint; there is no other linter config in the repo
go test -fuzz=FuzzDecode -fuzztime=30s ./internal/code/   # fuzz the code decoder
go run ./cmd/tmite --help

# Nix (optional; plain Go toolchain works fine):
nix build               # builds via package.nix (gomod2nix, CGO_ENABLED=0)
nix run .#gomod2nix     # regenerate gomod2nix.toml AFTER changing go.mod deps
```

Gotcha: if you add or bump a dependency in `go.mod`, regenerate
`gomod2nix.toml` with `nix run .#gomod2nix` or `nix build` will fail with a
hash mismatch. Plain `go build`/`go test` do not need it.

## Layout

```
cmd/tmite/        CLI wiring (urfave/cli/v3); one subpackage per subcommand
                  (daemon, code, join, list, cancel), each exporting `Command`
internal/
  code/           5-word pairing code (5 random bytes + sha256 checksum byte,
                  mnemonicode)
  keys/           HKDF-SHA256 derivation of server/client iroh keys from a code
  sas/            6-digit SAS via X25519 + hash commitment (RFC 6189 style)
  wire/           stream framing: version line, FWD lines, SAS exchange,
                  CONFIRM/REJECT, data-stream FWD/OK/ERR
  session/        session lifecycle, both ends: Server (daemon side, goroutine
                  per session) and Client (Connect + local TCP listeners)
  daemon/         daemon Unix-socket server (NDJSON), its client, and the
                  Request/Response/Event wire types (proto.go)
  discovery/      iroh relay / pkarr / DNS-TXT config shared by both sides
  forward/        --fwd flag parsing and the daemon's forward-target allowlist
test/             external probing tests against go-iroh itself (not unit tests)
docs/design.md    the protocol spec
```

## Architecture in brief

- `tmite daemon` runs persistently, listening NDJSON on a Unix socket
  (default `/run/tmite/daemon`). `code` is a **subscription**, not a one-shot:
  the daemon replies with the words, then streams `event` lines on the same
  connection until the session connects or ends. Other commands multiplex on
  the same connection; the daemon serves `code` in its own goroutine and
  serializes writes with a per-connection mutex (`connWriter`).
- Each `code` request spawns one `session.Server` goroutine: fresh iroh
  endpoint with the key derived from the code, pkarr publish, accept exactly
  one connection (must present the derived client EndpointID), version + SAS
  handshake on the control stream, then forward data streams to allowlisted
  TCP targets.
- `tmite join` (client) derives both identities from the typed words, resolves
  the server via pkarr/DNS, retries the dial with backoff for `--wait`, runs
  the SAS handshake, and on CONFIRM opens one data stream per local TCP
  connection.
- The code *is* the identity: there is no key file or other shared state.
  Session IDs are random and unrelated to the code.

## Conventions

- **Comments explain *why*, not what.** Package docs and function comments
  carry the security reasoning (threat model, anti-grinding, fail-closed
  defaults). Preserve this style; do not strip "obvious-looking" rationale
  comments — they encode the design's threat analysis.
- **Sentinel errors** for everything a caller may branch on (e.g.
  `code.ErrChecksum`, `wire.ErrSASRejected`, `session.ErrTimeout`). Typed
  errors implement `Unwrap` so `errors.Is` works. `join` maps
  `session.ErrTimeout/ErrSASMismatch/ErrRejected` to distinct exit codes
  (2/3/4) — keep that mapping intact.
- **Fail closed**: nil `SASConfirmer` rejects, nil `OnSAS` skips, no
  `--allow-forward` means the daemon refuses to start (`daemon.New` returns
  nil), SAS timeout rejects, unknown wire lines abort.
- **Version coupling**: `keys.Salt` (`tmite/v1`), `wire.Version` (`TMITE1`),
  `wire.ALPN` (`tmite/1`), and the SAS domain tags must change together. If
  you change any derivation or handshake detail, bump all of them and update
  the constants table in `docs/design.md` §10.
- Config structs take zero-value defaults documented per field
  ("Zero uses DefaultX"); durations of 0 mean "use package default", except
  `ServerConfig.Timeout` where 0 means unbounded (the daemon always sets one).
- Test seams are explicit config hooks: `ServerConfig.Publisher`,
  `ServerConfig.ExtraOptions`, `ClientConfig.Lookup`, `ClientConfig.OnSAS`,
  `ClientConfig.SASConfirmer`, `daemon.Config.SessionTune`. Use these to bind
  loopback endpoints, disable relays, and substitute in-memory publishers
  instead of adding test-only branches to production code. See
  `internal/daemon/daemon_test.go:startTestDaemon` for the canonical pattern.

## Testing

- Unit tests are standard `testing` package tests next to the code;
  `internal/code` also has fuzz tests (`FuzzDecode`, `FuzzEncodeBytes`).
- Tests must not touch the real network: bind `127.0.0.1:0`, use
  `relay.ModeDisabled()`, and a no-op `iroh.AddressPublisherFunc`.
- `test/` (package `test`) contains standalone behavior probes against
  go-iroh semantics (e.g. whether bytes written before `Stream.Close()`
  survive half-close). These document assumptions the forwarding layer relies
  on; keep them when changing the pipe logic.
- Async assertions use poll-with-deadline loops (state transitions are
  goroutine-driven); don't assert immediately after triggering a transition.

## Gotchas

- **`code` hangs by design** until the tunnel is established or the session
  ends; the daemon closes the stream after `connected` or a terminal event.
  Ctrl-C on `code` cancels the session only pre-connect; a connected session
  keeps running.
- **Session states** (`internal/session/server.go`): `generating → waiting →
  verifying → connected → done`, with `expired/cancelled/failed` terminals.
  `setState` after a terminal state is a no-op; `Subscribe` delivers the
  current state immediately and closes the channel at terminal.
- Cancel is only legal before `connected`; the daemon refuses with "session
  already connected".
- Terminal sessions stay registered in memory so `list` can show them;
  `list` without `all` filters them out.
- The `--fwd` parse is **right-anchored** (`[bind:]port:host:hostport`) so
  IPv6 bind addresses work; ports must be 1–65535.
- The forward allowlist glob is custom (`forward.globMatch`): unlike
  `path.Match`, `*` and `?` also match `:`.
- The daemon socket defaults to mode `0666` (any local user may create
  sessions) — intentional, since the code + SAS are the authentication.
- `internal/daemon/proto.go` `PathInfo.RTTSecs` is misnamed: it carries
  nanoseconds (`int64(time.Duration)`), not seconds. Fixing the JSON field is
  a wire-protocol change to the daemon socket; don't "fix" it casually.
- `docs/design.md` drifts easily: when you change protocol behavior, timeouts,
  constants, exit codes, or CLI flags, update the matching section (it has a
  CLI reference and constants table).
