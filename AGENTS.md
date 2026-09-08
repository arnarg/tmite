# AGENTS.md

`tmite` is a Rust workspace implementing temporary forwarding tunnels between
two machines over iroh (QUIC + NAT traversal). A long-lived daemon runs on a
server; clients pair once with a 5-word code and then forward TCP traffic over
a single multiplexed iroh connection.

**Read `docs/design.md` first.** It is the authoritative, decision-numbered
spec (D-CONN, §5 pairing wire protocol, §14 test strategy). Code comments
reference it by section number. When changing wire/IPC behavior, update the
design doc if the change contradicts it.

## Commands

```sh
cargo build                                  # workspace build
cargo test --workspace                       # full test suite (offline, no relays)
cargo clippy --all-targets -- --deny warnings  # what CI/nix checks enforce
cargo fmt

# Golden vectors (see "Golden vectors" below)
cargo run -p tmite-core --example gen_vectors
cargo run -p tmite-core --example gen_transcript

# Nix (crane-based)
nix build          # builds only the `tmite` binary (-p tmite)
nix flake check     # clippy (--all-targets --deny warnings) + fmt
```

Development run (everything under the repo):

```sh
mkdir -p data run
cargo run -- daemon --data-dir ./data --socket-path ./run/daemon.sock
```

`docs/smoke.sh` is the manual end-to-end flow (server / invite / pair / allow
/ connect / test) including the half-close check. The `test` subcommand is the
canonical half-close regression: `ssh -p 2222 localhost 'echo; exit'` must
return promptly.

## Crate layering (strict)

```
tmite-proto   pure, synchronous: frame codec, pairing codec + HKDF,
              IPC envelope types, limits. NO tokio, NO iroh.
tmite-core    all async logic: endpoint builder (net.rs), daemon
              (main_ep.rs data plane, invite.rs, ipc.rs, sessions.rs, state.rs),
              client (pair.rs, session.rs, connect.rs), fsio.rs.
tmite         the `tmite` binary only: clap parsing, prompts, printing, exit
              codes. No business logic.
```

- New wire types / limits go in `tmite-proto`, not `tmite-core`.
- Anything testable without iroh belongs in `tmite-proto` (see `tmite-proto/src/limits.rs`
  for all protocol constants: frame caps, timeouts, TTLs, keepalive).
- `tmite/src/main.rs` maps crate errors to exit codes via a static
  `EXIT_CODE: AtomicI32`; propagate specific codes by storing before returning
  Err (default on error is `exit(1)`).

## Architecture invariants

- **Data plane**: one iroh connection per client session, one bidirectional
  QUIC stream per forwarded TCP connection. Frames are
  `u8 type | u32be len | JSON` (see `tmite-proto/src/frame.rs`); after `OK`
  the stream is an opaque byte pipe. Half-close propagation (TCP FIN ⇄
  stream `finish()`) is mandatory — breaking it is the classic regression here.
- The daemon's main endpoint closes any connection whose `remote_id()` is not
  in the peer table, before any stream handling (`daemon/main_ep.rs`).
- **Pairing**: invite endpoints are ephemeral iroh endpoints whose keypair is
  HKDF-derived from the invite code entropy (salt `tmite/v1`, info `invite`).
  The daemon's persistent key is never derived from the code. Codes are
  single-use, default TTL 900 s, ≤ 8 concurrent invites.
- **ACLs**: exact, case-sensitive string matches on `host:port`. No
  wildcards, ever (non-goal N2). `rule_allows` tests in
  `tmite-core/tests/state.rs` pin this.
- **State**: `state.toml` / `servers.toml`, TOML, written atomically
  (tempfile + rename) on every mutation. Names are unique, case-sensitive,
  immutable once created. `peer.rm` fails without `--force` if the peer has
  rules. State is never hand-edited (edits apply only after restart).
- **IPC**: NDJSON over a Unix socket (mode 0660, tested in
  `tmite-core/tests/ipc.rs`). A `Reply` is one of result / error / event —
  long-running requests (invite, pair) stream mid-request events on the same
  `id`. The admin confirm prompt reads from `/dev/tty` so piped input cannot
  auto-confirm; `--yes` skips it for scripting.
- **Socket fallback**: an explicit `--socket-path` *disables* candidate
  fallback (`fsio::candidate_socket_paths`) so misconfiguration is never
  masked. Preserve this when touching path logic.

## Golden vectors

`vectors/pairing.json` and `vectors/transcript.json` are committed golden
vectors pinning the pairing codec and handshake transcript. `tmite-proto`
tests `include_str!` them at **compile time**, so:

- The `vectors/` directory must exist for any `--all-targets` build (the nix
  flake explicitly unions it into the source fileset for this reason).
- After any change to the pairing scheme or handshake frame sequence, rerun
  both `gen_vectors` and `gen_transcript` examples and commit the updated
  JSON — otherwise `tmite-proto` tests fail (correctly).

## Testing conventions

- Integration tests use **offline loopback iroh endpoints**:
  `Endpoint::builder(presets::Minimal)` with direct addresses exchanged by
  the harness (`tmite-core/tests/data_plane.rs`, `iroh_smoke.rs`). Do not add
  tests that require real relays or the network.
- `peer invite` is deliberately excluded from the test suite (needs iroh
  relays); it is only exercised by the manual smoke flow.
- The IPC test harness (`tmite-core/tests/ipc.rs`) builds a `DaemonHandle`
  directly and asserts the socket appears with mode 0660; reuse
  `start_daemon_ipc` when adding IPC method tests.
- Pairing code parsing is case-insensitive; the 5th word of a 6-byte
  encoding can only be among the first 41 words of the Tirosh list (reject
  earlier indices) — pinned in `tmite-proto/tests/vectors.rs`.

## Gotchas

- Rust **edition 2024** (workspace-wide).
- Exit codes are a contract: `0` ok · `1` fatal/usage · `2` invalid/expired
  code · `3` admin denied · `4` timeout · `5` server unreachable.
- The repo is colocated with **jujutsu** (`.jj/`) alongside git; `git`
  commands work normally.
- `tmite-core/examples/` are regenerators, not demos — running them rewrites
  the committed vector files.
- Client and server store different files (`servers.toml` vs `state.toml`)
  under different default dirs (XDG data dir vs `/var/lib/tmite`); the
  client keys servers by `node_id` and rejects alias collisions rather than
  overwriting.
