# tmite — Design Document

**Version:** 1.1 (design freeze for v0.1 implementation)
**Status:** Ready for implementation
**Supersedes:** v1.0 — data plane changed from connection-per-forward to multiplexed streams (D-CONN revised, §7)
**Audience:** Implementers. This document is sufficient to build v0.1 without further design input; where a decision was necessary, it is stated as a decision, not a suggestion.

---

## 1. Overview

`tmite` creates temporary forwarding tunnels between two machines over [iroh](https://crates.io/crates/iroh). A long-lived daemon runs on a server with a persistent iroh identity. Laptops and workstations pair with it once (using a 5-word spoken code), after which the admin can grant them access to specific TCP endpoints on the server. The client runs local listeners; traffic entering a listener is carried over an encrypted, hole-punched iroh connection to the server, which relays it to the configured target.

Typical use: run `tmite daemon` on your VPS, pair your laptop, `tmite admin peers allow laptop localhost:22`, then `tmite connect laptop --fwd 2222:localhost:22` and `ssh -p 2222 localhost` from anywhere, with no open ports on either side.

### 1.1 Goals

- G1: Encrypted transport with NAT traversal, provided by iroh (dial by NodeId, QUIC, hole punching, relay fallback).
- G2: Zero-configuration first contact: 5-word mnemonic pairing code, no NodeIds, IPs, or tickets typed or copied by humans.
- G3: Dual-screen confirmation of the client's identity during pairing (admin compares the client's public key fingerprint shown on both terminals).
- G4: Explicit per-peer, per-target ACLs administered from the server. No peer can request arbitrary dials.
- G5: Single Rust workspace, official `iroh` crate, one binary, three roles (`daemon`, client CLI, server admin CLI).
- G6: Deployable as a plain systemd unit; state is a human-readable file.

### 1.2 Non-goals (v0.1)

- N1: Reverse tunnels (server-side listeners forwarding to the client). Requires the client to be dialable; cut deliberately.
- N2: Dynamic/SOCKS forwarding, wildcard targets, CIDR ranges.
- N3: UDP forwarding.
- N4: Multi-user ACLs, groups, per-rule TTLs.
- N5: Windows support (Unix sockets are central; macOS/Linux only).
- N6: An SAS/ZRTP-style challenge on the *server's* identity (see §12: server identity is TOFU-on-pair, same as `known_hosts`).

### 1.3 Trust model summary

| Relationship | Mechanism |
|---|---|
| Client → server (data plane) | Client pins the server's NodeId learned at pairing; every dial verifies it via the iroh handshake |
| Server → client (data plane) | Server checks `conn.remote_id()` against its peer table before accepting any stream; per-stream ACL checks on `FORWARD` |
| Pairing confidentiality | 128-bit random code, HKDF-derived ephemeral endpoint; nothing secret is transmitted during pairing |
| Pairing authentication | Client's persistent public key displayed on both screens; admin compares and confirms (`y/N`) |
| Admin → daemon | Unix socket permissions (same model as `docker.sock`) |

---

## 2. Architecture

Two node roles, one binary.

**Server node (`tmite daemon`):** long-lived process holding the persistent iroh keypair. Runs:

1. The **main endpoint** — an iroh `Endpoint` with a `Router` accepting a single ALPN `tmite/1` (the data plane). Hard rule: if `conn.remote_id()` is not in the peer table, close immediately. One connection per client session; many streams per connection.
2. Zero or more **invite endpoints** — short-lived, ephemeral endpoints (one per pending invite), each with a keypair *derived from the invite code*, ALPN `tmite-pair/1`. Killed on success, admin rejection, IPC disconnect, or TTL.
3. An **IPC server** on a Unix socket, NDJSON-over-lines, for the admin CLI.
4. State: peers, ACL rules, pending invites. In memory, persisted to TOML on every mutation.

**Client node:** *no daemon*. `tmite connect` is long-lived and holds one iroh connection; `tmite pair` is one-shot. Clients are never dialable; they only dial.

```
laptop                                        server
┌────────────────────────────────┐  ┌──────────────────────────────────────┐
│ tmite connect laptop           │  │ tmite daemon                         │
│  listener 127.0.0.1:2222       │  │  main endpoint (persistent keypair)  │
│    │ TCP conn                  │  │   ALPN tmite/1                       │
│    ├─ open_bi() ─── stream 1 ───────▶ accept_bi → FORWARD → dial 127.0.0.1:22
│    ├─ open_bi() ─── stream 2 ───────▶ accept_bi → FORWARD → dial ...       │
│    └─ open_bi() ─── stream n ───────▶ ...                                  │
│  (one iroh connection, one     │  │  invite endpoints (ephemeral)        │
│   QUIC session, many streams)  │  │  IPC socket (admin CLI)              │
└────────────────────────────────┘  └──────────────────────────────────────┘
```

### 2.1 Data-plane flow (per forwarded connection)

```
ssh -p 2222 localhost
  → tmite accepts 127.0.0.1:2222
  → (session already connected, else dials server NodeId once)
  → opens a bidirectional stream, ALPN tmite/1
  → sends Frame::Forward { target: "localhost:22" } as first bytes on stream
  → server: ACL check on remote_id + target string → dial 127.0.0.1:22
  → server: Frame::Ok  (or Frame::Deny { reason } before any payload bytes)
  → bidirectional raw byte relay on that stream until either side closes
```

**Decision (D-CONN, revised):** `tmite connect` maintains **one iroh connection** to the server; each forwarded TCP connection maps to one **bidirectional QUIC stream**. iroh connections are QUIC sessions: many concurrent streams, independent flow control per stream, no cross-stream head-of-line blocking, keepalive handled by the transport. This is the idiomatic shape; there is no connection-per-forward fallback path in v0.1.

---

## 3. Storage and identity

### 3.1 Locations

| | Server | Client |
|---|---|---|
| Keypair + state | `/var/lib/tmite/` (or `--data-dir`) | `$XDG_DATA_HOME/tmite/` (i.e. `~/.local/share/tmite/`; `--data-dir` overrides) |
| IPC socket | `$XDG_RUNTIME_DIR/tmite/daemon.sock`, else `/run/tmite/daemon.sock` (or `--socket-path`) | tries `$XDG_RUNTIME_DIR/tmite/daemon.sock` then `/run/tmite/daemon.sock` (or just `--socket-path`) |

Paths follow XDG via the `dirs` crate on the client; the server paths are overridable by flags for development (run everything under `./data/` and `./run/`). A client `--socket-path` disables candidate fallback so misconfiguration is never masked.

### 3.2 Files

**`keypair`** (both roles): 32-byte raw secret key, hex-encoded, one line, mode `0600`. Generated with `iroh::SecretKey::generate()` on first run. The iroh NodeId (Ed25519 public half) *is* the node's identity.

**`state.toml`** (server only), written atomically (tempfile + rename) on every mutation:

```toml
version = 1

[[peers]]
name        = "laptop"                      # unique, immutable once created
node_id     = "9f2a41c70b3e5d1877c4a2f0..." # 64-char lowercase hex
paired_at   = "2026-09-07T12:00:00Z"
last_seen   = "2026-09-07T14:02:11Z"        # updated on data-plane sessions

[[rules]]
peer   = "laptop"       # references peers.name
target = "localhost:22" # exact string matched at dial request time
created_at = "2026-09-07T12:05:00Z"
```

**`servers.toml`** (client only):

```toml
version = 1

[[servers]]
name      = "mybox"                       # local alias, used in `tmite connect mybox`
node_id   = "ab12..."                     # server's NodeId, pinned after pairing
paired_at = "2026-09-07T12:00:00Z"
forwards  = ["2222:localhost:22"]         # optional default forward specs (§7)
```

When `tmite connect` is invoked without `--fwd`, the saved `forwards` for the
selected server are used (validated exactly like explicit `--fwd` specs);
passing any `--fwd` replaces the defaults for that invocation. `connect
--save-defaults` persists the given `--fwd` specs as the server's defaults
(or clears them when no `--fwd` is given).

**`ntfy.toml`** (server only, optional): push-notification configuration;
its presence enables notifications (§18). Written atomically (tempfile +
rename) with mode `0600` by the daemon on `ntfy.enable` (§9.2) — never by
the admin CLI directly:

```toml
topic  = "c4a2f09f2a41c70b3e5d1877c4a2f0aa"  # 32 hex chars; the topic is the credential
server = "https://ntfy.sh"                   # optional; defaults to ntfy.sh
```

A client may hold entries for any number of servers; `connect <name>` selects
among them. The alias is chosen by the client (`tmite pair --name`, defaulting
to the server-chosen peer name) and is independent of the server-side peer
name, which remains the server admin's choice and the ACL namespace there.
Entries are keyed by `node_id`: re-pairing the same server updates its entry
(alias included); pairing a different server under an already-used alias is
rejected instead of silently overwriting the existing entry.

### 3.3 Invariants

- Names are unique, case-sensitive, immutable after creation (no rename in v0.1).
- `peer.rm` on a peer with rules fails unless `--force` (which also deletes its rules), preventing silent ACL deletion.
- Rules reference peers by name; deleting a peer cascades only with `--force`.
- All state mutations go through the daemon's IPC. `state.toml` is never hand-edited in v0.1 (no file watching; edits apply only after a restart — accepted limitation).

---

## 4. Pairing code: encoding and key derivation

This is the only shared state between two independently compiled parties. It is pinned by golden test vectors (§14.2). All of this lives in `tmite-proto/src/pairing.rs`.

### 4.1 Code encoding

Identical to iruks (the `mnemonic` crate, Tirosh list):

- Entropy: 5 random bytes (`getrandom::fill`).
- Checksum: `c = sha256(entropy)[0]`; encoded input is 6 bytes = entropy ‖ c.
- Encoding: `mnemonic::to_string` over the 6 bytes → exactly 5 words (4-byte group → 3 words, 2-byte group → 2 words; 3+2 = 5). Displayed space-separated, lowercase.
- Decoding: trim, case-insensitive word match → 6 bytes → verify checksum → reject with a typed error on: wrong word count, unknown word, checksum mismatch. Additionally apply the list-specific validity rule for the final word (in a 6-byte encoding the 5th word can only be one of the first 41 words of the list; reject index ≥ 41 early).
- Client prompts up to **3 rounds** on invalid input, then exits (exit code 2).

### 4.2 Key derivation

```
ikm        = code_entropy          // exactly the 5 entropy bytes, not the checksum
salt       = "tmite/v1"            // version anchor; bump to rotate the scheme
invite_sk  = SecretKey::from_bytes(HKDF-SHA256(ikm, salt, info = "invite"))
invite_id  = invite_sk.public()    // the NodeId the client dials
```

The daemon's **persistent** keypair is never derived from or related to the code. The invite identity exists only to make the daemon dialable by people who know the code, for the invite's lifetime.

### 4.3 Security properties

- 40 bits of entropy, network-bound guessing (each guess = pkarr lookup + QUIC/TLS handshake), short TTL, single use, escalating reject delay (§6.5).
- The code is a *bearer rendezvous secret*, not an authorization: nothing confidential is transmitted over the pairing connection, and pairing only completes after a human on the server compares the client's public key on two screens (§5). An attacker who learns the code in real time can at worst pair first and force a re-invite — visible, not silent (§12).

---

## 5. Pairing protocol (wire)

ALPN `tmite-pair/1` on the invite endpoint. All frames use the §7.1 framing. Pre-decision reads are bounded at 30 s per frame; a stalled peer is dropped.

### 5.1 Flow

```
laptop (tmite pair)                       daemon (invite endpoint)
  │ derive invite_id from code              │ (endpoint already up, pkarr published)
  │ print own NodeId (grouped hex)          │
  │ ── VERSION {version: 1} ──────────────► │ abort on mismatch (both sides)
  │ ── PAIR_HELLO {client_version} ───────► │
  │                                         │ check name not taken (atomic recheck)
  │ ◄── PAIR_WAIT {} ─────────────────────  │ notify IPC client: event pair_request
  │ print "waiting for admin..."            │
  │                                         │   admin sees client NodeId, runs
  │                                         │   peer.invite.decide (y/N)
  │ ◄── PAIR_CONFIRM {node_id, name} ─────  │ if accepted: record peer, persist
  │ store {name → node_id}; print "✔"       │ kill invite endpoint
  │   — or —                                │
  │ ◄── PAIR_DENY {reason} ───────────────  │ if rejected: token burned, endpoint killed
```

### 5.2 Frame types (ALPN `tmite-pair/1`)

| Type | Name | Payload | Direction |
|---|---|---|---|
| 0x01 | `VERSION` | `{ version: u16 }` | both |
| 0x02 | `PAIR_HELLO` | `{ client_version: String }` | client → server |
| 0x03 | `PAIR_WAIT` | `{}` | server → client |
| 0x04 | `PAIR_CONFIRM` | `{ node_id: [u8;32], name: String }` | server → client |
| 0x05 | `PAIR_DENY` | `{ reason: Reason }` | server → client |

`Reason` enum: `NameTaken`, `AdminDenied`, `Expired`, `ServerError`, `Busy`. Payloads are JSON (UTF-8) inside the length-prefixed frame; JSON is used for all control payloads in both ALPNs (§7.1).

### 5.3 Confirmation and timeouts

- **Prompt timeout:** if the client connects but no `peer.invite.decide` arrives within **120 s**, the daemon sends `PAIR_DENY { reason: Expired }`. The invite itself stays alive until TTL; a client may reconnect and try again while the admin is still deciding. The token is burned only by explicit admin rejection or TTL expiry.
- **Single pair connection:** only one pair connection may be in progress per invite. The daemon claims a slot when a connection passes the accept loop and releases it when that connection ends without a recorded peer (including a client that vanishes mid-wait). While the slot is held, any further connection gets `PAIR_DENY { reason: Busy }` immediately — a racing code-holder is never confirmed for an unregistered NodeId.
- **Escalating reject delay** (§6.5) applies per invite endpoint.
- Client behavior on `PAIR_DENY`: print reason, exit 3 (`AdminDenied`) or 2 (other).
- On `PAIR_CONFIRM`, the client prints the server's NodeId in the same grouped-hex format and persists `servers.toml` (under the `--name` alias if given), then exits 0.

### 5.4 Who prints what (dual-screen check)

**Client, immediately on start** (before dialing):

```
Code: ocean pixel falcon ...
This client's NodeId:
  9f2a41c7 0b3e5d18 77c4a2f0 ...
Connecting to invite server...
Waiting for the server admin to confirm...
✔ Paired as "laptop" on:
  ab12ef34 ...
```

**Server admin's terminal** (`tmite admin peers invite`), on `pair_request` event:

```
Pairing request from client:
  9f2a41c7 0b3e5d18 77c4a2f0 ...
Pair this client? [y/N]
```

The NodeId is printed in full, lowercase hex, grouped in 8-char blocks, no truncation. The admin compares the two screens; both terminals are typically the same human over one SSH session, which is the intended deployment. `tmite admin peers invite --yes` skips the prompt for scripting (documented as weakening the check).

**Decision (D-NAME):** names are chosen by the admin at invite time (`--name`, required). Client-chosen names are rejected: the name is the ACL namespace and belongs to the admin.

---

## 6. Invite lifecycle (daemon side)

1. `peer.invite` IPC request → validate name is free (fail fast, error `name_taken`) → check concurrent-invite cap (**8**; beyond that, error `invite_cap`) → derive `invite_sk` per §4.2 → spawn endpoint with the pkarr publisher (n0 preset by default; `--pkarr`/`--relay` daemon flags override, §11) → await `ep.online()` bounded at 45 s → emit `event: code`.
2. Client connects → `PAIR_WAIT` + IPC `pair_request` event.
3. Resolution: `decide(true)` → record peer (atomic recheck of name uniqueness under the state lock) → `PAIR_CONFIRM` → kill endpoint → IPC result. `decide(false)` → `PAIR_DENY { AdminDenied }` → kill endpoint → token burned. IPC socket closed without decision → kill endpoint, no notification.
4. TTL (default **900 s**, `--ttl` on invite, cap 3600 s) → kill endpoint, mark invite expired, notify IPC client with `event: expired` if still connected.

Rejected-vs-expired semantics: after admin rejection the code is dead (endpoint gone, guesses fail fast). After prompt-timeout the code still works until TTL.

### 6.5 Escalating reject delay

Any rejected or failed handshake attempt (unknown/duplicate pair client, malformed frames, guess) on an invite or main endpoint delays the next accept: 500 ms initial, doubling, capped at 8 s, per endpoint, reset by a successful session establishment. Keeps guessing interactive and rate-limited without configuration.

---

## 7. Data protocol (tunnel)

ALPN `tmite/1` on the main endpoint. **One iroh connection per client session; one bidirectional stream per forwarded TCP connection.**

### 7.1 Framing (both ALPNs)

```
u8  msg_type
u32be len
[len] payload (JSON, UTF-8, for all control frames)
```

Control payloads are JSON via `serde_json`; limits: control frames ≤ 4 KiB (over-limit → close stream, log). After a `FORWARD` is answered with `OK`, the *remaining stream* is an opaque byte pipe; no further framing. Versioning: ALPN string is the version (`tmite/1` → `tmite/2` for breaking changes); the `VERSION` frame exists only on the pairing ALPN where pre-share mismatch must be human-explainable.

### 7.2 Frame types (ALPN `tmite/1`)

| Type | Name | Payload | Direction |
|---|---|---|---|
| 0x01 | `FORWARD` | `{ target: String }` | client → server, first frame on each stream |
| 0x02 | `OK` | `{}` | server → client |
| 0x03 | `DENY` | `{ reason: Reason }` | server → client |
| 0x04 | `VALIDATE` | `{ target: String }` | client → server, ACL probe without dialing |

`Reason`: `Unauthorized` (peer has no rule for this target), `TargetUnreachable` (dial failed — include `os_error` string), `ServerError`. Each stream carries exactly one `FORWARD` (or one `VALIDATE`).

There are **no `PING`/`PONG` frames.** Connection maintenance is QUIC's job: the client's transport config sets a keep-alive interval (~15 s) and a generous max idle timeout; the server relies on QUIC keepalives plus the per-read deadlines below. Application-level pings would duplicate the transport and drift out of sync with it.

### 7.3 Server accept loop

Connection level (once per iroh connection):

1. Accept connection on Router; read `remote_id`.
2. Peer lookup: unknown → log, close **after an escalating delay** (§6.5). No frames are parsed from unknown peers.
3. Spawn a per-connection handler that loops: `accept_bi()` → spawn per-stream handler. The accept loop itself never blocks on application logic.

Stream level (per bidirectional stream):

1. Read one `FORWARD` or `VALIDATE` (30 s bound from stream open; over-limit, unexpected type, or malformed frame → close stream).
2. ACL check: exact-match the target string (§8) against that peer's rules. No match → send `DENY { Unauthorized }`, `finish()` the stream, done. **The connection survives a denial.**
3. For `VALIDATE`, the ACL check is the whole job: allowed → `OK`, `finish()` the stream, done. The target is **not** dialed; a probe must never touch the target system.
4. For `FORWARD`: `TcpStream::connect(target)` (connect timeout **10 s**) → on failure `DENY { TargetUnreachable }`, finish stream.
5. `OK`, then relay (§7.5). Update `peers.last_seen` at connection establishment (batched writes are fine; persistence of this field may lag).

Implementation rules:

- **R1:** Never hold shared state across an `await` in the per-stream handler. The handler reads the ACL and dials independently; a slow or hostile stream must not stall the accept loop or sibling streams. The only shared items are the (immutable for the connection's life) peer record and config.
- **R2:** Stream limits: server transport config sets `max_concurrent_bidi_streams` = **256** (constant in `tmite-proto/limits.rs`). At the cap, `open_bi()` on the client pends under QUIC flow control — transparent backpressure, never an application-level `DENY`. The cap is a transport detail, not an observable policy.
- Target string validation: shape `host:port`, ≤ 256 chars, no spaces; **literal match only** against that peer's rules — no wildcard resolution, no DNS logic in the ACL layer (the *dial* resolves DNS normally).

### 7.4 Client session management

`tmite connect <name> --fwd SPEC...` (repeatable, ≥ 1 required). `SPEC` = `[LOCAL_ADDR:]LOCAL_PORT:TARGET`, where `TARGET` is `host:port` and `LOCAL_ADDR` defaults to `127.0.0.1` (v0.1 listens on loopback only). Example: `--fwd 2222:localhost:22`, `--fwd 5433:db.internal:5432`.

Listeners bind at startup (fail fast on port conflicts). The client wraps the server connection in a session type with state `Idle | Connecting | Connected(Connection)` behind a mutex:

- **Eager establishment:** `connect` dials the server immediately at startup (bounded by the online/dial timeouts) and then validates every requested forward before entering the accept loop: for each spec it opens a stream, sends `VALIDATE { target }`, and awaits `OK`/`DENY` (30 s bound). Any dial or validation failure aborts the command with a non-zero exit — an unauthorized or unreachable target fails fast on the command line instead of surfacing only when a local connection arrives.
- On success the client prints one `listening on <addr>:<port> → <target>` line per spec to stdout; `Ctrl-C` tears down.
- The server-side ACL remains authoritative at `FORWARD` time: rules may change while the client runs, and a later `FORWARD` can still be denied even though `VALIDATE` passed.
- **Re-dial on demand after failures:** if the connection drops later, per-stream handlers reset the session handle to `Idle` and the next accepted TCP conn re-dials; the startup probe is not repeated. Per-stream errors (denial, target unreachable) never touch session state. Local TCP conns that hit a failed session are closed (SSH sees connection refused mid-handshake); no automatic retry loop in v0.1 — the local client reconnecting is the natural retry.
- **Defensive identity check:** assert `conn.remote_id()` equals the pinned NodeId (iroh already guarantees this; the assert is cheap insurance).
- `Ctrl-C` → graceful: close listeners, close the connection. QUIC propagates connection close to all streams.

### 7.5 Relay requirements (per stream, both directions)

- Use bounded copies (`tokio::io::copy_bidirectional` semantics) between the TCP socket and the iroh stream. No unbounded buffering.
- **Half-close propagation is mandatory:** TCP FIN ⇄ iroh stream `finish()`. Map a read-side EOF on one transport to a shutdown-write on the other. A wrong implementation manifests as SSH sessions that hang after `exit`; this is the #1 correctness test (§14.3).
- Backpressure: reads must stall when the peer transport's write buffer is full; never `read_to_end` into memory.
- Per-read deadlines: server-side stream reads bound by `--idle-timeout`, default **0 = disabled** in v0.1 (QUIC keepalives maintain the path; SSH-level keepalives handle application liveness).

---

## 8. ACL model

- A rule grants a peer the right to forward to **one exact target string**. Matching is `rule.target == requested.target`, byte-for-byte, evaluated per stream at `FORWARD` time.
- v0.1 has no wildcards, no negations, no defaults. No rules ⇒ every `FORWARD` is denied.
- The daemon dials only target strings that match a rule, which bounds SSRF-style abuse by the daemon itself: it will never dial anything an admin did not type via `peer allow`.
- Targets are dial-then-connect: DNS resolution happens at dial time on the server; a rule for a hostname that later resolves elsewhere is the admin's choice, documented as such.
- Auth happens **once per connection** (§7.3 step 2); ACL checks happen **per stream**. A session's streams are trusted to be from the authenticated peer (iroh authenticates every packet regardless; this is about code structure, not a second security mechanism).

Admin CLI surface (all via IPC):

```
tmite admin peers allow <peer> <target>      # add rule
tmite admin peers revoke <peer> <target>     # remove one rule
tmite admin peers ls                         # peers + rules + pending invites
tmite admin peers rm <peer> [--force]        # delete peer (and rules with --force)
tmite admin peers invite --name <name> [--ttl SECS]
tmite admin status                          # uptime, node id, version, peer/rule/invite counts
```

---

## 9. IPC protocol

Unix socket (`$XDG_RUNTIME_DIR/tmite/daemon.sock`, falling back to `/run/tmite/daemon.sock` under systemd, or `--socket-path`), mode `0660`, parent dir `0755`; users in the daemon's group can use the admin CLI over it. NDJSON: one JSON object per line, both directions. Access control is entirely the socket's.

### 9.1 Envelope

```jsonc
// request
{"id": 7, "method": "peer.invite", "params": {...}}
// success response (terminal for this id)
{"id": 7, "result": {...}}
// error response
{"id": 7, "error": {"code": "name_taken", "message": "peer \"laptop\" already exists"}}
// progress event (mid-request; correlated by id, never terminal)
{"id": 7, "event": "pair_request", "data": {...}}
```

Rules:

- `id` is chosen by the caller (u64); the daemon echoes it. Events and the result for one request share its `id`. Malformed line → `{"error":{"code":"bad_request"}}` and close the connection.
- Events only flow for methods documented with them (`peer.invite`).

### 9.2 Methods

| Method | Params | Events | Result |
|---|---|---|---|
| `peer.invite` | `{name, ttl?}` | `code`, `pair_request`, `expired`, `cancelled` | `{status: "paired", node_id}` or `{status:"rejected"}` / `{status:"expired"}` |
| `peer.invite.decide` | `{invite_id, accept}` | – | `{status: "accepted"}` / `{status: "rejected"}` |
| `peer.allow` | `{peer, target}` | – | `{rule_index}` |
| `peer.revoke` | `{peer, target}` | – | `{removed: bool}` |
| `peer.ls` | `{}` | – | `{peers: [...], rules: [...], invites: [...]}` |
| `peer.rm` | `{peer, force?}` | – | `{removed: bool}` |
| `daemon.status` | `{}` | – | `{version, node_id, uptime_secs, peers, rules, invites}` |
| `daemon.stop` | `{}` | – | `{stopping: true}` (graceful shutdown) |
| `ntfy.enable` | `{server?}` | – | `{topic, server_url}`; generates the topic daemon-side (§18) |
| `ntfy.disable` | `{}` | – | `{removed: bool}` |
| `ntfy.status` | `{}` | – | `{enabled: bool, topic?, server_url?}` |
| `ntfy.test` | `{message?}` | – | `{sent: true}`; synchronous POST via the daemon |

Error codes (string, stable): `bad_request`, `name_taken`, `not_found`, `invite_cap`, `invite_expired`, `peer_has_rules` (rm without force), `internal`.

`peer.invite.decide` references the invite by `invite_id` (a UUID returned in the `code` event's data). If the invite is gone → error `not_found`/`invite_expired`.

### 9.3 CLI prompt hygiene

`tmite admin peers invite` reads `y/N` from `/dev/tty` (not stdin) so piped input can't auto-confirm; if no TTY and no `--yes`, fail with exit 1 rather than guessing. Ctrl-C closes the socket → daemon cancels the invite (§6.3).

---

## 10. CLI specification

Single binary `tmite`; clap-derive; global flags: `-v/-vv` (tracing to stderr; `RUST_LOG` respected, `-vv` ⇒ `trace`), `--data-dir`, `--socket-path` (server commands).

| Command | Runs on | Behavior |
|---|---|---|
| `tmite daemon [--relay URL]... [--pkarr URL] [--idle-timeout SECS]` | server | Foreground process; systemd unit runs it. Logs via `tracing-subscriber` (journald-friendly single-line format) |
| `tmite admin peers invite --name N [--ttl S] [--yes]` | server | IPC; hangs through the whole flow (§5–6); prints code immediately |
| `tmite admin peers allow/revoke/ls/rm`, `tmite admin status` | server | One-shot IPC; print result; exit per §10.1 |
| `tmite pair [CODE] [--yes] [--name ALIAS]` | client | §5; prompts for code if absent and stdin is a TTY (3 rounds); `--name` sets the local alias stored in `servers.toml` (defaults to the server-chosen peer name) |
| `tmite connect <name> --fwd SPEC...` | client | §7.4; blocks until Ctrl-C |
| `tmite node-id` | both | Print this node's NodeId (grouped hex) and exit — used in docs/tests |

### 10.1 Exit codes (an API)

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Fatal / usage error (incl. no TTY for a required prompt) |
| 2 | Invalid or expired code (pairing) |
| 3 | Admin denied pairing |
| 4 | Timeout (pairing: awaiting admin; connect: dial timeout) |
| 5 | Server unreachable (pairing/connect dial failure) |

Scripted consumers (systemd units, CI) may depend on these; they are part of the contract.

---

## 11. iroh integration

Pinned: `iroh = "1"` (lockfile pins the exact minor; the n0 API surface moved substantially across 1.x — treat iroh upgrades as code changes, not bumps). Other deps: `tokio` (full), `clap` (derive), `serde`, `serde_json`, `toml`, `thiserror`, `anyhow` (bin layer only — libraries use typed errors), `tracing`, `tracing-subscriber`, `mnemonic`, `hex`, `data-encoding` (or `hex` alone), `rand`, `getrandom`, `tempfile` (tests), `sha2`, `hkdf`, `zeroize`.

- **All endpoints** (daemon main, invite, client) are built through one helper in `tmite-core/src/net.rs` so option sets can't diverge: default preset `iroh::endpoint::presets::N0` (n0 relay + pkarr publisher/resolver + DNS lookup), `.secret_key(...)`, `.alpns([...])`, `bind()`, then await `online()` (bounded 45 s) before printing anything that assumes discoverability (the pairing code; `daemon` logs "ready" only then).
- **Daemon main endpoint:** `Router` with one accept route for `tmite/1`; transport config sets `max_concurrent_bidi_streams` = 256 (§7.3 R2).
- **Client endpoint:** transport config sets keep-alive ~15 s and a generous max idle timeout (§7.2). The client dials the pinned NodeId from `servers.toml`.
- **Invite endpoints:** same helper with the derived key and `tmite-pair/1`; each registers the pkarr publisher so the client can resolve `invite_id` by NodeId alone. Shutdown via the endpoint's drop/close; ensure the derived `SecretKey` is zeroized on drop (`zeroize`).
- **Custom infrastructure:** `--relay` (repeatable) replaces the relay map; `--pkarr` points publishing/resolution at a self-hosted pkarr relay. When either is set, build the endpoint from the `Minimal` preset plus exactly the requested services. Public n0 relays rate-limit; self-hosting is the documented escape hatch. Dependency on public infrastructure is limited to: invite windows (15 min) and, on the data plane, relay fallback when hole punching fails (direct connections dominate after the first dial).
- **Deployment:** systemd unit template in the repo:

```ini
[Unit]
Description=tmite tunnel daemon
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tmite daemon
Restart=on-failure
User=tmite
Group=tmite
StateDirectory=tmite
RuntimeDirectory=tmite
# StateDirectory ⇒ /var/lib/tmite, RuntimeDirectory ⇒ /run/tmite
# (systemd chowns both to User=/Group=tmite; socket mode 0660 lets
# `tmite`-group members run the admin CLI)
```

---

## 12. Security considerations

1. **Bearer code + human check.** Possession of the code grants dialability of the invite endpoint for ≤ 15 min, nothing more. Authorization to *become a peer* requires the admin comparing the client's NodeId on two screens. A real-time code thief can pair first; the admin sees an unfamiliar key (or no prompt at all if the thief paired before the real client connected — the real user then sees "denied/expired" and reports it; recovery is `peer rm` + re-invite). This is the documented residual risk and the reason invites are single-use with a short TTL.
2. **Server identity is TOFU.** The client pins the NodeId delivered in `PAIR_CONFIRM`. A MITM would need to intercept the spoken code *and* pass the dual-screen check. Same model as `known_hosts`; fingerprint printed at pair time for out-of-band comparison by the paranoid.
3. **Guessing.** 2⁴⁰ invite keyspace, one active guess per connect attempt, escalating accept delay (§6.5) per endpoint, reset on success. Pairing endpoint does nothing except the §5 exchange — no state mutation without a later human decision.
4. **Data plane auth:** connection-level identity check on `remote_id()` before any stream is accepted (§7.3); ACL check per `FORWARD` before any dial. Unknown peers get connection close with delay, no error detail.
5. **No secret material crosses the wire during pairing** (client NodeId is public by definition); the confidentiality of the code itself is irrelevant post-TTL.
6. **Zeroization:** invite secret keys zeroized on endpoint teardown; nothing else long-lived is secret beyond the two keypair files (0600).
7. **Resource limits:** ≤ 8 pending invites; ≤ 256 peers; ≤ 1024 rules; 256 concurrent streams per connection (transport-enforced, §7.3 R2); control frames ≤ 4 KiB; target string ≤ 256 bytes; connect timeout 10 s; per-stream first-frame read 30 s. Limits are constants in `tmite-proto` and surface as errors/flow-control, never panics.
8. **Stream isolation:** one stream's failure or denial never affects sibling streams or session state; enforced by R1 (no shared state across awaits in stream handlers).
9. **No wildcard ACL targets** ⇒ the daemon's dialer cannot be pointed at arbitrary hosts by peers.

---

## 13. Crate layout

```
tmite/
├── Cargo.toml            # workspace
├── tmite-proto/          # pure, no iroh dependency
│   └── src/
│       ├── alpn.rs           # ALPN constants
│       ├── frame.rs          # framing codec, Frame enums (data + pairing)
│       ├── pairing.rs        # code encode/decode, HKDF, vectors
│       ├── ipc.rs            # IPC envelope, methods, error codes
│       └── limits.rs         # all numeric limits as constants
├── tmite-core/           # tokio + iroh
│   └── src/
│       ├── net.rs            # endpoint builder helper, transport config, online()/publish helpers
│       ├── daemon/
│       │   ├── mod.rs        # daemon assembly, shutdown
│       │   ├── main_ep.rs    # Router, connection/stream accept loops, ACL, dialer, relay
│       │   ├── invite.rs     # invite lifecycle, invite endpoints
│       │   ├── state.rs      # State (peers/rules/invites) + TOML persistence
│       │   └── ipc.rs        # unix socket server, dispatch, event fanout
│       └── client/
│           ├── pair.rs       # `pair` flow
│           ├── session.rs    # Session type: Idle/Connecting/Connected, eager dial at startup, reconnect
│           └── connect.rs    # listeners, startup VALIDATE probes, per-conn open_bi, relay
└── tmite/                # bin: clap parsing, prompt (/dev/tty), printing, exit codes
```

Layering rule: `tmite-proto` must compile without tokio/iroh (codec + derivation + JSON types only). `tmite-core` contains all async logic and is where integration tests live. `tmite` is thin: parse, prompt, print, map errors to exit codes.

---

## 14. Testing plan

### 14.1 Unit (offline, fast)

- Code round-trip; every rejection class (word count, unknown word, checksum, last-word rule); 3-round prompt logic.
- Frame codec round-trips, truncation rejection, over-limit rejection.
- IPC envelope parse/serialize; error code coverage.
- ACL matching (exact string; case sensitivity; peer without rules).

### 14.2 Golden vectors (frozen, committed as files)

The code→identity path is the inter-party contract. Commit `vectors/pairing.json` with: entropy hex → words → invite seed hex → invite NodeId hex, for ≥ 5 cases including edge entropy (all-zero — excluded from generation in practice but valid for derivation), and one full pairing handshake transcript (fixed inputs → exact frame byte sequence). CI regenerates and diffs.

### 14.3 Integration (in `tmite-core`)

- Real iroh endpoints bound locally (loopback relay, discovery off, direct addrs exchanged in test harness): pair end-to-end via a mock IPC client; happy path, name-collision, admin-reject, TTL expiry, IPC-close cancellation, prompt timeout.
- **Half-close test (the important one):** one stream's TCP client sends N bytes then `shutdown(WR)`, expects the server-side target to see EOF while the reverse direction stays open, and vice versa; full-duplex 10 MiB each way with checksums; ensures no deadlock and correct FIN mapping.
- **Stream multiplexing:** open **64 simultaneous streams** on one connection, all relaying concurrently, per-stream checksums; then kill the connection mid-stream and assert the client's session state resets to `Idle` and the next TCP conn re-dials.
- **Stream independence:** one stream half-closed while a sibling stream on the same connection still passes data — pins no cross-stream interference.
- **Denial survival:** server sends `DENY` on stream 1; stream 2 on the same connection forwards successfully afterward.
- Data-plane ACL: `DENY { Unauthorized }` for ruleless peer; exact-target matching; target unreachable → `DENY { TargetUnreachable }`.
- Attacker-shaped: unknown `remote_id` → close-with-delay, no frames parsed; malformed `FORWARD` → stream closed, connection alive; `FORWARD` from unknown peer → never dialed (assert no outbound TCP).
- IPC: scripted request/event/result sequences over a real socket, including mid-request disconnect.

### 14.4 Manual smoke script

`docs/smoke.sh`: daemon on a box, invite in one SSH pane, `pair` on a laptop, `peer allow`, `connect --fwd 2222:localhost:22`, `ssh -p 2222 localhost`, `exit` must return the shell promptly (the half-close check, by hand). Then open a second SSH session over the same tunnel concurrently — the multiplexed path, exercised for real.

---

## 15. Configuration reference (defaults)

| Flag/constant | Default | Notes |
|---|---|---|
| invite TTL | 900 s (cap 3600) | `--ttl` |
| prompt timeout | 120 s | admin silence after `pair_request` |
| pre-handshake read timeout | 30 s | pairing ALPN |
| first-frame read timeout (data streams) | 30 s | per stream, server side |
| target connect timeout | 10 s | server dial |
| OK/DENY wait (client) | 30 s | after `FORWARD` |
| `ep.online()` bound | 45 s | daemon + invite endpoints + `pair` |
| reject delay schedule | 500 ms ×2 → 8 s cap | per endpoint, reset on success |
| concurrent invites | 8 | error `invite_cap` beyond |
| max streams per connection | 256 | transport config, server side; client pends at cap |
| QUIC keep-alive (client) | 15 s | transport config |
| control frame max | 4 KiB | |
| idle timeout | disabled (0) | `--idle-timeout`, server stream reads |
| relay / pkarr | n0 defaults | `--relay`, `--pkarr` |

---

## 16. Future work (explicitly out of scope for v0.1, but designed-for)

1. **Reverse tunnels (`-R`):** requires clients to run listeners and the daemon to dial them — a new ALPN and a client capability flag; the biggest single future feature. (Stream multiplexing is no longer future work — it *is* v0.1's data plane.)
2. **6-word codes** (56-bit): one-constant change once `salt` versioning is in place.
3. Rule wildcards, UDP, peer rename, state file watching, multi-admin ACLs, connection-level metrics (`daemon.status` gains per-peer stream counts).

---

## 17. Implementation milestones

1. **M1 — `tmite-proto`:** framing, code codec, HKDF, vectors, IPC types. Done when vector tests pass offline.
2. **M2 — daemon skeleton:** keypair/state persistence, IPC server, `daemon.status`, `node-id`. No iroh yet.
3. **M3 — pairing end-to-end:** invite endpoints, `tmite pair`, dual-screen confirm, all IPC events. Done when the smoke script's pairing section passes.
4. **M4 — data plane:** main endpoint, connection auth, stream accept loop, client session type, relay with half-close correctness. Done when SSH over the tunnel works, concurrent sessions multiplex over one connection, and exit is clean.
5. **M5 — hardening:** reject delays, limits, full integration suite, systemd unit, README.

Each milestone is independently demonstrable; M1–M2 are parallelizable across two implementers.

---

## 18. Push notifications (ntfy)

The daemon can post events to an [ntfy](https://ntfy.sh) topic so the admin's
phone/desktop sees them without polling `tmite admin status`.

**Enable/disable model.** All ntfy management goes through the daemon's IPC
(§9.2, `ntfy.enable`/`ntfy.disable`/`ntfy.status`/`ntfy.test`) — consistent
with the §3.3 invariant that all mutations flow through the daemon. The
daemon owns `${data_dir}/ntfy.toml` and writes it atomically (tempfile +
rename) with mode `0600`. `tmite admin ntfy enable` requests a topic: the daemon
generates 32 hex chars (16 bytes from the pairing CSPRNG; valid ntfy topic
charset), persists the file, and returns `{topic, server_url}` for the CLI
to print as the subscribe URL. Enabling while enabled is a `bad_request`
(no silent topic rotation); an invalid `server` scheme is rejected at
enable time; `tmite admin ntfy test` does a synchronous send from the daemon so
setup failures surface immediately. These commands therefore require a
running daemon and the IPC-group permission on the socket — the admin CLI
never needs read access to `/var/lib/tmite`. There is no config file for
the daemon generally; this one file is deliberately read **per event** by
the drain task, so enable/disable takes effect without a daemon restart
(unlike `state.toml`, §3.3). On ntfy.sh the topic *is* the credential —
anyone who knows it can publish and subscribe — hence 0600 and CSPRNG
entropy. A self-hosted `server` base URL can be given at enable time
(`--server`, http/https only).

**Architecture.** Event sources never do I/O: they clone a `Notifier`
(unbounded channel sender) into the data-plane handler, invite manager, and
`DaemonHandle`. One drain task (spawned by `daemon::run`) receives
`Notification` values, re-reads `ntfy.toml`, applies the cooldown, and POSTs
via the `ntfy` crate (async `Dispatcher`, 10 s timeout). Delivery failures
are logged and dropped; they never block the data plane or fail a request.

**Cooldown.** Notifications with the same (event kind, subject) pair are
suppressed for 60 s — subject being peer name, node id, invite id, or
`peer/target` for rules — so a reconnecting peer or an attacker retry loop
cannot flood the topic. Different subjects never suppress each other.

**Events.**

| Event | Source | Notes |
|---|---|---|
| peer connected | data plane, after peer-table hit | includes peer name |
| connection rejected | data plane, unknown `remote_id` | priority high; security signal |
| pairing request | invite, at `pair_request` | informational (v1): approval still happens on the daemon host via the IPC prompt |
| peer registered | invite, after `add_peer` succeeds | |
| invite created | `peer.invite` accepted for processing | includes TTL |
| invite expired | invite loop, `Outcome::Expired` | |
| rule added | `peer.allow` success | |
| rule revoked | `peer.revoke` success (removed=true) | |

`peer.rm` does not notify (housekeeping; forced removal already implies rule
loss). Notifications add no pairing-wire changes — no frame or pairing
changes — so golden vectors are unaffected (§14.2). The IPC method table
(§9.2) gains the `ntfy.*` methods above.

---

*End of document. Decisions of record: D-CONN (revised, v1.1 — one connection, stream per forward, transport-enforced 256-stream cap), D-NAME (admin names peers at invite time), §5.3 (prompt-timeout keeps the invite alive until TTL). No open questions.*
