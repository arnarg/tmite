# tmite — Design Document

**One-shot TCP tunnel to a firewalled host via iroh, with a 5-word pairing code and SAS verification.**

---

## 1. Overview

`tmite` solves one problem: you have a server behind a firewall that you can reach somehow (VPN on your phone, or the server has a public IP), but you can't reach it from your work laptop. You want to tunnel TCP connections to it, just once, without reconfiguring firewalls or VPNs.

The flow:

1. **On the server** (via SSH from your phone): run `tmite code`. It prints a 5-word code and, once a client connects, a 6-digit SAS. It blocks until the tunnel is established.
2. **On the laptop**: run `tmite join alpha beta gamma delta epsilon --fwd 2222:localhost:22 --fwd 8080:localhost:80`.
3. Read the words and SAS off the phone screen, type the words on the laptop, compare the SAS, confirm. The laptop starts listening on the specified local ports and forwards traffic through the tunnel.

A daemon runs persistently on the server. `tmite code` tells the daemon to create a one-shot session. The daemon binds an ephemeral iroh endpoint, publishes it to the relay network, and waits for a single connection. The client derives the same cryptographic identity from the words, finds the endpoint through iroh, connects, performs a SAS verification handshake, and then opens data streams — one per forwarded TCP connection — that the daemon forwards to the requested TCP destinations.

---

## 2. Architecture

```
┌─ phone ───────────┐
│  ssh user@server  │
│  $ tmite code      │
│  alpha beta ...    │
│  SAS: 123456       │
│  (blocks until     │
│   tunnel is up)    │
└───────────────────┘
         │ SSH (VPN or direct)
         ▼
┌──────────────────────────────────────────┐
│              server                      │
│                                          │
│  tmite daemon (persistent)               │
│  ┌────────────────────────────────────┐  │
│  │ Unix socket: /run/tmite/daemon     │  │
│  │   NDJSON, one command per line     │  │
│  │   code is a subscription:          │  │
│  │   reply words, then stream events  │  │
│  │                                    │  │
│  │  code handler:                     │  │
│  │    → generate 5 words              │  │
│  │    → derive ephemeral iroh key     │  │
│  │    → bind endpoint, publish pkarr  │  │
│  │    → return words                  │  │
│  │    → stream waiting/verifying/...  │  │
│  │                                    │  │
│  │  session goroutine:                │  │
│  │    → accept 1 connection           │  │
│  │    → verify client EndpointID      │  │
│  │    → version + SAS handshake       │  │
│  │    → accept data streams,          │  │
│  │      forward to TCP targets        │  │
│  │    → wait for client close,        │  │
│  │      shutdown endpoint, exit       │  │
│  └────────────────────────────────────┘  │
│                                          │
│  ┌────────────────────────────────────┐  │
│  │ ephemeral iroh endpoints           │  │
│  │  (one per active session)          │  │
│  └────────────────────────────────────┘  │
└──────────────────────────────────────────┘
         ▲
         │ iroh relay / hole-punch (internet)
         │
┌─ laptop ──────────┐
│ tmite join         │
│  alpha beta ...    │
│  --fwd ...         │
│  SAS: 123456 [y/N] │
│  → listens on      │
│    local ports     │
└────────────────────┘
```

### 2.1 Why ephemeral endpoints per session

Each session is a fresh `iroh.Bind` with a key derived from the 5-word code. The code *is* the identity — there is no other shared state between client and server. After the session ends, the endpoint is shut down, the key is useless, and the code is meaningless.

Goroutines manage the lifecycle: the daemon's main loop accepts NDJSON commands on the Unix socket, spawns a goroutine per session, the goroutine cleans up its own endpoint when the session ends, and the subscriber (the `code` command) watches state changes until the tunnel is established.

Parallel sessions are supported and bounded only by available ports and relay connections. In practice sessions are rare and short-lived, so the public n0 relay infrastructure is adequate. Self-hosted relays are supported via flags.

---

## 3. The Pairing Code

### 3.1 Encoding

- 5 random bytes from `crypto/rand`.
- 1 checksum byte = `sha256(payload[0:5])[0]`.
- 6 bytes encoded via [mnemonicode](https://github.com/schollz/mnemonicode) → exactly 5 words.

The encoding uses mnemonicode's standard word list. 4 bytes map to 3 words, 2 bytes map to 2 words: 3+2 = 5 words total.

Decoding validates: word-list membership, decoded length (must be 6 bytes), checksum byte (catches ~255/256 of single-word typos), and final-word index (must be < 41, a structural constraint of the 6-byte encoding where the last word can only be one of the first 41 words of the list).

### 3.2 Key Derivation

```
IKM   = code[0:5]                           (5 bytes)
salt  = "tmite/v1"
HKDF-SHA256(ikm, salt, info="server") → 32-byte server seed
HKDF-SHA256(ikm, salt, info="client") → 32-byte client seed
```

Each seed becomes an iroh `SecretKey` via `key.NewSecretKey(seed)`. The server's `EndpointID` (Ed25519 public half) is the address the client resolves and connects to. The client's `EndpointID` is the only identity the server will accept.

Role separation (server vs. client info strings) prevents self-connect and lets the server allowlist exactly one client.

If the derivation scheme changes, bump the salt to `tmite/v2`. Both client and server binaries embed the protocol version and refuse mismatches at the wire level.

### 3.3 Security Budget

40 bits of entropy, ephemeral, network-bound, single-shot. An attacker must:

1. Know (or guess) the 5 words (~2⁴⁰ keyspace).
2. Perform a pkarr lookup to resolve the server's address.
3. Complete a QUIC handshake to the server endpoint.
4. Race the legitimate client (only one connection is accepted).
5. Pass the SAS verification.

Each guess is a full network round-trip. The server rejects wrong client IDs immediately. The pairing window is minutes long (configurable, default 5 minutes). This is sufficient: the code is read from a screen and typed within seconds — it is never stored or transmitted.

---

## 4. Wire Protocol

A single iroh connection with multiple streams. The first stream is the **control stream** — it carries version negotiation, the forward declaration, the SAS handshake, and stays open as a session heartbeat. Subsequent streams are **data streams**, one per forwarded TCP connection.

### 4.1 Control Stream

```
Client                                    Server
  │                                          │
  │ ── "TMITE1\n" ────────────────────────► │  version check
  │ ◄─────────────────── "TMITE1\n" ─────── │  (both abort on mismatch)
  │                                          │
  │ ── "FWD localhost:80,localhost:5432\n"─► │  forward targets
  │                                          │  (must be non-empty)
  │ ── SHA-256 commitment (32B) ──────────► │  SAS agreement
  │ ◄──────────────── X25519 pub (32B) ──── │  (hash commitment:
  │ ── X25519 pub (32B) ──────────────────► │   server picks blind)
  │                                          │
  │          [both compute SAS,              │
  │           server sends SAS to daemon,    │
  │           human compares both screens]   │
  │                                          │
  │ ── "CONFIRM\n" ───────────────────────► │  SAS-gated; first
  │                                          │  message that can
  │          [control stream stays open      │  commit the session
  │           as heartbeat]                  │
```

Every line before CONFIRM is plaintext and terminated by `\n`. A client that rejects the SAS sends `REJECT\n` instead of `CONFIRM\n`, so the server fails the session immediately rather than waiting out the confirmation timeout. CONFIRM is the last plaintext line on the control stream. After CONFIRM the control stream is idle — it stays open, and the session ends when the connection closes.

**Version string**: `TMITE1` (protocol version 1).

**Forward line**: a comma-separated list of `host:port` targets as resolved on the server side. The forward list must be non-empty — the server rejects an empty forward list by closing the control stream. The client enforces this at the CLI level: `tmite join` requires at least one `--fwd` flag.

The exact bytes of the forward line are bound into the SAS computation.

### 4.2 SAS Handshake

The SAS (Short Authentication String) is a 6-digit number computed independently on both sides from the handshake transcript. It is never transmitted. The human compares the server's SAS (displayed by `tmite code` on the phone screen) against the client's SAS (displayed by `tmite join` on the laptop) and confirms or rejects.

**Why SAS**: anyone who knows the 5 words can derive both iroh identities and impersonate either side. The SAS protects against an active MITM who holds the words and terminates iroh on both legs. Without a commitment scheme, such an attacker could grind ephemeral keys offline to produce matching SAS on both screens. The hash commitment makes grinding interactive — each attempt requires a fresh connection and a fresh SAS on the console, visible to the human as a handshake storm.

**Commitment protocol**:

1. Client generates an ephemeral X25519 keypair and sends `SHA-256("tmite/sas/commit/v1" || client_eph_pub)` — 32 bytes.
2. Server generates its own ephemeral X25519 keypair and sends the public key — 32 bytes. The server picks its key **blind**, having seen only the client's hash.
3. Client sends its public key — 32 bytes.
4. Server verifies the commitment: `SHA-256("tmite/sas/commit/v1" || received_client_pub) == commitment`. Mismatch aborts.
5. Both sides compute the shared secret: `ss = X25519(own_priv, peer_pub)`.
6. Both sides compute the SAS:

```
SAS = first 6 decimal digits of
    SHA-256(
        "tmite/sas/v1" ||
        ss ||
        uint16be(len(forward_line_bytes)) || forward_line_bytes ||
        client_eph_pub ||
        server_eph_pub
    )
```

All fields are fixed-size except the forward line, which is length-prefixed (2 bytes, big endian) so its framing inside the hash is unambiguous. The forward line is bound into the SAS, so a MITM who changes the targets changes the SAS — the human would see a mismatch.

**Timeouts**: each pre-CONFIRM read is bounded at 30 seconds. The server waits 30 seconds for CONFIRM after the SAS is computed. If the client doesn't confirm in time, the session aborts.

### 4.3 Data Streams

After CONFIRM, the client opens one data stream per local TCP connection. Each data stream has a minimal framing:

```
Client                                    Server
  │                                          │
  │ ── "FWD host:port\n" ─────────────────► │  target to dial
  │ ◄── "OK\n" ──────────────────────────── │  connected
  │ ◄═══ raw bidirectional ═══════════════► │  io.Copy ↔ TCP
  │                                          │
  │  or:                                     │
  │ ◄── "ERR connection refused\n" ───────── │  dial failed
  │ ◄── (stream closed)                      │
```

The target in the data stream's `FWD` line **must** match one of the targets declared in the control stream's forward list. The server rejects any stream whose target was not in the SAS-bound list — this prevents a compromised client from pivoting to new targets after SAS confirmation.

The client may open data streams concurrently. The server bounds the maximum number of concurrent streams (64). Beyond that, new streams are rejected by closing them immediately.

---

## 5. Daemon Protocol

The daemon listens on a Unix socket at `/run/tmite/daemon` (configurable). It speaks **NDJSON** — newline-delimited JSON, one JSON object per line.

### 5.1 Commands

**CODE** — create a session and subscribe to its state. Unlike the other commands, code is **not** a one-shot round trip: after replying with the words it streams `event` lines on the same connection until the tunnel is established or the session ends.

```
→ {"cmd":"code"}
← {"ok":true,"words":["alpha","beta","gamma","delta","epsilon"],"id":"abc123","expires":"2026-08-31T10:05:00Z"}
← {"event":"waiting"}
← {"event":"verifying","sas":"123456"}
← {"event":"connected"}
```

The words are printed only once the endpoint is online and published, so a printed code is a resolvable code. After `connected` (or a terminal event) the daemon closes the stream, ending the command. Other commands may still be issued on the same connection before code completes; code runs concurrently and its events are multiplexed into the same NDJSON stream.

**LIST** — list sessions.

```
→ {"cmd":"list"}
← {"ok":true,"sessions":[{"id":"abc123","age_secs":45,"state":"waiting"},{"id":"def456","age_secs":12,"state":"connected"}]}
```

`state` is one of `generating`, `waiting`, `verifying`, `connected`, `done`, `expired`, `cancelled`, `failed`.

**CANCEL** — cancel a session by ID. Only sessions that have **not** connected yet can be cancelled — that includes `verifying` (the tunnel is not up until CONFIRM arrives). The daemon refuses with an error once a session is `connected` or terminal.

```
→ {"cmd":"cancel","id":"abc123"}
← {"ok":true}
← {"ok":false","error":"session not found"}
← {"ok":false,"error":"session already connected"}
```

### 5.2 Session States

```
generating → waiting → verifying → connected → done
                  ↓         ↓
    expired / cancelled / failed
```

- **generating**: Ephemeral key derivation, iroh `Bind`, pkarr publish, `Online`. Typically sub-second.
- **waiting**: Endpoint is online and published. Code displayed. Awaiting client connection.
- **verifying**: Client has connected, SAS computed and displayed to the daemon subscriber. Awaiting SAS confirmation from the client.
- **connected**: CONFIRM received. Data streams are active.
- **done**: Client closed the connection. Endpoint shut down. Goroutine exited.
- **expired**: No client connected within `--session-timeout`. Endpoint shut down. Goroutine exited.
- **cancelled**: `cancel` (or an interrupted `code`) ended the session before it connected (`generating`, `waiting`, or `verifying`). Endpoint shut down. Goroutine exited.
- **failed**: Session could not start (endpoint bind, relay config, or publish error). Typically sub-second.

Each session consumes one goroutine, one UDP socket, and one relay connection. Resources are freed at any terminal state. Sessions stay registered (in memory) after completion so `list` can show what happened.

---

## 6. iroh Integration

### 6.1 Server (per session)

```go
ep, _ := iroh.Bind(ctx,
    iroh.WithSecretKey(serverKey),
    iroh.WithALPNs("tmite/1"),
    iroh.WithRelayMode(relayMode),
)
ep.Online(ctx)
// Publish to pkarr
pub, _ := iroh.N0PkarrPublisher(serverKey, nil)
pub.Publish(ep.Addr())
// Republish on address changes
go func() {
    for addr := range ep.WatchAddr().Stream(ctx) {
        pub.Publish(addr)
    }
}()
```

### 6.2 Client

```go
ep, _ := iroh.Bind(ctx,
    iroh.WithSecretKey(clientKey),
    iroh.WithALPNs("tmite/1"),
    iroh.WithAddressLookup(lookup),
    iroh.WithRelayMode(relayMode),
)
// Resolve server ID with backoff
addr, _ := resolveID(ctx, lookup, serverID)
conn, _ := ep.Connect(ctx, addr, "tmite/1")
```

### 6.3 Discovery

The server publishes its addressing to a pkarr relay. The client resolves via pkarr HTTP and DNS TXT records. Both use the same defaults (n0 production infrastructure) and are overridable via flags:

| Flag | Default | Used by | Description |
|------|---------|---------|-------------|
| `--relay` | n0 production relays | daemon, client | Home relay URL (repeatable) |
| `--pkarr` | n0 production pkarr relay | daemon, client | Pkarr HTTP relay URL |
| `--dns-origin` | `dns.iroh.link` | client | DNS TXT discovery origin |

The daemon passes its `--relay` and `--pkarr` configuration to each session's ephemeral endpoint. The client must use matching values to resolve the server.

---

## 7. Security Model

### 7.1 Threat Model

| Adversary | Capability | Defense | Residual risk |
|-----------|-----------|---------|---------------|
| Passive eavesdropper | Reads the 5 words from the screen | Words are ephemeral, single-shot, useless after the session ends. | None |
| Passive VNC recorder | Records the words and SAS | Words are boot-scoped; recorded code is useless after the session. Recorded SAS is useless without the words. | None |
| Network-only attacker | Guesses the 5 words and dials the server | 2⁴⁰ keyspace, each guess is a network round-trip. Server accepts exactly one connection, rejects wrong client IDs. | ≈10⁻⁴ at 10⁶ guesses/s |
| Network attacker + real-time words | Connects with the derived client key, MITMs both legs | **SAS mismatch** aborts before any data stream is opened. Hash commitment makes grinding interactive (~2²⁰ per cycle), each retry is a fresh SAS on the console. | ~2⁻²⁰ per grind cycle |
| Malicious iroh relay | Observes and forwards traffic | iroh QUIC is end-to-end encrypted between client and server endpoints. The tunneled protocol may provide its own encryption (e.g. SSH, TLS). | Metadata (timing, data volume) visible to relay |
| Compromised server | Full access to daemon process | Out of scope. The server terminates the iroh stream and forwards to TCP, so it sees plaintext tunneled traffic. | Same as trusting the server itself |

### 7.2 What tmite does NOT protect against

- **Host compromise**: the server running the daemon sees the plaintext tunneled traffic at the TCP forwarding layer. This is inherent — the daemon terminates the iroh stream and forwards to TCP. If you don't trust the server, don't run the daemon there.
- **Active MITM with knowledge of the code + SAS ignored**: an attacker who knows the 5 words and can MITM the iroh connection will produce a different SAS. If the human ignores the mismatch and confirms anyway, the attacker owns the tunnel. This is the same failure mode as ignoring an SSH host key warning.
- **Evil maid**: modifying the unencrypted daemon binary is out of scope.

---

## 8. CLI Reference

### 8.1 Daemon

```
tmite daemon
    --allow-forward=localhost:*
    [--listen=/run/tmite/daemon]
    [--session-timeout=5m]
    [--relay=...]
    [--pkarr=...]
    [--bind=...]
    [--external-addr=...]
```

Starts the long-running daemon. Listens on the specified Unix socket for NDJSON commands. Sessions expire after `--session-timeout`. Relay and pkarr configuration applies to all session endpoints.

`--allow-forward` (repeatable, **required**) restricts which destinations sessions may forward to. Each pattern is a glob matched against the full `host:port` string; `*` and `?` match any characters including the colon separator (e.g. `localhost:*`, `*.internal:22`, `127.0.0.1:*`). A target is allowed if it matches any pattern. There is no default: the daemon refuses to start without at least one `--allow-forward` flag.

The daemon has no default forward target. Every session's forward targets are declared by the client. The server rejects any connection that sends an empty forward list.

### 8.2 Code

```
tmite code [--socket=/run/tmite/daemon]
```

Connects to the daemon's Unix socket, sends `{"cmd":"code"}`, prints the 5 words to stdout, then **blocks until the tunnel is established or the session ends without one**, watching the daemon's streaming state:

- Prints the session ID and expiry to stderr.
- On `verifying`: prints the SAS to stderr.
- On `connected`: prints "tunnel established" and exits 0.
- On `expired` (no client before `--session-timeout`) or `cancelled`: explains why and exits 2.
- On `failed` (bind/publish failure): exits 1.

This is the command you run on the server. Interrupting it (Ctrl-C / SIGINT / SIGTERM) exits 130 and tells the daemon to cancel the session — but only while it is still `generating`/`waiting`/`verifying`. A connected session is left running (the tunnel is in use). A second Ctrl-C exits immediately without waiting for the cancel.

### 8.3 Join

```
tmite join
    --fwd [bind_addr:]port:host:hostport
    [--wait=10m]
    [--relay=...]
    [--pkarr=...]
    [--dns-origin=...]
    [--bind=...]
    [--external-addr=...]
    <word1> <word2> <word3> <word4> <word5>
```

Derives keys from the words, resolves the server, connects via iroh, performs the SAS handshake, and starts forwarding traffic.

**Forward flags** (`--fwd`, repeatable, required): each specifies a port forward. At least one `--fwd` is required. The format is `[bind_address:]port:host:hostport`. The bind address defaults to `localhost`. The remote `host:port` is resolved on the server side.

**Connection flow:**

1. Prints connection progress to stderr.
2. After the SAS handshake, prints the 6-digit SAS in bold to stderr and prompts on stderr, reading the answer from stdin (a single line; only `y`/`Y` accepts):

   ```
   SAS: 123456
   Does this match the server's console? [y/N]
   ```

3. On `N`, EOF, or timeout: exits 3.
4. On `Y`: sends CONFIRM, starts local TCP listeners for each `--fwd`.
5. Blocks until the connection closes or Ctrl-C.

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Session completed |
| 1 | Fatal error (bad words, network, protocol, version mismatch, no `--fwd` flags) |
| 2 | Session timeout (server didn't come online within `--wait`) |
| 3 | SAS mismatch / not confirmed |
| 4 | Server rejected (wrong client ID, expired session, bad forward list) |

The words may be omitted if the `TMITE_ASKPASS` environment variable names a helper program. In that case the helper is invoked with no arguments and must print the 5 words to stdout (whitespace-separated, any case); its stderr is passed through. Explicit word arguments always win; a partial argument list is an error and the helper is never consulted.

### 8.4 List and Cancel

```
tmite list   [--socket=/run/tmite/daemon]   # List active sessions
tmite cancel [--socket=/run/tmite/daemon] <id>   # Cancel a session
```

---

## 9. Filesystem Layout

```
cmd/tmite/
  main.go              # CLI wiring, version string
  daemon/              # daemon command
  code/                # code command (pairing session creation)
  join/                # join command (client)
  list/                # list command
  cancel/              # cancel command
internal/
  code/                # 5-word pairing code: encode, decode, checksum
  keys/                # HKDF key derivation from code bytes
  discovery/           # iroh relay/pkarr/DNS configuration
  session/             # session lifecycle: bind, accept, SAS, pipe
  daemon/              # daemon: unix socket listener, NDJSON dispatch
  wire/                # version handshake, SAS protocol, forward framing
  sas/                 # SAS computation and commitment
```

---

## 10. Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `ALPN` | `tmite/1` | iroh ALPN for stream negotiation |
| `Version` | `TMITE1` | Wire protocol version string |
| `Salt` | `tmite/v1` | HKDF salt / derivation scheme version |
| `RandomLen` | `5` | Random bytes in pairing code |
| `ChecksumLen` | `1` | Checksum bytes in pairing code |
| `WordCount` | `5` | Words in pairing code |
| `DefaultSessionTimeout` | `5m` | Session lifetime without a client |
| `DefaultClientWait` | `10m` | Client dial backoff budget |
| `DefaultSocket` | `/run/tmite/daemon` | Daemon Unix socket path (mode 0666) |
| `MaxStreams` | `64` | Maximum concurrent data streams per session |
| `SASCommitTag` | `tmite/sas/commit/v1` | Domain tag for hash commitment |
| `SASTag` | `tmite/sas/v1` | Domain tag for SAS derivation |
| `SASDigits` | `6` | Number of digits in the SAS |
| `SASConfirmTimeout` | `30s` | Server timeout waiting for CONFIRM |
| `PreConfirmTimeout` | `30s` | Per-read timeout during the SAS handshake |

---

## 11. References

- [mnemonicode](https://github.com/schollz/mnemonicode) — word list encoding used for the pairing code
- [go-iroh](https://github.com/tmc/go-iroh) — Go bindings for the iroh P2P library
- [RFC 6189 — ZRTP](https://www.rfc-editor.org/rfc/rfc6189) — SAS and hash commitment analysis (§4.4.1)
