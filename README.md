# tmite

One-shot TCP tunnels to firewalled hosts over [iroh](https://github.com/tmc/go-iroh),
with a 5-word pairing code and SAS verification.

You have a server behind a firewall that you can reach somehow (VPN on your
phone, or the server has a public IP), but not from your work laptop. `tmite`
tunnels TCP connections to it, just once, without reconfiguring firewalls or
VPNs.

## How it works

1. **On the server**: run `tmite code`. It prints a 5-word code and, once a
   client connects, a 6-digit SAS. It blocks until the tunnel is established.
2. **On the laptop**: run `tmite join alpha beta gamma delta epsilon --fwd 2222:localhost:22`.
3. Read the words and SAS off the phone screen, type the words on the laptop,
   compare the SAS, confirm. The laptop starts listening on the local ports and
   forwards traffic through the tunnel.

The 5 words *are* the identity: both sides derive ephemeral iroh keys from them
via HKDF, so there is no key file and no other shared state. The SAS protects
against an active MITM who holds the words — a hash-commitment exchange makes
grinding detectable, and the human compares the two screens before any data
flows. After the session ends, the code is meaningless.

Full protocol, threat model, and constants: [`docs/design.md`](docs/design.md).

## Install

```sh
go install github.com/arnarg/tmite/cmd/tmite@latest
```

Or with Nix:

```sh
nix build github:arnarg/tmite
```

## Usage

### 1. Start the daemon (server)

```sh
tmite daemon --allow-forward='localhost:*'
```

The daemon listens on a Unix socket (`/run/tmite/daemon` by default) and
manages pairing sessions. `--allow-forward` is **required** and restricts which
destinations sessions may forward to; each value is a glob matched against the
full `host:port` string (`*` and `?` also match `:`). Examples:

```sh
tmite daemon --allow-forward='localhost:*' --allow-forward='*.internal:22'
```

### 2. Create a session (server, via SSH)

```sh
tmite code
```

Prints the 5 words to stdout and waits. When a client connects it prints the
SAS to stderr, then "tunnel established" once confirmed. Ctrl-C cancels the
session while it is still waiting (exit 130); a connected session keeps running.

### 3. Join the session (laptop)

```sh
tmite join alpha beta gamma delta epsilon --fwd 2222:localhost:22 --fwd 8080:localhost:80
```

`--fwd` is repeatable and required. Format: `[bind_addr:]port:host:hostport`.
The bind address defaults to `localhost`; the remote `host:port` is resolved on
the server side. After the SAS handshake you are prompted:

```
SAS: 123456
Does this match the server's console? [y/N]
```

Answer `y` only if it matches the server's screen. Then connect to the local
ports as usual (`ssh -p 2222 localhost`, `http://localhost:8080`, ...).

The words may be omitted if `TMITE_ASKPASS` names a helper program that prints
the 5 words to stdout (SSH_ASKPASS-style).

### Other commands

```sh
tmite list            # active sessions (add --all for finished ones, --paths for route detail)
tmite cancel <id>     # cancel a session that has not connected yet
```

## Exit codes (`join`)

| Code | Meaning |
|------|---------|
| 0 | Session completed |
| 1 | Fatal error (bad words, network, protocol, no `--fwd`) |
| 2 | Server didn't come online within `--wait` |
| 3 | SAS mismatch / not confirmed |
| 4 | Server rejected (wrong client ID, expired session, bad forward list) |

## Configuration

Flags read environment variables (e.g. `TMITE_SOCKET`, `TMITE_FWD`,
`TMITE_RELAY`). Self-hosted iroh infrastructure is selected with `--relay`,
`--pkarr`, and `--dns-origin`; the client and daemon must use matching values.
Run `tmite <command> --help` for the full flag list.

## Security notes

- The daemon terminates the iroh stream and forwards to TCP, so it sees the
  plaintext tunneled traffic. Only run it on a host you trust.
- Tunneled protocols should provide their own encryption (SSH, TLS).
- Ignoring a SAS mismatch is the same failure mode as ignoring an SSH host-key
  warning: don't.

## Development

```sh
go build ./...
go test ./...
go test -race ./...
go vet ./...
```
