# keyhold

Temporarily keep a GPG private key cached in `gpg-agent` while you explicitly
allow it.

`gpg-agent` forgets your passphrase after `default-cache-ttl` seconds of
inactivity — a sensible default, but painful when you are actively signing
things for an afternoon. `keyhold` periodically performs a harmless signing
operation with your key, refreshing that *normal* idle timer for exactly as
long as you allow it. Turn it off (or let a `--for` deadline lapse) and the
key simply expires on its own again.

`keyhold` never sees, stores, or handles your passphrase. GnuPG and pinentry
remain entirely responsible for unlocking the key.

## Requirements

- Linux (this is a Linux-only tool for now — no fake platform support)
- GnuPG 2.2+ (tested with 2.4)
- A pinentry configured for your terminal (only needed to unlock the key)
- `$XDG_RUNTIME_DIR` set (any modern systemd distribution does this)

## Installation

From source:

```sh
git clone https://github.com/seapagan/keyhold
cd keyhold
cargo install --path .
```

Or build and run in place:

```sh
cargo build --release
./target/release/keyhold --help
```

A `cargo install keyhold` path is intended once the crate is published.

## Usage

```sh
keyhold on                    # hold indefinitely, 5-minute ping interval
keyhold on --for 30m          # hold for thirty minutes
keyhold on --for 4h
keyhold on --key <fingerprint-or-key-id>
keyhold on --key <key-id> --for 2h
keyhold on --interval 5m      # custom ping interval
keyhold off                   # stop holding; cache expires naturally
keyhold status                # what is happening right now
```

Output uses restrained semantic colour when writing to a terminal —
success in green, inactive states in yellow, errors in red. Colour is
handled automatically (via the `colored_text` crate): redirected or piped
output stays plain, and `NO_COLOR` plus the standard force-colour
variables are honoured. There is no colour configuration option.

A typical session:

```text
$ keyhold status
Keyhold status

Daemon     stopped
Hold       off

$ keyhold on --for 4h
# Pinentry appears here if the key is not cached yet.
Keyhold enabled for 4h.

$ keyhold status
Keyhold status

Daemon     running
Hold       on
Key        default
Interval   5m
Remaining  3h 59m
Last ping  3s ago
Next ping  in 4m 57s

# Close the terminal and walk away; the daemon keeps the key cached.

$ keyhold off
Keyhold disabled.

$ keyhold status
Keyhold status

Daemon     running
Hold       off
```

### What `on` does

1. Loads configuration and resolves the key.
2. Starts the daemon if it is not already running.
3. Signs once **in the foreground** with normal pinentry behaviour, so you can
   unlock the key if needed. If this fails, nothing is enabled.
4. Tells the daemon to keep pinging. The daemon's pings are strictly
   non-interactive (see below).

Running `keyhold on` again while enabled replaces the current hold: new
deadline, new interval, new key — not an error.

### `--for`

Without `--for`, the hold lasts until you turn it off (status reports
`Remaining  no deadline`). With it, the daemon disables the hold
automatically when the time is up (e.g. `--for 1h30m`). Durations accept
combined units (`30m`, `4h`, `1h30m`, `500ms`).

Expiry — like `off` — never touches `gpg-agent` and never clears the cache;
the key just resumes its normal idle countdown from the last use.

### Selecting a key

There are three key-selection modes.

**GnuPG default** — plain `keyhold on` passes no key selector, so GnuPG
chooses its normal/default signing key. This is what happens with no
key-related options or configuration; Git configuration is irrelevant
unless Git-key mode is explicitly requested.

**Explicit key** — `keyhold on --key ABCDEF0123456789` (or `key = "..."`
in the config file). `--key` accepts anything `gpg --local-user` accepts
(full fingerprint, long or short key id).

**Git signing key** — `keyhold on --git-key` (or `git_key = true` in the
config file) resolves Git's effective **OpenPGP** `user.signingkey` and
uses that value exactly like an explicit key, for both the foreground
unlock and the daemon's keepalives. The effective `gpg.format` is checked
first: unset or `openpgp` proceeds, while repositories configured with
`gpg.format = ssh` or `gpg.format = x509` are not supported — keyhold
works through GnuPG/OpenPGP, and those signing keys are not GnuPG
selectors. Git itself performs the resolution with its normal
configuration precedence, so inside a repository the local
`user.signingkey` and `gpg.format` naturally override the global ones.
The value is resolved once, when the hold is enabled; the daemon never
consults Git afterwards, and the hold keeps the originally resolved key
until the next `keyhold on`. If Git reports no signing key, `on` fails
clearly without starting anything.

`--key` and `--git-key` are mutually exclusive. Precedence when several
sources are configured: `--key` > `--git-key` > config `key` >
config `git_key` > GnuPG default.

Git-selected holds show the source in `keyhold status`:

```text
Key        ABCDEF0123456789 (git)
```

## Configuration

Optional file at `$XDG_CONFIG_HOME/keyhold/config.toml`
(`~/.config/keyhold/config.toml` by default):

```toml
key = "ABCD1234EFGH5678"   # optional static key; omit for GPG's default key
git_key = true             # optional; use Git's user.signingkey by default
interval = "5m"            # optional; default 5m
```

Setting both `key` and `git_key = true` is rejected as an invalid
configuration: choose one default key-selection strategy.

Precedence: CLI option > config file > built-in default. No config file is
required. Unknown keys, non-positive intervals, and conflicting
key-selection settings are rejected with an error naming the file.

## How the GnuPG TTL interaction works

`keyhold` does **not** modify `gpg-agent.conf`. Ever.

- `default-cache-ttl` is the normal idle timeout that each `keyhold` ping
  refreshes. **Keep the ping interval shorter than this value.**
- `max-cache-ttl` is an absolute cap GnuPG enforces regardless of activity.
  Configure it long enough for your longest intended hold, or the cache will
  expire mid-hold (the daemon will notice and stop; see below).

For example, with:

```text
default-cache-ttl 600
max-cache-ttl 43200
```

a key left alone expires after ten minutes of inactivity. With
`keyhold on --for 8h` and the default 5-minute interval, keyhold actively
maintains the cached key for exactly those eight hours. When the hold ends,
keyhold stops touching the key and normal `gpg-agent` idle expiry resumes
from the final key use, so the key may stay cached for up to ten more
minutes before expiring naturally.

The `max-cache-ttl 43200` setting does **not** stretch an 8-hour hold into a
twelve-hour one — it is an independent absolute ceiling GnuPG enforces on
the cache entry regardless of activity.

## Daemon model

- One resident daemon per user, listening on a Unix socket at
  `$XDG_RUNTIME_DIR/keyhold/keyhold.sock` (mode 0700).
- `keyhold on` starts it automatically, properly detached (`setsid`, no
  controlling terminal, stdio to `/dev/null`); it survives the terminal that
  launched it.
- `off` (and hold replacement, and `--for` expiry) stops *scheduling* new
  keepalives immediately. A keepalive gpg process that already started may
  still run to completion — ordinary signing finishes in milliseconds, with
  a 30-second timeout as the exceptional bound — but its outcome is
  discarded: it can never re-enable, alter, or raise an error against a
  hold that was disabled or replaced in the meantime.
- `keyhold off` leaves the daemon running — it only stops the pings.
- `keyhold daemon` runs the daemon in the foreground (for debugging or use
  under a service manager). A second instance refuses to start.
- `keyhold daemon --stop` shuts the daemon down cleanly and removes its
  socket.
- The daemon keeps no state across restarts: a fresh daemon starts with the
  hold off, and stale socket files are recovered automatically.
- IPC is a small newline-framed JSON protocol on the socket; nothing is
  exposed over the network.

## If a background ping fails

The daemon pings with `--pinentry-mode cancel`: if the cached key has
disappeared (for example the `max-cache-ttl` ceiling hit, or the agent was
restarted), the ping fails immediately instead of opening a pinentry dialog
nobody is watching. The daemon then:

1. disables the hold,
2. stays running,
3. records the failure, shown by `keyhold status`:

```text
Keyhold status

Daemon     running
Hold       off
Error      gpg keepalive failed: gpg: signing failed: Operation cancelled (exit status 2)
```

Run `keyhold on` again to unlock via the normal pinentry flow and resume.

## Security notes

- The passphrase never passes through `keyhold`: no loopback pinentry, no
  passphrase capture, storage, or transmission.
- Foreground unlock uses your normal pinentry; background pings are
  non-interactive by construction.
- The keepalive operation is a detached signature of empty input written to
  `/dev/null` — no files are left behind and no artefacts are kept.
- The socket lives inside `$XDG_RUNTIME_DIR` (0700, per-user) and is itself
  mode 0700.

## Exit codes

| Code | Meaning                                |
| ---- | -------------------------------------- |
| 0    | success                                |
| 1    | operational failure (message on stderr) |
| 2    | usage error (invalid arguments)        |

## Development

```sh
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo nextest run --all-targets --all-features --locked   # or: cargo test
cargo doc --no-deps
cargo package --locked
```

Tests never touch your real keyring: integration tests point `KEYHOLD_GPG` at
a fake `gpg` script. For manual smoke testing against real GnuPG, use a
throwaway home:

```sh
export GNUPGHOME=$(mktemp -d) XDG_RUNTIME_DIR=$(mktemp -d) XDG_CONFIG_HOME=$(mktemp -d)
chmod 700 "$GNUPGHOME"
gpg --batch --passphrase x --pinentry-mode loopback \
    --quick-generate-key 'test' ed25519 sign 0
keyhold on --for 5m --interval 10s
keyhold status
```

Formatting uses a 79-column width (`.rustfmt.toml`); please run `cargo fmt`
before submitting.

## Limitations

- Linux only (v0.1).
- The daemon handles `SIGTERM` (and `SIGINT` when running in the foreground)
  with the same clean shutdown as `keyhold daemon --stop`: no new keepalive
  pings are scheduled, the socket file is removed, and the process exits
  successfully. A `SIGKILL` still abandons the socket file, but the next
  start recovers it automatically.
- One hold at a time: `on` replaces any existing hold.
- `keyhold` cannot extend a hold past GnuPG's `max-cache-ttl` ceiling; GnuPG
  itself imposes that limit.
