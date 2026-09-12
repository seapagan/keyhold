# keyhold

Temporarily keep a GPG private key cached in `gpg-agent` while you explicitly
allow it.

`keyhold` was primarily created for long-running unattended coding-agent
sessions that make GPG-signed commits. `gpg-agent` normally forgets your
passphrase after `default-cache-ttl` seconds of inactivity, so a later commit
can end up blocked on pinentry when nobody is there to answer it. `keyhold`
periodically performs a harmless signing operation with your key, refreshing
that normal idle timer for exactly as long as you allow it. Turn it off (or let
a `--for` deadline lapse) and normal GnuPG cache expiry resumes. It is equally
useful during attended development when repeatedly unlocking the same key is
simply inconvenient.
`keyhold` has two operating modes. In the default mode keyhold never sees,
stores, or handles your passphrase — GnuPG and pinentry remain entirely
responsible for unlocking the key. The explicitly opted-in session
credential mode (`keyhold on --store-passphrase`) additionally stores the
passphrase in the Linux Secret Service **session** collection (erased at
logout) so keyhold can recreate the selected key's cache entry before
GnuPG's absolute `max-cache-ttl` expires; see
[Session credential mode](#session-credential-mode-optional).

## Requirements

- Linux (this is a Linux-only tool for now — no fake platform support)
- GnuPG 2.2+ (tested with 2.4)
- A pinentry configured for your terminal (only needed to unlock the key)
- `$XDG_RUNTIME_DIR` set (any modern systemd distribution does this)
- A Secret Service keyring (GNOME Keyring/KWallet) — only for the optional
  session credential mode

## Installation

Using [cargo-binstall](https://github.com/cargo-bins/cargo-binstall) —
recommended and fastest if you already have it; downloads the prebuilt
release binary from GitHub without compiling anything locally:

```sh
cargo binstall keyhold
```

Using Cargo — standard installation from crates.io (compiles from source):

```sh
cargo install keyhold
```

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

## Usage

```sh
keyhold on                    # hold indefinitely, 5-minute ping interval
keyhold on --for 30m          # hold for thirty minutes
keyhold on --for 4h
keyhold on --key <fingerprint-or-key-id>
keyhold on --key <key-id> --for 2h
keyhold on --interval 5m      # custom ping interval
keyhold on -s --for 4h        # session credential mode (see below)
keyhold off                   # stop holding; cache expires naturally
keyhold status                # what is happening right now
keyhold credential clear      # erase stored session credentials
keyhold daemon -b             # start the daemon detached; no hold, no GPG use
keyhold daemon --stop         # shut the daemon down cleanly
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

Daemon       stopped
Hold         off

$ keyhold on --for 4h
# Pinentry appears here if the key is not cached yet.
Keyhold enabled for 4h.

$ keyhold status
Keyhold status

Daemon       running
Hold         on
Key          default
Key state    unlocked
Credential   not in use
GPG max TTL  2h
Max expiry   in 2h
Interval     5m
Remaining    3h 59m
Last ping    3s ago
Next ping    in 4m 57s

# Close the terminal and walk away; the daemon keeps the key cached.

$ keyhold off
Keyhold disabled.

$ keyhold status
Keyhold status

Daemon       running
Hold         off
Key          default
Key state    unlocked
Credential   not in use
```

`Key state` and `Credential` answer the two questions that matter at a
glance: can GPG sign with this key *right now*, and could keyhold recover
it when GnuPG drops the cache? They stay visible after `off` while the
daemon still knows the most recently resolved key — the hold being off
does not itself clear the GPG cache or delete a session credential — and
disappear only when there is no resolved key left to query. `Max expiry`
shows the honest hard-max countdown when keyhold knows the cache entry's
age (`unknown` otherwise, for example when the key was already cached
before activation), and reads `(auto-renew)` while a session credential is
backing the hold; the timing rows (`Interval`, `Remaining`, `Last ping`,
`Next ping`) appear only while a hold is actually on.

For an ordinary hold, `Credential not in use` is known from the hold mode
alone and does not query Secret Service. A retained stored-mode hold may
still query its explicitly opted-in session credential after `off` or
expiry.

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
(~/.config/keyhold/config.toml by default):

```toml
key = "ABCD1234EFGH5678"   # optional static key; omit for GPG's default key
git_key = true             # optional; use Git's user.signingkey by default
interval = "5m"            # optional; default 5m
store_passphrase = false   # optional; default false — opt in to session
                           # credential mode for `keyhold on` (see below)
clear_secret_on_daemon_stop = false  # optional; delete keyhold's Secret
                                     # Service session items on clean daemon
                                     # shutdown
lock_key_on_daemon_stop = false      # optional; clear the last resolved
                                     # key's GPG cache entry on clean daemon
                                     # shutdown (still works after `off` or
                                     # hold expiry)
```

Setting both `key` and `git_key = true` is rejected as an invalid
configuration: choose one default key-selection strategy.

Precedence: CLI option > config file > built-in default. No config file is
required. In particular `--store-passphrase` / `-s` beats
`store_passphrase = false`, and `--no-store-passphrase` beats
`store_passphrase = true`; storage is never the implicit default. Unknown
keys, non-positive intervals, and conflicting key-selection settings are
rejected with an error naming the file.

## How the GnuPG TTL interaction works

`keyhold` does **not** modify `gpg-agent.conf`. Ever.

- `default-cache-ttl` is the normal idle timeout that each `keyhold` ping
  refreshes. **Keep the ping interval shorter than this value.**
- `max-cache-ttl` is an absolute cap GnuPG enforces regardless of activity.

In ordinary mode, keyhold warns at activation when the requested hold
cannot be guaranteed under these values (a hold longer than
`max-cache-ttl`, a pre-existing cache entry of unknown age, or an
indefinite hold), and the daemon ends the hold when the cache finally
disappears. To hold a key across `max-cache-ttl` boundaries **without
changing your global GnuPG settings**, use session credential mode; see the
next section.

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
minutes before expiring naturally. The `max-cache-ttl 43200` setting does
**not** stretch an 8-hour hold into a twelve-hour one — it is an
independent absolute ceiling GnuPG enforces on the cache entry regardless
of activity.

## Session credential mode (optional)

Ordinary mode cannot hold a key across GnuPG's absolute `max-cache-ttl`:
GnuPG itself drops the cache entry no matter how often the key is used.
Session credential mode opts into a larger security surface in exchange for
holds that are not bounded by that ceiling:

```sh
keyhold on -s --for 4h        # or --store-passphrase
keyhold credential clear
```

or persistently in the configuration file:

```toml
store_passphrase = true
```

(`keyhold on --no-store-passphrase` disables it again for one invocation.)

How it works:

- A normal first stored activation prompts once (normal terminal prompt, not
  pinentry); reuse of a valid stored credential prompts zero times. A
  conclusively stale credential causes one replacement prompt. The passphrase
  is validated by *clearing only the selected key's* GPG cache entry and
  unlocking it again with the exact key, which establishes a cache epoch
  keyhold owns. Keyhold then stores it in the Linux Secret Service **`session`
  collection**, which the desktop session destroys at logout.
- There is no fallback to the `login`/`default` collection, no file, no
  environment variable and no daemon IPC copy: the passphrase reaches
  `gpg` only through child stdin, wrapped in zeroized memory otherwise.
- The daemon proactively recreates the selected key's cache entry shortly
  before each `max-cache-ttl` boundary (a 2h maximum renews at ~1h59m),
  and recovers once from unexpected cache loss (agent restart, another
  program clearing the entry). If the session credential disappears — for
  example after `keyhold credential clear` — the hold stops with a clear
  error at the next renewal instead of prompting unattended.
- The credential lives for the **login session**, not for one hold:
  `keyhold off`, hold expiry and daemon restarts leave it in place, and a
  later `keyhold on -s` reuses it without another prompt. `keyhold
  credential clear` removes every keyhold credential from the session
  collection (it never touches the GPG cache or an active hold).
- Your global GnuPG configuration is never modified: the key's own cache
  entry is cleared and recreated keygrip-specifically, `gpg-agent` is
  never restarted, and unrelated keys are never flushed.
- External programs may also clear or recreate the GPG cache entry; the
  `Max expiry` countdown keyhold displays is then approximate until the
  next renewal re-establishes it. Recovery makes this cosmetic rather
  than fatal.

The security trade-off is real: in ordinary mode keyhold never sees the
passphrase at all, while in session mode the passphrase additionally
exists in the Secret Service session collection for the rest of the login
session, where same-user malware running inside an unlocked desktop
session may be able to read it depending on the keyring's policy. This is
the price of unattended signing reliability; see
[SECURITY.md](SECURITY.md) for the full model.

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
- `keyhold daemon -b` (or `--background`) starts the daemon detached through
  the same path `keyhold on` uses, then returns. It enables no hold and
  never touches GPG; if the daemon is already running it reports that and
  succeeds.
- `keyhold daemon --stop` shuts the daemon down cleanly and removes its
  socket. If (and only if) `clear_secret_on_daemon_stop = true` and/or
  `lock_key_on_daemon_stop = true` is configured, the same clean shutdown
  — including SIGTERM and Ctrl-C on a foreground daemon — also runs those
  cleanup policies synchronously before the process exits: deleting
  keyhold's Secret Service session items and/or clearing the active
  signing key's own GPG cache entry. `keyhold off` never runs them, and
  no cleanup is guaranteed after SIGKILL, a crash or power loss (the
  session collection still disappears at logout).
- The daemon keeps no state across restarts: a fresh daemon starts with the
  hold off, and stale socket files are recovered automatically.
- IPC is a small newline-framed JSON protocol on the socket carrying
  metadata only (never a passphrase); nothing is exposed over the network.

## If a background ping fails

The daemon pings with `--pinentry-mode cancel`: if the cached key has
disappeared (for example the `max-cache-ttl` ceiling hit, or the agent was
restarted), the ping fails immediately instead of opening a pinentry dialog
nobody is watching. The daemon then:

1. disables the hold — except in session credential mode, which first
   attempts exactly one recovery from the stored credential (retrieve,
   keygrip-scoped clear, exact-key loopback unlock) and keeps the hold if
   it succeeds;
2. stays running;
3. records any failure, shown by `keyhold status`:

```text
Keyhold status

Daemon       running
Hold         off
Error        gpg keepalive failed: gpg: signing failed: Operation cancelled (exit status 2)
```

Run `keyhold on` again to unlock via the normal pinentry flow and resume
(in session mode, `keyhold on -s` reuses the stored credential and does
not re-prompt).

## Security notes

- **Ordinary mode (the default)**: the passphrase never passes through
  keyhold — no loopback pinentry, no capture, storage, or transmission.
- **Session credential mode (opt-in)**: keyhold receives the passphrase
  once, validates it, and stores it only in the Secret Service `session`
  collection; it never crosses keyhold's IPC socket, never appears in
  argv/environment/files/logs, and is zeroized after each use. This
  expands the same-user attack surface for the rest of the login
  session; see [SECURITY.md](SECURITY.md).
- Foreground unlock uses your normal pinentry; background pings are
  non-interactive by construction.
- The keepalive operation is a detached signature of empty input written to
  `/dev/null` — no files are left behind and no artefacts are kept.
- The socket lives inside `$XDG_RUNTIME_DIR` (0700, per-user) and is itself
  mode 0700.
- GnuPG configuration files are never modified, `gpg-agent` is never
  restarted, and cache clearing is always scoped to the selected key's
  own keygrip.

## Exit codes

| Code | Meaning                                 |
| ---- | --------------------------------------- |
| 0    | success                                 |
| 1    | operational failure (message on stderr) |
| 2    | usage error (invalid arguments)         |

## Development

```sh
cargo make verify        # full local gate: fmt, check, clippy, tests, docs,
                         # release build, package, MSRV, actionlint, zizmor
cargo make test          # tests only (cargo nextest)
cargo make coverage-html # HTML coverage report in target/llvm-cov/html
cargo make msrv          # check against the minimum supported Rust
cargo make changelog     # regenerate CHANGELOG.md
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the required development tools,
the full task list, and contribution guidelines.

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

The optional Secret Service paths are the one thing the automated suite
cannot fake in-process; exercise them manually against your real session
collection with a throwaway key and `keyhold credential clear` afterwards.

Formatting uses a 79-column width (`.rustfmt.toml`); please run `cargo fmt`
before submitting.

## Limitations

- Linux only (This may change in later versions).
- The daemon handles `SIGTERM` (and `SIGINT` when running in the foreground)
  with the same clean shutdown as `keyhold daemon --stop`: no new keepalive
  pings are scheduled, the socket file is removed, and the process exits
  successfully. A `SIGKILL` still abandons the socket file, but the next
  start recovers it automatically.
- One hold at a time: `on` replaces any existing hold.
- In ordinary mode `keyhold` cannot extend a hold past GnuPG's
  `max-cache-ttl` ceiling; GnuPG itself imposes that limit. Session
  credential mode works around it by recreating the selected key's cache
  entry without touching global GnuPG settings.
- The `Max expiry` countdown assumes no other program recreates the GPG
  cache entry behind keyhold's back; if one does, the display becomes
  approximate until the next renewal or recovery.
