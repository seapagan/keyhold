# Security Policy

## Supported versions

Only the latest release line is supported.

## Security properties

keyhold has two operating modes with deliberately different guarantees.

### Ordinary mode (the default)

- keyhold **never sees, stores, or transmits your GPG passphrase**:
  unlocking is delegated entirely to GnuPG and pinentry.
- Loopback passphrase handling is never used.
- Ordinary holds never access Secret Service. Explicit credential deletion
  commands (`credential clear`, `lock --clear`, or configured cleanup) may
  delete stored credentials without reading passphrases.

### Session credential mode (explicit opt-in)

`keyhold on --store-passphrase` / `-s` (or `store_passphrase = true` in the
config) deliberately expands the security surface in exchange for holds
that survive GnuPG's absolute `max-cache-ttl`:

- A normal first activation prompts once; reuse of a valid stored credential
  prompts zero times, and a conclusively stale credential causes one
  replacement prompt. The passphrase is validated against the exact selected
  key and stored **only** in the Linux Secret Service collection aliased
  `session`, which the desktop session destroys at logout. There is
  no fallback to the persistent `default`/`login` collection, no file, and no
  other persistence. The daemon never prompts.
- The passphrase never appears in process arguments, environment
  variables, keyhold's Unix-socket IPC protocol, daemon state, config
  files, temporary files, or logs. It reaches `gpg` exclusively through
  the child's stdin (`--passphrase-fd 0` with loopback pinentry) and is
  held in zeroized buffers otherwise, discarded immediately after each
  validation.
- GnuPG configuration is never modified. Cache management is scoped to
  the selected signing key's own keygrip (`CLEAR_PASSPHRASE
  --mode=normal <keygrip>`); `gpg-agent` is never restarted and unrelated
  keys are never flushed.

**Threat-model consequence:** in this mode the passphrase additionally
exists in the Secret Service session collection for the rest of the login
session. Same-user malware running inside an unlocked desktop session may
be able to read it, depending on the keyring service and its policy. This
is the explicit trade-off for unattended signing reliability; if that
trade is unacceptable, keep using ordinary mode and raise GnuPG's
`max-cache-ttl` yourself.

### Both modes

- IPC is a Unix-domain socket at `$XDG_RUNTIME_DIR/keyhold/keyhold.sock`
  (directory 0700, socket 0700, per-user). It carries metadata only —
  never a passphrase or any secret bytes. There is no network surface.
- The keepalive operation is a detached signature of empty input written
  to `/dev/null`; nothing is persisted.
- GnuPG configuration files are never modified by either mode.

### Explicit locking

`keyhold lock` disables the hold and removes the retained managed keygrip's
live GPG-agent passphrase cache entry, leaving the daemon running. It waits
for in-flight stored-mode renewal under the same per-key transaction lock;
stale renewal work then observes the disabled hold and aborts. It preserves
the stored Keyhold session credential by default, allowing Keyhold to
restore access when you explicitly run `keyhold on -s` again.

`keyhold lock --clear` also deletes that key's stored session credential,
removing Keyhold's unattended recovery ability for it. Neither operation
flushes unrelated keys or restarts GPG-agent. Cleanup errors leave the hold
off and preserve completed cleanup; Keyhold reports failure. Unprotected
keys have no passphrase cache entry to lock.

These commands cannot undo secret theft or prevent same-user malware in an
unlocked desktop session from driving GPG or accessing the session keyring.

## Attack surface considerations

- Any local process running as your user can talk to the daemon socket and
  enable/disable holds, stop the daemon, or read status metadata. This is
  the same trust boundary as `~/.gnupg` itself; if your user account is
  compromised, the attacker can drive `gpg` directly anyway. Enabling a
  hold does not reveal key material to the caller; it only causes your own
  agent to keep its cache warm.
- The daemon refuses to run as a second instance and verifies that an
  existing socket is live before replacing it.
- The daemon never prompts for anything. In session credential mode, a
  hold whose stored credential has disappeared stops with a recorded
  error instead of attempting interactive recovery.
- Shutdown cleanup (`clear_secret_on_daemon_stop`,
  `lock_key_on_daemon_stop`) runs only on clean daemon shutdown
  (`keyhold daemon --stop`, SIGTERM, or Ctrl-C on a foreground daemon).
  The lock policy targets the most recently resolved signing keygrip —
  non-secret metadata the daemon deliberately retains after `off`,
  timed expiry or a hold failure, because the GPG cache entry can
  outlive the hold. It never clears a key it never resolved.
  No cleanup is guaranteed after SIGKILL, a process crash or power loss;
  the session collection itself still disappears at logout.

## Reporting a vulnerability

Please report privately via the GitHub security advisories feature for
[seapagan/keyhold](https://github.com/seapagan/keyhold/security/advisories),
or email the maintainer. Do not open a public issue for security problems.
