# Security Policy

## Supported versions

Only the latest release line is supported.

## Security properties

keyhold has two operating modes with deliberately different guarantees.

### Ordinary mode (the default)

- keyhold **never sees, stores, or transmits your GPG passphrase**:
  unlocking is delegated entirely to GnuPG and pinentry.
- Loopback passphrase handling is never used.
- No Secret Service access happens at all.

### Session credential mode (explicit opt-in)

`keyhold on --store-passphrase` / `-s` (or `store_passphrase = true` in the
config) deliberately expands the security surface in exchange for holds
that survive GnuPG's absolute `max-cache-ttl`:

- The passphrase is prompted once, validated against the exact selected
  key, and stored **only** in the Linux Secret Service collection aliased
  `session` — the collection the desktop session destroys at logout.
  There is no fallback to the persistent `default`/`login` collection, no
  file, and no other persistence.
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
  No cleanup is guaranteed after SIGKILL, a process crash or power loss;
  the session collection itself still disappears at logout.

## Reporting a vulnerability

Please report privately via the GitHub security advisories feature for
[seapagan/keyhold](https://github.com/seapagan/keyhold/security/advisories),
or email the maintainer. Do not open a public issue for security problems.
