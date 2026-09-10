# Security Policy

## Supported versions

Only the latest release line is supported.

## Security properties

- `keyhold` never sees, stores, or transmits your GPG passphrase. Unlocking
  is delegated entirely to GnuPG and pinentry.
- Loopback passphrase handling is never used.
- IPC is a Unix-domain socket at `$XDG_RUNTIME_DIR/keyhold/keyhold.sock`
  (directory 0700, socket 0700, per-user). There is no network surface.
- The keepalive operation is a detached signature of empty input written to
  `/dev/null`; nothing is persisted.
- GnuPG configuration files are never modified.

## Attack surface considerations

- Any local process running as your user can talk to the daemon socket and
  enable/disable holds or stop the daemon. This is the same trust boundary as
  `~/.gnupg` itself; if your user account is compromised, the attacker can
  drive `gpg` directly anyway. Enabling a hold does not reveal key material
  to the caller; it only causes your own agent to keep its cache warm.
- The daemon refuses to run as a second instance and verifies that an
  existing socket is live before replacing it.

## Reporting a vulnerability

Please report privately via the GitHub security advisories feature for
[seapagan/keyhold](https://github.com/seapagan/keyhold/security/advisories),
or email the maintainer. Do not open a public issue for security problems.
