# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-10

### Added

- `keyhold on` command: foreground GPG unlock ping (normal pinentry
  behaviour) followed by background keepalive in the resident daemon.
- `--for DURATION` limited holds with automatic, non-destructive expiry.
- `--interval DURATION` ping interval and `--key` key selection, with
  `$XDG_CONFIG_HOME/keyhold/config.toml` configuration
  (CLI > config file > built-in default).
- `keyhold off`: idempotent disable that leaves the GPG cache and daemon
  untouched.
- `keyhold status`: daemon/hold state, key, interval, remaining time, last
  and next ping, last keepalive error.
- Per-user detached daemon on `$XDG_RUNTIME_DIR/keyhold/keyhold.sock` with
  stale-socket recovery, single-instance enforcement, and a small
  newline-framed JSON IPC protocol.
- `keyhold daemon` (foreground) and `keyhold daemon --stop`.
- Non-interactive background pings (`--pinentry-mode cancel`) that disable
  the hold and retain the failure reason instead of opening a pinentry.
- Unit and integration test suites using a fake `gpg` executable; no real
  keyring is ever touched by tests.

[0.1.0]: https://github.com/seapagan/keyhold/releases/tag/v0.1.0
