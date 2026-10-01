# TODO

## Bounded/cancellable activation drain for `keyhold lock`

`keyhold lock` disables the hold, then takes the exclusive `activation.lock`
guard to drain foreground activation before cache cleanup. This can wait
indefinitely behind a foreground `keyhold on` blocked in pinentry, retaining
the daemon connection handler and keeping `locking = true`. Daemon shutdown
may then wait for that active connection to drain. The CLI's 120-second IPC
timeout does **not** cancel the daemon-side operation.

Provide bounded and/or cancellable activation draining while preserving every
successful lock guarantee:

- The hold is off.
- The exact managed key's normal GPG-agent passphrase cache entry is absent.
- With `--clear`, that key's stored Keyhold session credential is absent.
- No overlapping activation can re-unlock the managed key after lock reports
  success.
