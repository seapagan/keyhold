# Contributing to keyhold

Thanks for considering a contribution.

## Development setup

```sh
git clone https://github.com/seapagan/keyhold
cd keyhold
cargo build
```

Rust toolchain: see `rust-version` in `Cargo.toml` for the minimum supported
version; development generally targets current stable.

## Before opening a PR

Run the full local gate:

```sh
cargo fmt --all -- --check
cargo check --all-targets --all-features --locked
cargo clippy --all-targets --all-features --locked -- -D warnings
cargo nextest run --all-targets --all-features --locked   # or: cargo test --locked
cargo doc --no-deps
cargo package --locked
```

CI runs the same checks on Ubuntu 24.04 plus a Zizmor audit of the workflow
files.

## Conventions

- Formatting is enforced with a 79-column width (`.rustfmt.toml`); always run
  `cargo fmt` before committing.
- Commit subjects: short, imperative, Conventional Commits
  (`feat: ...`, `fix: ...`), signed (`git commit -s`).
- Keep changes minimal and scoped; no drive-by refactors.
- Tests must not touch a real GPG keyring. Use the fake-`gpg` harness in
  `tests/common/` (`KEYHOLD_GPG`) or an isolated `GNUPGHOME`.
- Update `CHANGELOG.md` for user-visible changes.

## Design constraints to respect

- `keyhold` never handles passphrases or uses loopback pinentry.
- `keyhold` never edits GnuPG configuration files.
- Linux-only for now; do not add untested platform shims.

## Reporting bugs

Open an issue with the `keyhold status` output, the exact command, and the
error message. Never include private key material or passphrases.
