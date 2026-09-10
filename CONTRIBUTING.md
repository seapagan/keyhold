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
cargo make verify
```

That runs formatting, check, Clippy (`-D warnings`), tests (nextest), docs,
release build, packaging, the MSRV check, `actionlint`, and Zizmor
(pedantic). Other useful tasks:

```sh
cargo make test           # tests only (cargo nextest)
cargo make coverage-html  # HTML coverage report in target/llvm-cov/html
cargo make msrv           # check against the minimum supported Rust
cargo make changelog      # regenerate CHANGELOG.md
```

The tasks live in `Makefile.toml` (requires `cargo-make`; the coverage tasks
also need `cargo-llvm-cov`, and `verify` needs `actionlint` and `zizmor` on
`PATH`).

CI runs the same cargo-make tasks on Ubuntu 24.04 plus a Zizmor audit of the
workflow files.

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
