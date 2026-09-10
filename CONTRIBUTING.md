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

## Development tools

The `cargo make` tasks (see `Makefile.toml`) rely on a few external tools.
Required for the normal `cargo make verify` gate:

| Tool | Needed by | Install |
| ---- | --------- | ------- |
| `cargo-make` | every `cargo make ...` task | `cargo install cargo-make` |
| `cargo-nextest` | tests, coverage | `cargo install cargo-nextest --locked` |
| `actionlint` | `verify` | [see notes below][actionlint-install] |
| `zizmor` | `verify` | `pipx install zizmor` |

Only needed for special-purpose tasks:

| Tool | Needed by | Install |
| ---- | --------- | ------- |
| `cargo-llvm-cov` | coverage tasks | `cargo install cargo-llvm-cov --locked` |
| `cargo-audit` | `audit` | `cargo install cargo-audit` |
| `github-changelog-md` | `changelog` | `pipx install github-changelog-md` |

Notes:

- `cargo-nextest --locked` is mandatory: a plain `cargo install
  cargo-nextest` fails by design.
- `zizmor` also ships on PyPI (`uv tool install zizmor`), Homebrew and
  crates.io (`cargo install --locked zizmor`).
- `github-changelog-md` is a Python tool (>= 3.10);
  `uv tool install github-changelog-md` works too.
- `actionlint` is a Go binary: `go install
  github.com/rhysd/actionlint/cmd/actionlint@latest`,
  `brew install actionlint`, or a prebuilt binary from its releases.
- CI pins `cargo-make@0.37.24` and `cargo-nextest@0.9.143`; matching those
  versions locally avoids surprises.

[actionlint-install]: https://github.com/rhysd/actionlint/releases

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

The tasks live in `Makefile.toml`; see *Development tools* above for the
external tools they require.

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
