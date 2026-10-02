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
| `shellcheck` | shell-script checks | `apt install shellcheck` or `brew install shellcheck` |
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

### Optional Python support tooling

Python 3.10+ is required for the Python support tasks. Lizard must be exactly
version 1.23.0 to preserve the checker's parser compatibility. Ruff and mypy
are optional local support tools. For example, install them with uv:

```sh
uv tool install 'lizard==1.23.0'
uv tool install ruff
uv tool install mypy
```

Run `cargo make complexity` for the Rust and Python complexity report,
including tests. Findings are advisory and do not fail verification.
Malformed output, invalid configuration, version mismatches, and other
failures that prevent a trustworthy report still fail the task.

`cargo make verify` includes `python-format`, `python-lint`, `python-type`,
`python-test`, and `complexity`. Tasks skip when their optional prerequisites
are unavailable; failures after a task starts remain failures. Python tooling
is not required to run unrelated Rust tasks.

## Before opening a PR

Run the full local gate:

```sh
cargo make verify
```

That runs formatting, check, Clippy (`-D warnings`), tests (nextest), docs,
release build, packaging, the MSRV check, ShellCheck, deterministic installer
tests, deterministic release-binary verification helper tests, `actionlint`,
and Zizmor (pedantic). Other useful tasks:

```sh
cargo make test           # tests only (cargo nextest)
cargo make coverage-html  # HTML coverage report in target/llvm-cov/html
cargo make msrv           # check against the minimum supported Rust
cargo make changelog      # regenerate CHANGELOG.md
```

The tasks live in `Makefile.toml`; see *Development tools* above for the
external tools they require.

CI runs the Rust, packaging, ShellCheck, installer, and release-verifier tasks
on Ubuntu 24.04; a dedicated workflow runs Zizmor.

## Conventions

- Formatting is enforced with a 79-column width (`.rustfmt.toml`); always run
  `cargo fmt` before committing.
- Commit subjects: short, imperative, Conventional Commits
  (`feat: ...`, `fix: ...`), signed (`git commit -s`).
- Keep changes minimal and scoped; no drive-by refactors.
- Tests must not touch a real GPG keyring. Use the fake-`gpg` harness in
  `tests/common/` (`KEYHOLD_GPG`) or an isolated `GNUPGHOME`.
- DO NOT Update `CHANGELOG.md`, this will be done automatically after PR merge
  or before a release.

## Design constraints to respect

- Ordinary mode never handles passphrases or uses loopback pinentry; the
  opt-in session credential mode must keep the passphrase out of argv,
  environment, files, daemon IPC and logs, zeroized in memory otherwise.
- `keyhold` never edits GnuPG configuration files.
- Linux-only for now; do not add untested platform shims.

## Reporting bugs

Open an issue with the `keyhold status` output, the exact command, and the
error message. Never include private key material or passphrases.
