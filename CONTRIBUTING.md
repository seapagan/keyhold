# Contributing to keyhold

Thanks for considering a contribution.

## Core development prerequisites

Use Linux to build and run Keyhold. You need Git, a native compiler/linker,
and Rust with Cargo, rustfmt, and Clippy. Install Rust through
[rustup](https://rustup.rs/); see `rust-version` in `Cargo.toml` for the
minimum supported version. Development generally targets current stable.

```sh
rustup component add rustfmt clippy
git clone https://github.com/seapagan/keyhold
cd keyhold
cargo build
```

Application requirements, including GnuPG and optional Secret Service
support, are listed in [README.md](README.md#requirements). **Python is a
development/tooling dependency, not a requirement for running Keyhold.**
The automated Rust tests use isolated fixtures rather than a real keyring.

## Verification tools

The tasks in `Makefile.toml` need the following tools on `PATH` for the
non-optional parts of `cargo make verify`:

| Tool | Purpose |
| ---- | ------- |
| `cargo-make` | Runs the repository's `cargo make` tasks |
| `cargo-nextest` | Runs the Rust test suite |
| ShellCheck | Checks maintained shell scripts |
| actionlint | Checks GitHub Actions workflow syntax |
| Zizmor | Audits GitHub Actions workflows with the pedantic persona |

```sh
cargo install cargo-make --locked
cargo install cargo-nextest --locked
```

Use `--locked` when installing cargo-nextest; installation without it is
unsupported by upstream. CI currently pins cargo-make to 0.37.24 and
cargo-nextest to 0.9.143; matching those versions avoids differences from CI.
The MSRV task also needs the Rust toolchain selected by `MSRV_VERSION` in
`Makefile.toml` installed through rustup.

See the platform guidance below for ShellCheck and actionlint installation.
[actionlint's installation guide][actionlint-install] also covers Go and
prebuilt binaries. Zizmor can be installed with `uv tool install zizmor`,
`pipx install zizmor`, Homebrew, or `cargo install --locked zizmor`.

[actionlint-install]: https://github.com/rhysd/actionlint/blob/main/docs/install.md

### Optional Python checks

Install Python **3.10+** to run the support-code tests and complexity checker.
The tasks look for `python3` on Unix and `python` on Windows. Ruff and mypy
run when their executables are available. These checks are included in
`verify`, but their availability checks can skip them:

| Task | Tool and purpose | Availability check |
| ---- | ---------------- | ------------------ |
| `python-format` | Ruff: Python formatting | `ruff --version` |
| `python-lint` | Ruff: Python linting | `ruff --version` |
| `python-type` | mypy: strict Python type checks | `mypy --version` |
| `python-test` | Python: standard-library support tests | Python 3.10+ |
| `complexity` | Lizard: Rust/Python complexity | Python + Lizard |

The complexity report includes tests. Python must be 3.10+ and
`lizard --version` must succeed.
Lizard must match `COMPLEXITY_LIZARD_VERSION` in `Makefile.toml` (currently
1.23.0) for parser compatibility. A wrong version fails the started task;
it is not treated as a missing tool. Complexity findings are advisory and
do not fail verification, but checker errors and invalid configuration do.

Prefer [uv][uv-install] for isolated Python tool installations:

```sh
uv tool install ruff
uv tool install mypy
uv tool install 'lizard==1.23.0'
uv tool update-shell
```

Restart your shell after updating `PATH`. Installing tools with uv does not
replace the task's requirement for a discoverable Python 3.10+ interpreter.
Alternatively, use `pipx install` with the same package names, or activate a
Python virtual environment and run
`python -m pip install ruff mypy 'lizard==1.23.0'`.

[uv-install]: https://docs.astral.sh/uv/getting-started/installation/

### Platform setup

- **Linux:** use your distribution's packages for build tools and Python.
  For Debian/Ubuntu:

  ```sh
  sudo apt install build-essential git python3 python3-venv shellcheck
  ```

  Install uv using its [official instructions][uv-install], then use the
  tool commands above. Install actionlint using its upstream guide.
  The complete suite needs a Unix shell and utilities including `tar`,
  `gzip`, `install`, and GNU `sha256sum` for the installer fixtures.
  Release-verifier tests use a fake `readelf`; checking actual release ELF
  binaries separately requires `readelf` from binutils.
- **macOS:** external tools and Python checks can run natively. For example,
  `brew install uv shellcheck actionlint zizmor`; install Python 3.10+ too.
  Use a Linux VM for Keyhold builds, runtime tests, and the complete suite.
  The macOS BSD utilities do not satisfy all Unix installer-test assumptions.
- **Windows:** install uv with `winget install --id=astral-sh.uv -e` and use
  the Python tool commands above with Python 3.10+ available as `python`.
  The Python test and complexity tasks have Windows command overrides;
  this does not make Keyhold or the full suite Windows-compatible.
  Use WSL2 with a Linux distribution for the complete development workflow,
  installing the Linux prerequisites inside WSL rather than only on Windows.

### Tools for separate tasks

These are not required by `cargo make verify`:

- `cargo-llvm-cov`: coverage tasks; install with
  `cargo install cargo-llvm-cov --locked` (also needs cargo-nextest).
- `cargo-audit`: dependency vulnerability checks; install with
  `cargo install cargo-audit --locked`.
- `github-changelog-md`: changelog generation (Python 3.10+); install with
  `uv tool install github-changelog-md` or `pipx install github-changelog-md`.

## Before opening a PR

Run the full local gate on Linux:

```sh
cargo make verify
```

Its required tasks run formatting, check, Clippy (`-D warnings`),
tests (nextest), docs,
release build, packaging, the MSRV check, ShellCheck, deterministic installer
tests, deterministic release-binary verification helper tests, `actionlint`,
and Zizmor (pedantic). It also attempts the optional Python checks above.
**A successful run does not prove every optional check ran.** Look for
`Skipping Task` messages, install missing tools, and rerun to include those
checks. A task that starts must succeed, except advisory complexity findings.
Check Zizmor's reported [operating mode][zizmor-modes]: offline runs omit
audits requiring online access.

Other useful tasks:

```sh
cargo make test           # tests only (cargo nextest)
cargo make coverage-html  # HTML coverage report in target/llvm-cov/html
cargo make msrv           # check against the minimum supported Rust
cargo make changelog      # regenerate CHANGELOG.md
```

The tasks live in `Makefile.toml`; see *Verification tools* above for the
external tools they require.

CI runs selected Rust, packaging, ShellCheck, installer, and release-verifier
tasks on Ubuntu 24.04; it does not currently run the Python checks or local
complexity report. A dedicated workflow runs Zizmor with online audits.

[zizmor-modes]: https://docs.zizmor.sh/usage/#operating-modes

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
