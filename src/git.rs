//! Git signing-key resolution — client side only.
//!
//! `keyhold on --git-key` (or `git_key = true` in the config) asks Git for
//! its effective `user.signingkey` and passes the value to GPG exactly as
//! an explicit `--key` would. Git itself performs all configuration
//! resolution (repository-local overriding global, plus include/system
//! rules) from the caller's current working directory; keyhold never
//! parses Git config files and never falls back to GPG's default key in
//! this mode. The daemon is entirely Git-unaware: it only ever receives
//! the already-resolved selector.
//!
//! keyhold is an OpenPGP/GnuPG utility, so Git-key mode first verifies
//! that Git's effective signing format is OpenPGP. `gpg.format` unset
//! counts as OpenPGP (Git's default); `ssh` or `x509` signing keys are
//! not GnuPG selectors and are rejected before anything is started.

use std::process::Command;

use crate::error::{Error, Result};

/// Resolve Git's effective OpenPGP signing key.
///
/// Verifies the signing format first, then resolves `user.signingkey`.
/// Fails with a clear message when Git cannot be executed, uses a
/// non-OpenPGP signing format, reports no signing key, or returns an
/// empty value. The value is passed on as-is, apart from trimming the
/// command output's surrounding whitespace.
pub fn signing_key() -> Result<String> {
    ensure_openpgp_format()?;
    let Some(key) = config_get("user.signingkey")? else {
        return Err(no_signing_key());
    };
    if key.is_empty() {
        return Err(no_signing_key());
    }
    Ok(key)
}

/// Confirm Git's effective signing format is OpenPGP.
///
/// `gpg.format` unset is Git's default (OpenPGP); an explicit `openpgp`
/// (ASCII case-insensitively, as a lone canonical value) also passes.
/// Anything else — `ssh`, `x509`, unknown values — is rejected: those
/// signing keys are not GnuPG selectors.
fn ensure_openpgp_format() -> Result<()> {
    match config_get("gpg.format")? {
        None => Ok(()),
        Some(format) if format.eq_ignore_ascii_case("openpgp") => Ok(()),
        Some(format) => Err(Error::Message(format!(
            "Git signing format is '{format}'; --git-key requires OpenPGP \
             signing"
        ))),
    }
}

/// Run `git config --get <name>` in the caller's working directory.
///
/// `Ok(None)` means the value is unset (`git config --get` exit code 1).
/// Trimmed values are returned as-is.
fn config_get(name: &str) -> Result<Option<String>> {
    let output = Command::new("git")
        .args(["config", "--get", name])
        .output()
        .map_err(|e| Error::Message(format!("could not execute git: {e}")))?;
    if !output.status.success() {
        // `git config --get` exits 1 when the key is unset; anything else
        // is a real Git failure worth showing.
        if output.status.code() == Some(1) {
            return Ok(None);
        }
        return Err(Error::Message(format!(
            "git config failed: {}",
            stderr_tail(&output.stderr)
        )));
    }
    Ok(Some(
        String::from_utf8_lossy(&output.stdout).trim().to_string(),
    ))
}

fn no_signing_key() -> Error {
    Error::Message(
        "no Git signing key is configured: set user.signingkey, use --key, \
         or disable git_key"
            .into(),
    )
}

/// Last non-empty stderr line, trimmed (mirrors the GPG error style).
fn stderr_tail(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("unknown git error")
        .chars()
        .take(200)
        .collect()
}
