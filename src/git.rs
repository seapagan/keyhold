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

use std::process::Command;

use crate::error::{Error, Result};

/// Resolve Git's effective `user.signingkey`.
///
/// Fails with a clear message when Git cannot be executed, reports no
/// signing key, or returns an empty value. The value is passed on as-is,
/// apart from trimming the command output's surrounding whitespace.
pub fn signing_key() -> Result<String> {
    let output = Command::new("git")
        .args(["config", "--get", "user.signingkey"])
        .output()
        .map_err(|e| Error::Message(format!("could not execute git: {e}")))?;
    if !output.status.success() {
        // `git config --get` exits 1 when the key is unset; anything else
        // is a real Git failure worth showing.
        if output.status.code() == Some(1) {
            return Err(no_signing_key());
        }
        return Err(Error::Message(format!(
            "git config failed: {}",
            stderr_tail(&output.stderr)
        )));
    }
    let key = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if key.is_empty() {
        return Err(no_signing_key());
    }
    Ok(key)
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
