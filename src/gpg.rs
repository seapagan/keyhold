//! GPG invocation layer.
//!
//! The keepalive operation is a detached signature of empty input written to
//! `/dev/null`: a real private-key operation with no lasting effect and no
//! artefacts. Two modes exist:
//!
//! * [`PingMode::Foreground`] — normal pinentry behaviour, used by
//!   `keyhold on` so the user can unlock the key if it is not cached yet.
//! * [`PingMode::Background`] — adds `--pinentry-mode cancel`, used by the
//!   daemon. If the cache has expired, gpg fails promptly
//!   ("Operation cancelled") instead of opening an unattended pinentry.
//!
//! keyhold never uses loopback passphrase handling and never sees, stores or
//! transmits the passphrase: GnuPG and pinentry remain entirely responsible
//! for unlocking the key.

use std::{
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{ChildStderr, Command, Stdio},
    time::{Duration, Instant},
};

use crate::error::{Error, Result};

/// Environment variable overriding the `gpg` executable path.
///
/// Intended for the test suite and staged debugging; it does not change the
/// arguments keyhold passes to gpg.
pub const GPG_ENV: &str = "KEYHOLD_GPG";

/// How long a background ping may run before it is killed.
const BACKGROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// Pinentry policy for a keepalive ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingMode {
    /// Normal pinentry behaviour; may prompt the user.
    Foreground,
    /// Never prompt: a locked key must produce a prompt-free error.
    Background,
}

/// A located `gpg` executable.
#[derive(Debug, Clone)]
pub struct Gpg {
    path: PathBuf,
}

impl Gpg {
    /// Locate `gpg`: `$KEYHOLD_GPG` if set (resolved to an absolute path,
    /// since the daemon runs with cwd `/`), otherwise the first executable
    /// `gpg` on `$PATH`.
    pub fn detect() -> Result<Self> {
        if let Some(spec) = std::env::var_os(GPG_ENV) {
            let mut path = PathBuf::from(&spec);
            if !path.is_absolute() {
                let cwd = std::env::current_dir()
                    .unwrap_or_else(|_| PathBuf::from("/"));
                path = cwd.join(path);
            }
            if !is_executable(&path) {
                return Err(Error::GpgNotFound(
                    spec.to_string_lossy().into_owned(),
                ));
            }
            return Ok(Self { path });
        }
        if let Some(search) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&search) {
                let candidate = dir.join("gpg");
                if is_executable(&candidate) {
                    return Ok(Self { path: candidate });
                }
            }
        }
        Err(Error::GpgNotFound("gpg (not found on $PATH)".into()))
    }

    /// Perform one keepalive ping: detached-sign empty input, discard output.
    ///
    /// With `key` unset, GPG's normal default-key selection applies.
    pub fn ping(&self, key: Option<&str>, mode: PingMode) -> Result<()> {
        let mut cmd = Command::new(&self.path);
        cmd.arg("--batch")
            .arg("--yes")
            .arg("--detach-sign")
            .arg("--output")
            .arg("/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        if mode == PingMode::Background {
            // Prompt-free failure when the key is no longer cached.
            cmd.arg("--pinentry-mode").arg("cancel");
        }
        if let Some(key) = key {
            cmd.arg("--local-user").arg(key);
        }
        match mode {
            PingMode::Foreground => run_blocking(cmd),
            PingMode::Background => run_with_timeout(cmd, BACKGROUND_TIMEOUT),
        }
    }
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.permissions().mode() & 0o111 != 0
}

fn run_blocking(mut cmd: Command) -> Result<()> {
    let output = cmd.output().map_err(Error::GpgSpawn)?;
    if output.status.success() {
        return Ok(());
    }
    Err(Error::GpgFailed(message(
        &output.stderr,
        output.status.code(),
    )))
}

fn run_with_timeout(mut cmd: Command, timeout: Duration) -> Result<()> {
    let mut child = cmd.spawn().map_err(Error::GpgSpawn)?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().map_err(Error::GpgSpawn)? {
            Some(status) => {
                let stderr =
                    child.stderr.take().map(drain).unwrap_or_default();
                if status.success() {
                    return Ok(());
                }
                return Err(Error::GpgFailed(message(&stderr, status.code())));
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::GpgFailed(format!(
                    "timed out after {timeout:?}"
                )));
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

fn drain(mut reader: ChildStderr) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf);
    buf
}

/// Distil gpg stderr (last non-empty line) into a short human-readable message.
fn message(stderr: &[u8], code: Option<i32>) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("unknown gpg error");
    let suffix = code
        .map(|c| format!(" (exit status {c})"))
        .unwrap_or_default();
    format!("{}{}", line.chars().take(200).collect::<String>(), suffix)
}
