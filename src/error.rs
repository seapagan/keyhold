//! Error type shared by every `keyhold` component.

use std::{io, path::PathBuf};

/// Errors surfaced to the user by `keyhold` commands.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The `gpg` executable could not be located or is not usable.
    #[error("gpg executable not found: {0}")]
    GpgNotFound(String),

    /// A `gpg` keepalive invocation failed.
    #[error("gpg keepalive failed: {0}")]
    GpgFailed(String),

    /// A `gpg` subprocess could not be executed.
    #[error("failed to execute gpg: {0}")]
    GpgSpawn(io::Error),

    /// I/O failure.
    #[error(transparent)]
    Io(#[from] io::Error),

    /// The user configuration file is invalid.
    #[error("invalid configuration file {path}: {reason}")]
    Config {
        /// Path of the offending file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },

    /// A duration value could not be parsed or is out of range.
    #[error("invalid duration {value:?}: {reason}")]
    Duration {
        /// The offending input.
        value: String,
        /// Why it was rejected.
        reason: String,
    },

    /// `$XDG_RUNTIME_DIR` is missing or not absolute.
    #[error(
        "$XDG_RUNTIME_DIR is not set to an absolute path; keyhold needs it for its per-user socket"
    )]
    NoRuntimeDir,

    /// The daemon did not become reachable after being started.
    #[error("daemon did not become reachable after starting")]
    DaemonStart,

    /// The daemon is not running.
    #[error("keyhold daemon is not running")]
    DaemonNotRunning,

    /// The daemon reported an error.
    #[error("daemon error: {0}")]
    Daemon(String),

    /// Malformed IPC payload.
    #[error("IPC protocol error: {0}")]
    Ipc(String),

    /// Composed human-readable message.
    #[error("{0}")]
    Message(String),
}

/// Result alias used across the crate.
pub type Result<T, E = Error> = std::result::Result<T, E>;
