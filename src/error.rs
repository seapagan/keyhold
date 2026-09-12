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

    /// A companion gpg tool (`gpgconf`, `gpg-connect-agent`) could not
    /// be located.
    #[error("gpg tool executable not found: {0}")]
    GpgToolNotFound(String),

    /// The GPG signing key/target could not be resolved.
    #[error("could not resolve the GPG signing key: {0}")]
    GpgTarget(String),

    /// GnuPG's effective cache TTL values could not be read.
    #[error("could not read GnuPG cache TTL settings: {0}")]
    CachePolicy(String),

    /// GPG rejected the supplied passphrase.
    #[error("gpg rejected the passphrase")]
    BadPassphrase,

    /// A `gpg-connect-agent` command failed: the agent rejected the
    /// command with an Assuan `ERR` response, or its response could not
    /// be understood. The message carries the command and the agent's
    /// machine-readable answer; never secret material.
    #[error("gpg agent command failed: {0}")]
    AgentCommand(String),

    /// An unattended GPG/agent operation exceeded its execution bound
    /// and was killed. The message names the operation; it never
    /// includes secret material.
    #[error("gpg operation timed out: {0}")]
    GpgTimeout(String),

    /// The Linux Secret Service session credential store failed.
    #[error("secret service error: {0}")]
    SecretService(String),

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
