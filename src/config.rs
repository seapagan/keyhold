//! User configuration: `$XDG_CONFIG_HOME/keyhold/config.toml`, falling back
//! to `~/.config/keyhold/config.toml`.
//!
//! A config file is never required. Precedence is
//! CLI option > config file > built-in default.

use std::{fs, io, path::Path, path::PathBuf, time::Duration};

use serde::Deserialize;

use crate::{
    cli::{DEFAULT_INTERVAL, parse_duration},
    error::{Error, Result},
};

/// Effective settings for `keyhold on` after merging file and defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Key selector passed to `gpg --local-user`; `None` uses GPG's default key.
    pub key: Option<String>,
    /// Resolve Git's effective `user.signingkey` when no explicit key is
    /// given.
    pub git_key: bool,
    /// Keepalive ping interval.
    pub interval: Duration,
    /// Store the GPG passphrase in the Secret Service session collection
    /// by default (the security-expanding opt-in; CLI flags override).
    pub store_passphrase: bool,
    /// Delete keyhold's Secret Service session items on clean daemon
    /// shutdown.
    pub clear_secret_on_daemon_stop: bool,
    /// Clear the active signing key's GPG cache entry on clean daemon
    /// shutdown.
    pub lock_key_on_daemon_stop: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key: None,
            git_key: false,
            interval: DEFAULT_INTERVAL,
            store_passphrase: false,
            clear_secret_on_daemon_stop: false,
            lock_key_on_daemon_stop: false,
        }
    }
}

impl Config {
    /// The daemon-shutdown cleanup policies derived from this config.
    /// Both are independent, opt-in and default to doing nothing.
    pub fn shutdown_policies(&self) -> ShutdownPolicies {
        ShutdownPolicies {
            clear_secret: self.clear_secret_on_daemon_stop,
            lock_key: self.lock_key_on_daemon_stop,
        }
    }
}

/// Clean-daemon-shutdown cleanup policies. Independent booleans:
/// deleting the Secret Service session items and clearing the active
/// key's GPG cache entry are separate decisions. Neither runs on
/// `keyhold off`; only on a clean daemon stop (`keyhold daemon --stop`,
/// SIGTERM, or Ctrl-C on a foreground daemon).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ShutdownPolicies {
    /// Remove keyhold's items from the Secret Service session collection.
    pub clear_secret: bool,
    /// Clear only the active signing key's normal GPG cache entry
    /// (keygrip-scoped; never an agent restart or global flush).
    pub lock_key: bool,
}

/// Raw shape of the TOML file; unknown keys are rejected.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    key: Option<String>,
    git_key: Option<bool>,
    interval: Option<String>,
    store_passphrase: Option<bool>,
    clear_secret_on_daemon_stop: Option<bool>,
    lock_key_on_daemon_stop: Option<bool>,
}

/// Base config directory: `$XDG_CONFIG_HOME` if absolute, else `$HOME/.config`.
pub fn config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        let dir = PathBuf::from(dir);
        if dir.is_absolute() {
            return Ok(dir);
        }
    }
    let home = std::env::var_os("HOME").ok_or_else(|| Error::Config {
        path: PathBuf::new(),
        reason: "neither $XDG_CONFIG_HOME nor $HOME is set".into(),
    })?;
    Ok(PathBuf::from(home).join(".config"))
}

/// Load the user configuration from `<dir>/keyhold/config.toml`.
///
/// A missing file yields the defaults; anything else is an error.
pub fn load_from(dir: &Path) -> Result<Config> {
    let path = dir.join("keyhold").join("config.toml");
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Ok(Config::default());
        }
        Err(e) => {
            return Err(Error::Config {
                path,
                reason: e.to_string(),
            });
        }
    };
    let file: ConfigFile =
        toml::from_str(&raw).map_err(|e| Error::Config {
            path: path.clone(),
            reason: e.to_string(),
        })?;
    let interval = match file.interval.as_deref() {
        Some(text) => parse_duration(text).map_err(|e| Error::Config {
            path: path.clone(),
            reason: e.to_string(),
        })?,
        None => DEFAULT_INTERVAL,
    };
    let git_key = file.git_key.unwrap_or(false);
    if file.key.is_some() && git_key {
        return Err(Error::Config {
            path,
            reason: "both 'key' and 'git_key = true' are set; choose one \
                     default key-selection strategy"
                .into(),
        });
    }
    Ok(Config {
        key: file.key,
        git_key,
        interval,
        store_passphrase: file.store_passphrase.unwrap_or(false),
        clear_secret_on_daemon_stop: file
            .clear_secret_on_daemon_stop
            .unwrap_or(false),
        lock_key_on_daemon_stop: file.lock_key_on_daemon_stop.unwrap_or(false),
    })
}

/// Load configuration from the standard user configuration directory.
pub fn load() -> Result<Config> {
    load_from(&config_dir()?)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp() -> tempfile::TempDir {
        tempfile::TempDir::new().unwrap()
    }

    #[test]
    fn missing_file_yields_defaults() {
        let dir = tmp();
        assert_eq!(load_from(dir.path()).unwrap(), Config::default());
    }

    #[test]
    fn loads_key_and_interval() {
        let dir = tmp();
        fs::create_dir_all(dir.path().join("keyhold")).unwrap();
        fs::write(
            dir.path().join("keyhold").join("config.toml"),
            "key = \"ABCD\"\ninterval = \"2m\"\n",
        )
        .unwrap();
        let cfg = load_from(dir.path()).unwrap();
        assert_eq!(cfg.key.as_deref(), Some("ABCD"));
        assert_eq!(cfg.interval, Duration::from_secs(120));
    }

    #[test]
    fn key_alone_is_valid() {
        let dir = tmp();
        fs::create_dir_all(dir.path().join("keyhold")).unwrap();
        fs::write(
            dir.path().join("keyhold").join("config.toml"),
            "key = \"ABCD\"\n",
        )
        .unwrap();
        let cfg = load_from(dir.path()).unwrap();
        assert_eq!(cfg.key.as_deref(), Some("ABCD"));
        assert_eq!(cfg.interval, DEFAULT_INTERVAL);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let dir = tmp();
        fs::create_dir_all(dir.path().join("keyhold")).unwrap();
        fs::write(
            dir.path().join("keyhold").join("config.toml"),
            "banana = true\n",
        )
        .unwrap();
        let err = load_from(dir.path()).unwrap_err();
        assert!(err.to_string().contains("invalid configuration"), "{err}");
    }

    #[test]
    fn malformed_toml_is_rejected() {
        let dir = tmp();
        fs::create_dir_all(dir.path().join("keyhold")).unwrap();
        fs::write(
            dir.path().join("keyhold").join("config.toml"),
            "not [ valid",
        )
        .unwrap();
        assert!(load_from(dir.path()).is_err());
    }

    #[test]
    fn zero_interval_is_rejected() {
        let dir = tmp();
        fs::create_dir_all(dir.path().join("keyhold")).unwrap();
        fs::write(
            dir.path().join("keyhold").join("config.toml"),
            "interval = \"0s\"\n",
        )
        .unwrap();
        let err = load_from(dir.path()).unwrap_err();
        assert!(err.to_string().contains("greater than zero"), "{err}");
    }
}
