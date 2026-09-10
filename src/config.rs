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
    /// Keepalive ping interval.
    pub interval: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key: None,
            interval: DEFAULT_INTERVAL,
        }
    }
}

/// Raw shape of the TOML file; unknown keys are rejected.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigFile {
    key: Option<String>,
    interval: Option<String>,
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
    Ok(Config {
        key: file.key,
        interval,
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
