//! Command-line interface definition and duration parsing.

use std::time::Duration;

use clap::{Parser, Subcommand};

use crate::error::{Error, Result};

/// Default keepalive interval: five minutes.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(5 * 60);

/// Parse a positive human-friendly duration (`30m`, `4h`, `1h30m`, `500ms`).
pub fn parse_duration(value: &str) -> Result<Duration> {
    let parsed =
        humantime::parse_duration(value).map_err(|e| Error::Duration {
            value: value.to_owned(),
            reason: e.to_string(),
        })?;
    if parsed.is_zero() {
        return Err(Error::Duration {
            value: value.to_owned(),
            reason: "must be greater than zero".into(),
        });
    }
    Ok(parsed)
}

/// `keyhold` command line.
#[derive(Debug, Parser)]
#[command(
    name = "keyhold",
    version,
    about = "Keep a GPG private key cached in gpg-agent while you explicitly allow it",
    long_about = "keyhold periodically performs a harmless signing operation with the selected \
GPG private key, refreshing gpg-agent's normal idle cache timeout for as long as you \
explicitly allow it. Turning it off leaves the cache to expire naturally; keyhold never \
sees or stores your passphrase.",
    propagate_version = true,
    arg_required_else_help = true
)]
pub struct Cli {
    /// Subcommand to run.
    #[command(subcommand)]
    pub command: Command,
}

/// Available subcommands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Enable the keepalive hold (starts the daemon if needed)
    On {
        /// GPG key (fingerprint or key id) to keep cached; omit for GPG's default signing key
        #[arg(long, value_name = "KEY")]
        key: Option<String>,
        /// Keep the hold enabled for this long (e.g. 30m, 4h, 1h30m); omit for an indefinite hold
        #[arg(long = "for", value_name = "DURATION", value_parser = parse_duration)]
        r#for: Option<Duration>,
        /// Interval between keepalive pings (e.g. 5m)
        #[arg(long, value_name = "DURATION", value_parser = parse_duration)]
        interval: Option<Duration>,
    },
    /// Disable the hold; the GPG cache is left to expire naturally
    Off,
    /// Show whether the daemon and hold are active
    Status,
    /// Run the daemon in the foreground, or stop a running daemon
    Daemon {
        /// Stop a running daemon instead of starting one
        #[arg(long)]
        stop: bool,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_composite_and_simple_durations() {
        assert_eq!(
            parse_duration("30m").unwrap(),
            Duration::from_secs(30 * 60)
        );
        assert_eq!(
            parse_duration("4h").unwrap(),
            Duration::from_secs(4 * 3600)
        );
        assert_eq!(
            parse_duration("1h30m").unwrap(),
            Duration::from_secs(90 * 60)
        );
        assert_eq!(
            parse_duration("500ms").unwrap(),
            Duration::from_millis(500)
        );
    }

    #[test]
    fn rejects_zero_and_malformed_durations() {
        assert!(parse_duration("0s").is_err());
        assert!(parse_duration("0m").is_err());
        assert!(parse_duration("5").is_err());
        assert!(parse_duration("banana").is_err());
        assert!(parse_duration("-1m").is_err());
    }
}
