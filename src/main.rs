//! `keyhold` binary: CLI dispatch and user-facing output.

use std::{
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;

use keyhold::{
    cli::{Cli, Command},
    config::{self, Config},
    daemon,
    error::{Error, Result},
    git,
    gpg::{Gpg, PingMode},
    ipc::{self, Request, Response},
    presentation,
    state::KeySource,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            presentation::error(&e.to_string());
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::On {
            key,
            git_key,
            r#for,
            interval,
        } => on(key, git_key, r#for, interval),
        Command::Off => off(),
        Command::Status => status(),
        Command::Daemon { stop } => {
            if stop {
                daemon_stop()
            } else {
                // Foreground/debugging mode (also the detached entry point).
                daemon::run(Gpg::detect()?)
            }
        }
    }
}

fn on(
    key: Option<String>,
    git_key: bool,
    hold_for: Option<Duration>,
    interval: Option<Duration>,
) -> Result<()> {
    let config = config::load()?;
    // Resolve which key to hold before any side effect: a failing Git
    // lookup must not start a daemon, touch GPG, or disturb a hold.
    let (key, key_source) = select_key(key, git_key, &config)?;
    let interval = interval.unwrap_or(config.interval);
    // Reject durations the millisecond IPC/state model cannot carry before
    // touching GPG or starting the daemon: silently truncating them would
    // schedule something the user never asked for.
    let interval_ms = duration_ms(&interval)?;
    let hold_ms = hold_for.map(|d| duration_ms(&d)).transpose()?;
    let gpg = Gpg::detect()?;

    daemon::ensure_running()?;

    // Foreground unlock/ping with normal pinentry behaviour. Only when this
    // succeeds does the daemon start holding the key; on failure the hold is
    // not enabled.
    if let Err(e) = gpg.ping(key.as_deref(), PingMode::Foreground) {
        return Err(Error::Message(format!("{e}; the hold was NOT enabled")));
    }

    // The foreground success is a genuine key use: send its wall-clock
    // moment so the daemon records it as the hold's first successful ping
    // (an immediate `status` then reports it instead of "Last ping: -").
    let activated_at_ms = now_ms();

    let request = Request::On {
        key,
        key_source,
        interval_ms,
        hold_ms,
        activated_at_ms,
    };
    check(ipc::request(&request)?)?;

    match hold_for {
        Some(d) => presentation::enabled_for(
            &humantime::format_duration(d).to_string(),
        ),
        None => presentation::enabled_indefinitely(),
    }
    Ok(())
}

/// Choose the key selector and its source.
///
/// Precedence: `--key` > `--git-key` > config `key` > config `git_key` >
/// GnuPG's default selection. Git is only ever consulted in explicit
/// Git-key mode, and the daemon receives the already-resolved selector.
fn select_key(
    cli_key: Option<String>,
    cli_git: bool,
    config: &Config,
) -> Result<(Option<String>, KeySource)> {
    if let Some(key) = cli_key {
        return Ok((Some(key), KeySource::Explicit));
    }
    if cli_git {
        return Ok((Some(git::signing_key()?), KeySource::Git));
    }
    if let Some(key) = &config.key {
        return Ok((Some(key.clone()), KeySource::Explicit));
    }
    if config.git_key {
        return Ok((Some(git::signing_key()?), KeySource::Git));
    }
    Ok((None, KeySource::Default))
}

fn off() -> Result<()> {
    match daemon::connect() {
        Ok(_) => {
            check(ipc::request(&Request::Off)?)?;
            presentation::disabled();
            Ok(())
        }
        // Nothing is running, so nothing is held: idempotent success.
        Err(Error::DaemonNotRunning) => {
            presentation::disabled();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn status() -> Result<()> {
    match daemon::connect() {
        Err(Error::DaemonNotRunning) => {
            presentation::status_stopped();
            Ok(())
        }
        Err(e) => Err(e),
        Ok(_) => {
            let response = ipc::request(&Request::Status)?;
            check(response.clone())?;
            let data = response.status.ok_or_else(|| {
                Error::Message("daemon returned no status".into())
            })?;
            presentation::print_status(&data);
            Ok(())
        }
    }
}

fn daemon_stop() -> Result<()> {
    match daemon::connect() {
        Ok(_) => {
            check(ipc::request(&Request::Shutdown)?)?;
            presentation::daemon_stopped();
            Ok(())
        }
        Err(Error::DaemonNotRunning) => {
            presentation::daemon_not_running();
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Millisecond form of a parsed duration.
///
/// Rejects durations too large for the daemon's millisecond IPC/state model
/// (with the original duration in the error) instead of truncating them.
fn duration_ms(d: &Duration) -> Result<u64> {
    u64::try_from(d.as_millis()).map_err(|_| Error::Duration {
        value: humantime::format_duration(*d).to_string(),
        reason: "exceeds the largest duration keyhold can schedule".into(),
    })
}

fn check(response: Response) -> Result<()> {
    if response.ok {
        Ok(())
    } else {
        Err(Error::Daemon(
            response.error.unwrap_or_else(|| "unknown error".into()),
        ))
    }
}

fn now_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0)
}
