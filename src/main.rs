//! `keyhold` binary: CLI dispatch and user-facing output.

use std::{
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;

use keyhold::{
    cli::{Cli, Command},
    config, daemon,
    error::{Error, Result},
    gpg::{Gpg, PingMode},
    ipc::{self, Request, Response},
    state::StatusData,
};

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("keyhold: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Command) -> Result<()> {
    match command {
        Command::On {
            key,
            r#for,
            interval,
        } => on(key, r#for, interval),
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
    hold_for: Option<Duration>,
    interval: Option<Duration>,
) -> Result<()> {
    let config = config::load()?;
    let key = key.or(config.key);
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
        interval_ms,
        hold_ms,
        activated_at_ms,
    };
    check(ipc::request(&request)?)?;

    match hold_for {
        Some(d) => {
            println!("Keyhold enabled for {}.", humantime::format_duration(d))
        }
        None => println!("Keyhold enabled (no expiry)."),
    }
    Ok(())
}

fn off() -> Result<()> {
    match daemon::connect() {
        Ok(_) => {
            check(ipc::request(&Request::Off)?)?;
            println!("Keyhold disabled.");
            Ok(())
        }
        // Nothing is running, so nothing is held: idempotent success.
        Err(Error::DaemonNotRunning) => {
            println!("Keyhold disabled.");
            Ok(())
        }
        Err(e) => Err(e),
    }
}

fn status() -> Result<()> {
    match daemon::connect() {
        Err(Error::DaemonNotRunning) => {
            println!("Daemon: stopped");
            println!("Hold:   off");
            Ok(())
        }
        Err(e) => Err(e),
        Ok(_) => {
            let response = ipc::request(&Request::Status)?;
            check(response.clone())?;
            let data = response.status.ok_or_else(|| {
                Error::Message("daemon returned no status".into())
            })?;
            print_status(&data);
            Ok(())
        }
    }
}

fn daemon_stop() -> Result<()> {
    match daemon::connect() {
        Ok(_) => {
            check(ipc::request(&Request::Shutdown)?)?;
            println!("Daemon stopped.");
            Ok(())
        }
        Err(Error::DaemonNotRunning) => {
            println!("Daemon not running.");
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

fn print_status(data: &StatusData) {
    println!("Daemon: running");
    println!("Hold:   {}", if data.hold_on { "on" } else { "off" });
    if data.hold_on {
        println!("Key:    {}", data.key.as_deref().unwrap_or("default"));
        println!(
            "Interval: {}",
            humantime::format_duration(Duration::from_millis(
                data.interval_ms
            ))
        );
        match data.remaining_ms {
            Some(ms) => println!(
                "Expires: in {}",
                humantime::format_duration(Duration::from_millis(ms))
            ),
            None => println!("Expires: never"),
        }
        let now = now_ms();
        match data.last_ping_ms {
            Some(ms) => println!(
                "Last ping: {} ago",
                humantime::format_duration(Duration::from_millis(
                    now.saturating_sub(ms)
                ))
            ),
            None => println!("Last ping: -"),
        }
        if let Some(ms) = data.next_ping_ms {
            println!(
                "Next ping: in {}",
                humantime::format_duration(Duration::from_millis(
                    ms.saturating_sub(now)
                ))
            );
        }
    }
    if let Some(err) = &data.last_error {
        println!("Error: {err}");
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
