//! `keyhold` binary: CLI dispatch and user-facing output.

use std::{
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use clap::Parser;

use keyhold::{
    activation,
    cli::{Cli, Command, CredentialAction},
    config::{self, Config},
    credential::CredentialStore as _,
    credential::SessionCredentialStore,
    daemon,
    error::{Error, Result},
    git,
    gpg::Gpg,
    ipc::{self, Request, Response},
    presentation,
    state::{CredentialMode, KeySource, StatusData},
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
            store_passphrase,
            no_store_passphrase,
            r#for,
            interval,
        } => on(
            key,
            git_key,
            store_passphrase,
            no_store_passphrase,
            r#for,
            interval,
        ),
        Command::Off => off(),
        Command::Status => status(),
        Command::Credential { action } => match action {
            CredentialAction::Clear => credential_clear(),
        },
        Command::Daemon { stop, background } => {
            if stop {
                daemon_stop()
            } else if background {
                daemon_background()
            } else {
                // Foreground/debugging mode (also the detached entry point).
                daemon::run(Gpg::detect()?)
            }
        }
    }
}

/// Start the daemon detached via the exact path `keyhold on` uses, then
/// return immediately. This only starts the daemon: no hold is enabled,
/// and neither GPG nor pinentry is invoked.
fn daemon_background() -> Result<()> {
    if daemon::ensure_running()? {
        presentation::daemon_started();
    } else {
        presentation::daemon_already_running();
    }
    Ok(())
}

fn on(
    key: Option<String>,
    git_key: bool,
    store_passphrase: bool,
    no_store_passphrase: bool,
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
    // Effective mode: explicit CLI enable/disable > config > built-in
    // default (false). Storage is never the implicit default.
    let store_enabled =
        store_passphrase || (config.store_passphrase && !no_store_passphrase);

    let gpg = Gpg::detect()?;

    daemon::ensure_running()?;

    // The activation flow performs the foreground key use (and, in
    // stored mode, the credential/epoch dance) before anything is
    // enabled; on failure the hold is not enabled.
    let prepared = activation::activate(
        &gpg,
        store_enabled,
        key.as_deref(),
        interval,
        hold_for,
        &SessionCredentialStore,
        &keyhold::credential::prompt_passphrase,
    )?;

    // The foreground success is a genuine key use: send its wall-clock
    // moment so the daemon records it as the hold's first successful ping
    // (an immediate `status` then reports it instead of "Last ping: -").
    let activated_at_ms = now_ms();

    let request = match activation_request(
        key,
        key_source,
        interval_ms,
        hold_ms,
        activated_at_ms,
        &prepared,
    ) {
        Ok(request) => request,
        Err(e) => {
            return finish_activation_handoff(
                ActivationHandoff::NotDelivered(e),
                &prepared,
                &SessionCredentialStore,
            );
        }
    };
    let handoff = match daemon::connect() {
        Ok(stream) => match ipc::request_on_stream(&stream, &request) {
            Ok(response) => ActivationHandoff::Response(response),
            Err(e) => ActivationHandoff::Ambiguous(e),
        },
        Err(e) => ActivationHandoff::NotDelivered(e),
    };
    finish_activation_handoff(handoff, &prepared, &SessionCredentialStore)?;

    for warning in &prepared.warnings {
        presentation::warning(warning);
    }
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
            let data: StatusData = response.status.ok_or_else(|| {
                Error::Message("daemon returned no status".into())
            })?;
            // Live key/credential state is queried at command time (a
            // snapshot, not a promise), not cached in the daemon.
            let gpg = Gpg::detect().ok();
            presentation::print_status(
                &data,
                key_state_row(&data, gpg.as_ref()),
                credential_row_with(&data, |keygrip| {
                    SessionCredentialStore.contains(keygrip)
                }),
            );
            Ok(())
        }
    }
}

/// The live `Key state` value for the resolved key, when one is
/// resolvable (an active hold, or the retained key of a hold that has
/// since been turned off or expired).
fn key_state_row(data: &StatusData, gpg: Option<&Gpg>) -> Option<String> {
    let keygrip = data.keygrip.as_deref()?;
    let gpg = gpg?;
    let state = gpg.key_state(keygrip).ok()?;
    Some(match state.protection {
        keyhold::gpg::KeyProtection::Passphrase => {
            if state.cached {
                "unlocked".to_string()
            } else {
                "locked".to_string()
            }
        }
        keyhold::gpg::KeyProtection::Clear => "unlocked (unprotected)".into(),
        keyhold::gpg::KeyProtection::Unknown => "unknown".into(),
    })
}

fn credential_row_with(
    data: &StatusData,
    contains: impl FnOnce(&str) -> Result<bool>,
) -> Option<String> {
    let keygrip = data.keygrip.as_deref()?;
    match data.credential_mode {
        CredentialMode::NotNeeded => Some("not needed".into()),
        CredentialMode::Session => match contains(keygrip) {
            Ok(true) => Some("session stored".into()),
            Ok(false) => Some("missing".into()),
            Err(_) => Some("unavailable".into()),
        },
        CredentialMode::None => Some("not in use".into()),
    }
}

/// `keyhold credential clear`: delete keyhold's passphrases from the
/// Secret Service session collection. The GPG cache, the daemon and any
/// active hold are deliberately left untouched.
fn credential_clear() -> Result<()> {
    let removed = SessionCredentialStore.clear_all()?;
    match removed {
        0 => presentation::no_session_credentials(),
        _ => presentation::session_credentials_cleared(),
    }
    // A stored-mode hold keeps running on its existing cache entry, but
    // automatic recovery is gone once that entry disappears.
    if let Ok(response) = ipc::request(&Request::Status)
        && let Some(status) = response.status
        && status.hold_on
        && status.credential_mode == CredentialMode::Session
    {
        presentation::warning(
            "an active hold still uses the existing GPG cache entry, but \
             automatic recovery is no longer available once it expires; \
             the next --store-passphrase activation will prompt again",
        );
    }
    Ok(())
}

fn daemon_stop() -> Result<()> {
    match daemon::connect() {
        Ok(probe) => {
            // Do not keep an idle admitted connection alive while asking the
            // daemon to drain its handlers.
            drop(probe);
            check(ipc::request(&Request::Shutdown)?)?;
            // The ACK confirms acceptance. Success is not reported until the
            // daemon has finished cleanup and removed its socket.
            daemon::wait_until_stopped()?;
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

fn activation_request(
    key: Option<String>,
    key_source: KeySource,
    interval_ms: u64,
    hold_ms: Option<u64>,
    activated_at_ms: u64,
    prepared: &activation::Prepared,
) -> Result<Request> {
    Ok(Request::On {
        key,
        key_source,
        interval_ms,
        hold_ms,
        activated_at_ms,
        fingerprint: prepared.target.as_ref().map(|t| t.fingerprint.clone()),
        keygrip: prepared.target.as_ref().and_then(|t| t.keygrip.clone()),
        credential_mode: prepared
            .cache
            .map(|cache| cache.mode)
            .unwrap_or_default(),
        default_cache_ttl_ms: prepared
            .cache
            .map(|cache| duration_ms(&cache.default_ttl))
            .transpose()?,
        max_cache_ttl_ms: prepared
            .cache
            .map(|cache| duration_ms(&cache.max_ttl))
            .transpose()?,
        cache_started_at_ms: prepared
            .cache
            .and_then(|cache| cache.started_wall)
            .and_then(epoch_ms),
    })
}

enum ActivationHandoff {
    Response(Response),
    NotDelivered(Error),
    Ambiguous(Error),
}

/// Complete activation handoff and undo only this activation's credential
/// mutation when the daemon definitely did not apply the request.
fn finish_activation_handoff(
    handoff: ActivationHandoff,
    prepared: &activation::Prepared,
    store: &dyn keyhold::credential::CredentialStore,
) -> Result<()> {
    let handoff_error = match handoff {
        ActivationHandoff::Response(response) => match check(response) {
            Ok(()) => return Ok(()),
            Err(e) => e,
        },
        ActivationHandoff::NotDelivered(e) => e,
        // Once connected, an I/O or protocol failure may mean the request
        // was applied and only the response was lost. Preserve the item so
        // a potentially active session-mode hold retains its recovery secret.
        ActivationHandoff::Ambiguous(e) => return Err(e),
    };

    if !prepared.credential_mutated {
        return Err(handoff_error);
    }
    let Some(keygrip) = prepared
        .target
        .as_ref()
        .and_then(|target| target.keygrip.as_deref())
    else {
        return Err(Error::Message(format!(
            "{handoff_error}; the hold was NOT enabled; rollback of the newly \
             stored session credential failed: no keygrip was available"
        )));
    };
    store.delete(keygrip).map_err(|rollback_error| {
        Error::Message(format!(
            "{handoff_error}; the hold was NOT enabled; rollback of the newly \
             stored session credential failed: {rollback_error}"
        ))
    })?;
    Err(handoff_error)
}

fn now_ms() -> u64 {
    epoch_ms(SystemTime::now()).unwrap_or(0)
}

fn epoch_ms(t: SystemTime) -> Option<u64> {
    u64::try_from(t.duration_since(UNIX_EPOCH).ok()?.as_millis()).ok()
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, sync::Mutex};

    use super::*;
    use keyhold::{
        credential::CredentialStore, gpg::SigningTarget, state::CachePlan,
    };
    use zeroize::Zeroizing;

    #[derive(Default)]
    struct Store {
        deleted: Mutex<Vec<String>>,
        fail_delete: bool,
    }

    impl CredentialStore for Store {
        fn load(&self, _: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
            unreachable!()
        }

        fn contains(&self, _: &str) -> Result<bool> {
            unreachable!()
        }

        fn store(&self, _: &SigningTarget, _: &[u8]) -> Result<()> {
            unreachable!()
        }

        fn delete(&self, keygrip: &str) -> Result<bool> {
            self.deleted.lock().unwrap().push(keygrip.into());
            if self.fail_delete {
                Err(Error::SecretService("injected delete failure".into()))
            } else {
                Ok(true)
            }
        }

        fn clear_all(&self) -> Result<usize> {
            unreachable!()
        }
    }

    fn prepared(credential_mutated: bool) -> activation::Prepared {
        activation::Prepared {
            target: Some(SigningTarget {
                fingerprint: "FINGERPRINT".into(),
                keygrip: Some("KEYGRIP".into()),
            }),
            cache: Some(CachePlan {
                mode: CredentialMode::Session,
                default_ttl: Duration::from_secs(10),
                max_ttl: Duration::from_secs(20),
                started_wall: Some(SystemTime::now()),
            }),
            credential_mutated,
            warnings: Vec::new(),
        }
    }

    fn status(hold_on: bool, mode: CredentialMode) -> StatusData {
        StatusData {
            hold_on,
            key: None,
            key_source: KeySource::Default,
            interval_ms: 1,
            remaining_ms: None,
            last_ping_ms: None,
            next_ping_ms: None,
            last_error: None,
            fingerprint: Some("FINGERPRINT".into()),
            keygrip: Some("KEYGRIP".into()),
            credential_mode: mode,
            default_cache_ttl_ms: None,
            max_cache_ttl_ms: None,
            max_expires_at_ms: None,
        }
    }

    #[test]
    fn ordinary_status_never_inspects_the_session_store() {
        for hold_on in [true, false] {
            let calls = Cell::new(0);
            let row = credential_row_with(
                &status(hold_on, CredentialMode::None),
                |_| {
                    calls.set(calls.get() + 1);
                    Ok(true)
                },
            );
            assert_eq!(row.as_deref(), Some("not in use"));
            assert_eq!(calls.get(), 0);
        }
    }

    #[test]
    fn stopped_stored_status_inspects_the_session_store() {
        let calls = Cell::new(0);
        let row = credential_row_with(
            &status(false, CredentialMode::Session),
            |_| {
                calls.set(calls.get() + 1);
                Ok(true)
            },
        );
        assert_eq!(row.as_deref(), Some("session stored"));
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn unavailable_daemon_rolls_back_fresh_credential() {
        let store = Store::default();
        let err = finish_activation_handoff(
            ActivationHandoff::NotDelivered(Error::DaemonNotRunning),
            &prepared(true),
            &store,
        )
        .unwrap_err();
        assert!(matches!(err, Error::DaemonNotRunning));
        assert_eq!(*store.deleted.lock().unwrap(), ["KEYGRIP"]);
    }

    #[test]
    fn any_connection_failure_rolls_back_fresh_credential() {
        let store = Store::default();
        finish_activation_handoff(
            ActivationHandoff::NotDelivered(Error::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "connect denied",
            ))),
            &prepared(true),
            &store,
        )
        .unwrap_err();
        assert_eq!(*store.deleted.lock().unwrap(), ["KEYGRIP"]);
    }

    #[test]
    fn unrepresentable_cache_metadata_is_a_definite_handoff_failure() {
        let store = Store::default();
        let mut prepared = prepared(true);
        prepared.cache.as_mut().unwrap().max_ttl = Duration::MAX;
        let error = activation_request(
            None,
            KeySource::Default,
            1,
            None,
            1,
            &prepared,
        )
        .unwrap_err();

        finish_activation_handoff(
            ActivationHandoff::NotDelivered(error),
            &prepared,
            &store,
        )
        .unwrap_err();
        assert_eq!(*store.deleted.lock().unwrap(), ["KEYGRIP"]);
    }

    #[test]
    fn explicit_rejection_rolls_back_fresh_credential() {
        let store = Store::default();
        let err = finish_activation_handoff(
            ActivationHandoff::Response(Response::err(
                "daemon is shutting down",
            )),
            &prepared(true),
            &store,
        )
        .unwrap_err();
        assert!(err.to_string().contains("daemon is shutting down"));
        assert_eq!(*store.deleted.lock().unwrap(), ["KEYGRIP"]);
    }

    #[test]
    fn explicit_rejection_rolls_back_stale_replacement_credential() {
        let store = Store::default();
        finish_activation_handoff(
            ActivationHandoff::Response(Response::err("invalid hold state")),
            &prepared(true),
            &store,
        )
        .unwrap_err();
        assert_eq!(*store.deleted.lock().unwrap(), ["KEYGRIP"]);
    }

    #[test]
    fn explicit_rejection_preserves_reused_credential() {
        let store = Store::default();
        finish_activation_handoff(
            ActivationHandoff::Response(Response::err(
                "daemon is shutting down",
            )),
            &prepared(false),
            &store,
        )
        .unwrap_err();
        assert!(store.deleted.lock().unwrap().is_empty());
    }

    #[test]
    fn ambiguous_post_delivery_failure_preserves_mutated_credential() {
        let store = Store::default();
        let err = finish_activation_handoff(
            ActivationHandoff::Ambiguous(Error::Ipc(
                "response was lost".into(),
            )),
            &prepared(true),
            &store,
        )
        .unwrap_err();
        assert!(err.to_string().contains("response was lost"));
        assert!(store.deleted.lock().unwrap().is_empty());
    }

    #[test]
    fn rollback_failure_reports_handoff_and_delete_errors() {
        let store = Store {
            fail_delete: true,
            ..Store::default()
        };
        let err = finish_activation_handoff(
            ActivationHandoff::NotDelivered(Error::DaemonNotRunning),
            &prepared(true),
            &store,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("keyhold daemon is not running"), "{err}");
        assert!(err.contains("the hold was NOT enabled"), "{err}");
        assert!(err.contains("injected delete failure"), "{err}");
    }
}
