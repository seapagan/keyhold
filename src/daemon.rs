//! The resident daemon: a per-user Unix-socket IPC server plus the keepalive
//! scheduler.
//!
//! One instance per user, auto-started detached by `keyhold on` or run in the
//! foreground via `keyhold daemon`. The daemon holds no GPG credentials and
//! keeps no state across restarts: a fresh daemon starts with the hold off.
//!
//! Concurrency model: one thread per connection (connections are one
//! request/response), a scheduler thread that sleeps on a condvar until the
//! next ping/deadline or an IPC wake-up. Background pings run outside the
//! shared lock so `status` stays responsive, and a generation counter
//! discards ping results that raced an `on`/`off` transition.

use std::{
    fs, io,
    os::unix::{
        fs::PermissionsExt,
        net::{UnixListener, UnixStream},
    },
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use crate::{
    config::ShutdownPolicies,
    credential::CredentialStore,
    error::{Error, Result},
    gpg::{Gpg, PingMode, SigningTarget},
    ipc::{self, Request, Response},
    state::{Action, Activation, CachePlan, CredentialMode, Hold},
};
use signal_hook::{
    consts::{SIGINT, SIGTERM},
    iterator::Signals,
};

/// How long `keyhold on` and `keyhold daemon --background` wait for a
/// freshly spawned daemon to answer.
const START_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the daemon waits for a client to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the accept loop waits before retrying after a failed `accept`,
/// so a persistent error (e.g. `EMFILE`) degrades to a slow poll instead
/// of a busy spin.
const ACCEPT_RETRY_DELAY: Duration = Duration::from_millis(100);

/// Locations of the daemon's per-user runtime files.
#[derive(Debug, Clone)]
pub struct Paths {
    /// `$XDG_RUNTIME_DIR/keyhold`
    pub dir: PathBuf,
    /// `$XDG_RUNTIME_DIR/keyhold/keyhold.sock`
    pub sock: PathBuf,
}

/// Resolve runtime paths from `$XDG_RUNTIME_DIR`.
pub fn paths() -> Result<Paths> {
    let Some(base) = std::env::var_os("XDG_RUNTIME_DIR") else {
        return Err(Error::NoRuntimeDir);
    };
    let base = PathBuf::from(base);
    if !base.is_absolute() {
        return Err(Error::NoRuntimeDir);
    }
    let dir = base.join("keyhold");
    Ok(Paths {
        sock: dir.join("keyhold.sock"),
        dir,
    })
}

/// Connect to the daemon socket, mapping "nothing there" (absent socket,
/// stale socket) to [`Error::DaemonNotRunning`].
pub fn connect() -> Result<UnixStream> {
    let paths = paths()?;
    match UnixStream::connect(&paths.sock) {
        Ok(stream) => Ok(stream),
        Err(e)
            if matches!(
                e.kind(),
                io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
            ) =>
        {
            Err(Error::DaemonNotRunning)
        }
        Err(e) => Err(e.into()),
    }
}

/// Ensure a daemon is reachable, starting a detached one if needed.
///
/// Returns `true` when a new daemon was started.
pub fn ensure_running() -> Result<bool> {
    match connect() {
        Ok(_) => return Ok(false),
        Err(Error::DaemonNotRunning) => {}
        // Anything else (e.g. no $XDG_RUNTIME_DIR) is a real error: report
        // it instead of pointlessly trying to start a daemon.
        Err(e) => return Err(e),
    }
    start_background()?;
    let deadline = Instant::now() + START_TIMEOUT;
    while Instant::now() < deadline {
        if connect().is_ok() {
            return Ok(true);
        }
        thread::sleep(Duration::from_millis(25));
    }
    Err(Error::DaemonStart)
}

/// Start a detached daemon: `setsid` + exec of `keyhold daemon` with all
/// standard streams pointed at `/dev/null`, so it survives the invoking
/// terminal and never touches a TTY. This is the one detached-start path,
/// shared by `keyhold on` and `keyhold daemon --background`.
// The only `unsafe` in the crate lives in this function; see the SAFETY note.
#[allow(unsafe_code)]
fn start_background() -> Result<()> {
    use std::os::unix::process::CommandExt;

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("daemon")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The daemon re-detects the gpg tools itself, but runs with cwd "/":
    // hand it absolute overrides so relative paths keep working.
    for env_key in [
        crate::gpg::GPG_ENV,
        crate::gpg::GPGCONF_ENV,
        crate::gpg::CONNECT_AGENT_ENV,
    ] {
        if let Some(spec) = std::env::var_os(env_key) {
            let path = PathBuf::from(&spec);
            if !path.is_absolute()
                && let Ok(cwd) = std::env::current_dir()
            {
                cmd.env(env_key, cwd.join(path));
            }
        }
    }
    // SAFETY: the closure runs in the child between fork and exec and must be
    // async-signal-safe. `setsid` is async-signal-safe, and the closure makes
    // no allocations, takes no locks and calls nothing else. Detaching into a
    // new session is what makes the daemon immune to terminal exit. A
    // setsid failure surfaces to the parent as a normal `io::Error`.
    unsafe {
        cmd.pre_exec(|| match libc::setsid() {
            -1 => Err(io::Error::last_os_error()),
            _ => Ok(()),
        });
    }
    cmd.spawn()?;
    Ok(())
}

/// Run the daemon until a `shutdown` IPC request or a termination signal
/// arrives.
///
/// Loads the user configuration for the shutdown policies and uses the
/// real Secret Service session store.
///
/// Returns cleanly after removing the socket file.
pub fn run(gpg: Gpg) -> Result<()> {
    let config = crate::config::load()?;
    run_with(
        &paths()?,
        gpg,
        Arc::new(crate::credential::SessionCredentialStore),
        config.shutdown_policies(),
    )
}

/// The testable daemon entry point: explicit runtime paths, credential
/// store and shutdown policies.
///
/// Clean shutdown (a `shutdown` IPC request, SIGTERM, or SIGINT on a
/// foreground daemon) removes the socket and then runs the configured
/// [`ShutdownPolicies`] synchronously: optionally delete keyhold's
/// Secret Service session items, then optionally clear the active key's
/// GPG cache entry. Cleanup failures are reported to stderr and never
/// prevent the rest of shutdown; no guarantee exists for SIGKILL,
/// crashes or power loss.
pub fn run_with(
    paths: &Paths,
    gpg: Gpg,
    store: Arc<dyn CredentialStore>,
    policies: ShutdownPolicies,
) -> Result<()> {
    let listener = bind(paths)?;
    let services = Arc::new(Services { gpg, store });
    let pair: Pair = Arc::new((
        Mutex::new(Shared {
            hold: Hold::default(),
            shutdown: false,
        }),
        Condvar::new(),
    ));

    // SIGTERM (service managers, plain `kill`) and SIGINT (Ctrl-C on a
    // foreground daemon) run through the same shutdown path as a shutdown
    // IPC request: set the flag, wake the scheduler, and let the loop
    // below remove the socket and exit successfully. The iterator is
    // self-pipe based, so nothing but async-signal-safe bookkeeping ever
    // runs inside a signal handler.
    let mut signals = Signals::new([SIGINT, SIGTERM])?;
    let signal_pair = Arc::clone(&pair);
    thread::Builder::new()
        .name("keyhold-signals".into())
        .spawn(move || {
            if signals.forever().next().is_some() {
                lock(&signal_pair).shutdown = true;
                signal_pair.1.notify_all();
            }
        })?;

    let accept_pair = Arc::clone(&pair);
    thread::Builder::new()
        .name("keyhold-accept".into())
        .spawn(move || accept_loop(listener, accept_pair))?;

    scheduler(&pair, &services);

    // Synchronous cleanup while the process still exists: the policies
    // run after the scheduler stops and before the socket disappears.
    shutdown_cleanup(&services, &policies, &pair);
    let _ = fs::remove_file(&paths.sock);
    Ok(())
}

/// Apply the configured shutdown policies. `keyhold off` never reaches
/// this: only clean daemon shutdown does. Failures are reported, never
/// fatal, and never include secret material.
fn shutdown_cleanup(
    services: &Services,
    policies: &ShutdownPolicies,
    pair: &Pair,
) {
    // The active hold's keygrip: the only cache entry the lock policy
    // may clear. No resolved keygrip means no clearing — never a guess.
    let keygrip = {
        let shared = lock(pair);
        shared
            .hold
            .enabled
            .then(|| shared.hold.keygrip.clone())
            .flatten()
    };
    if policies.clear_secret
        && let Err(e) = services.store.clear_all()
    {
        eprintln!("keyhold: daemon: clearing session credentials failed: {e}");
    }
    if policies.lock_key
        && let Some(keygrip) = keygrip.as_deref()
        && let Err(e) = services.gpg.clear_passphrase(keygrip)
    {
        eprintln!("keyhold: daemon: clearing the GPG cache entry failed: {e}");
    }
}

/// Create the private runtime directory (or accept an existing one) with
/// mode 0700, as documented. Failures are real errors: a runtime directory
/// we could not make private must not silently pass. `$XDG_RUNTIME_DIR`
/// itself is never modified.
fn ensure_private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Bind the daemon socket, recovering from stale socket files and refusing to
/// start when another daemon is live.
fn bind(paths: &Paths) -> Result<UnixListener> {
    ensure_private_dir(&paths.dir)?;
    for _ in 0..3 {
        if paths.sock.exists() && UnixStream::connect(&paths.sock).is_ok() {
            return Err(Error::Daemon(
                "another keyhold daemon is already running".into(),
            ));
        }
        let _ = fs::remove_file(&paths.sock);
        match UnixListener::bind(&paths.sock) {
            Ok(listener) => {
                // Belt and braces: the umask could otherwise loosen the
                // socket's mode below the documented 0700.
                fs::set_permissions(
                    &paths.sock,
                    fs::Permissions::from_mode(0o700),
                )?;
                return Ok(listener);
            }
            // Someone else bound the socket between our probe and bind:
            // loop and detect the live daemon.
            Err(e) if e.kind() == io::ErrorKind::AddrInUse => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(Error::Daemon("could not bind the daemon socket".into()))
}

/// Runtime services the scheduler needs: GPG tooling and the session
/// credential store. Injected as a whole so tests can supply fakes, and
/// never part of `Hold` state.
struct Services {
    gpg: Gpg,
    store: Arc<dyn CredentialStore>,
}

type Pair = Arc<(Mutex<Shared>, Condvar)>;

#[derive(Debug)]
struct Shared {
    hold: Hold,
    shutdown: bool,
}

fn lock(pair: &Pair) -> MutexGuard<'_, Shared> {
    pair.0
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn accept_loop(listener: UnixListener, pair: Pair) {
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let pair = Arc::clone(&pair);
                let _ = thread::Builder::new()
                    .name("keyhold-conn".into())
                    .spawn(move || handle(stream, pair));
            }
            // A failing `accept` must not busy-spin the loop: report it
            // and pause before the next attempt.
            Err(e) => {
                eprintln!(
                    "keyhold: daemon: accepting a connection failed: {e}"
                );
                thread::sleep(ACCEPT_RETRY_DELAY);
            }
        }
        if lock(&pair).shutdown {
            return;
        }
    }
}

fn handle(stream: UnixStream, pair: Pair) {
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
    let (response, shutdown) = match ipc::read_request(&stream) {
        // Client disconnected without sending anything: nothing to do.
        Ok(None) => return,
        Ok(Some(request)) => apply(request, &pair),
        Err(e) => (Response::err(e.to_string()), false),
    };
    // A shutdown request may only take effect once its acknowledgement has
    // been handed to the socket: after a successful write and flush the
    // client can read the response even if the daemon exits immediately
    // afterwards, and setting the flag before the write would reintroduce
    // the exit-before-ack race. If the client already vanished, delivery is
    // impossible over the broken socket: report the I/O error instead of
    // silently discarding it, then still honour the already-valid shutdown
    // request — there is nobody left to answer to.
    if let Err(e) = ipc::write_response(&stream, &response) {
        eprintln!("keyhold: daemon: writing response failed: {e}");
    }
    if shutdown {
        lock(&pair).shutdown = true;
        pair.1.notify_all();
    }
}

/// Apply one request, returning the response to send and whether the daemon
/// should shut down once that response has been acknowledged.
fn apply(request: Request, pair: &Pair) -> (Response, bool) {
    let mut shared = lock(pair);
    match request {
        Request::Ping => (Response::ok(), false),
        Request::On {
            key,
            key_source,
            interval_ms,
            hold_ms,
            activated_at_ms,
            fingerprint,
            keygrip,
            credential_mode,
            default_cache_ttl_ms,
            max_cache_ttl_ms,
            cache_started_at_ms,
        } => {
            if interval_ms == 0 {
                return (
                    Response::err("interval must be greater than zero"),
                    false,
                );
            }
            // The client sends the wall-clock moment of the successful
            // foreground key use; it becomes the hold's first recorded ping.
            // IPC values are untrusted: timestamps that cannot be
            // represented, or timings that cannot be scheduled, are normal
            // protocol errors — never a panic.
            let Some(activated) =
                UNIX_EPOCH.checked_add(Duration::from_millis(activated_at_ms))
            else {
                return (
                    Response::err("activation timestamp is out of range"),
                    false,
                );
            };
            // Session mode promises proactive renewal: it is only valid
            // with the full metadata needed to schedule it.
            if credential_mode == CredentialMode::Session
                && (keygrip.as_deref().is_none_or(str::is_empty)
                    || max_cache_ttl_ms.is_none()
                    || cache_started_at_ms.is_none())
            {
                return (
                    Response::err(
                        "session mode requires a keygrip, max cache TTL \
                         and a known cache epoch",
                    ),
                    false,
                );
            }
            let cache = match (credential_mode, max_cache_ttl_ms) {
                (CredentialMode::None, _) | (CredentialMode::NotNeeded, _)
                    if max_cache_ttl_ms.is_none() =>
                {
                    None
                }
                (_, Some(max_ms)) => {
                    let started = cache_started_at_ms.and_then(|ms| {
                        UNIX_EPOCH.checked_add(Duration::from_millis(ms))
                    });
                    Some(CachePlan {
                        mode: credential_mode,
                        default_ttl: Duration::from_millis(
                            default_cache_ttl_ms.unwrap_or(max_ms),
                        ),
                        max_ttl: Duration::from_millis(max_ms),
                        started_wall: started,
                    })
                }
                // A non-session mode with TTLs but no epoch still tracks
                // policy values for status display.
                _ => Some(CachePlan {
                    mode: credential_mode,
                    default_ttl: Duration::from_millis(
                        default_cache_ttl_ms.unwrap_or(0),
                    ),
                    max_ttl: Duration::from_millis(
                        max_cache_ttl_ms.unwrap_or(0),
                    ),
                    started_wall: None,
                }),
            };
            let target = fingerprint.map(|fingerprint| SigningTarget {
                fingerprint,
                keygrip: keygrip.clone(),
            });
            match shared.hold.turn_on(
                key,
                key_source,
                Duration::from_millis(interval_ms),
                hold_ms.map(Duration::from_millis),
                Instant::now(),
                activated,
                Activation {
                    target: target.as_ref(),
                    cache,
                },
            ) {
                Ok(()) => {
                    pair.1.notify_all();
                    (Response::ok(), false)
                }
                Err(reason) => (Response::err(reason), false),
            }
        }
        Request::Off => {
            shared.hold.turn_off();
            shared.hold.clear_error();
            pair.1.notify_all();
            (Response::ok(), false)
        }
        Request::Status => {
            (Response::with_status(shared.hold.status()), false)
        }
        // The flag itself is set by `handle` after the acknowledgement is
        // written; setting it here would let the scheduler exit first.
        Request::Shutdown => (Response::ok(), true),
    }
}

/// The keepalive scheduler.
///
/// Sleeps on the condvar until the next ping, renewal or deadline (or an
/// IPC wake-up), then acts. All GPG/Secret Service work runs outside the
/// shared lock; results are applied only if no `on`/`off` transition
/// happened meanwhile (generation check).
fn scheduler(pair: &Pair, services: &Services) {
    loop {
        let action = {
            let mut shared = lock(pair);
            loop {
                if shared.shutdown {
                    return;
                }
                let now = Instant::now();
                if let Some(action) = shared.hold.due_action(now) {
                    break action;
                }
                let timeout = match shared.hold.next_wake(now) {
                    Some(wake) => wake
                        .saturating_duration_since(now)
                        .saturating_add(Duration::from_millis(1)),
                    None => {
                        // Nothing scheduled: sleep until an IPC wake-up.
                        shared = pair
                            .1
                            .wait(shared)
                            .unwrap_or_else(|poisoned| poisoned.into_inner());
                        continue;
                    }
                };
                let (guard, _) = pair
                    .1
                    .wait_timeout(shared, timeout)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                shared = guard;
            }
        };

        match action {
            Action::Expire => lock(pair).hold.turn_off(),
            Action::Ping => {
                let snapshot = snapshot(pair);
                let mut result = ping(&services.gpg, &snapshot);
                // A stored-mode ping that failed before its scheduled
                // renewal (agent restart, external clear, race) gets
                // exactly one recovery attempt from the session
                // credential. Normal mode keeps today's behaviour.
                if result.is_err()
                    && snapshot.credential_mode == CredentialMode::Session
                {
                    result = renew_once(services, &snapshot).map_err(|e| {
                        Error::Message(format!(
                            "keepalive failed and session-credential \
                             recovery failed: {e}"
                        ))
                    });
                }
                apply_ping_result(pair, snapshot.generation, result);
            }
            Action::Renew => {
                let snapshot = snapshot(pair);
                let result = renew_once(services, &snapshot);
                let mut shared = lock(pair);
                if shared.hold.generation == snapshot.generation
                    && shared.hold.enabled
                {
                    match result {
                        Ok(()) => shared
                            .hold
                            .record_renewal(Instant::now(), SystemTime::now()),
                        Err(e) => {
                            shared.hold.record_ping_failure(e.to_string())
                        }
                    }
                }
            }
        }
    }
}

/// Everything a background operation needs from the hold, captured
/// under one lock and used outside it.
#[derive(Debug, Clone)]
struct HoldSnapshot {
    generation: u64,
    key: Option<String>,
    fingerprint: Option<String>,
    keygrip: Option<String>,
    credential_mode: CredentialMode,
}

fn snapshot(pair: &Pair) -> HoldSnapshot {
    let shared = lock(pair);
    HoldSnapshot {
        generation: shared.hold.generation,
        key: shared.hold.key.clone(),
        fingerprint: shared.hold.fingerprint.clone(),
        keygrip: shared.hold.keygrip.clone(),
        credential_mode: shared.hold.credential_mode,
    }
}

/// The stored-mode recreate sequence, shared by proactive renewal and
/// ping-failure recovery: retrieve the session credential **before**
/// touching the GPG cache, clear only this keygrip's normal entry, then
/// unlock with an exact loopback sign. The credential is zeroized when
/// this function returns.
fn renew_once(services: &Services, snapshot: &HoldSnapshot) -> Result<()> {
    let Some(keygrip) = snapshot.keygrip.as_deref() else {
        return Err(Error::Message("the hold has no resolved keygrip".into()));
    };
    let Some(target) = exact_target(snapshot) else {
        return Err(Error::Message(
            "the hold has no resolved signing key".into(),
        ));
    };
    // Retrieve before clear: a Secret Service outage must not lock a
    // currently usable key.
    let secret = services.store.load(keygrip)?.ok_or_else(|| {
        Error::Message(
            "session credential is no longer available; \
             stored-mode hold stopped"
                .into(),
        )
    })?;
    services.gpg.clear_passphrase(keygrip)?;
    let unlocked = services.gpg.use_key_with_passphrase(&target, &secret);
    drop(secret);
    unlocked
}

/// One background keepalive, using the resolved exact signing target
/// when known (falling back to the original selector).
fn ping(gpg: &Gpg, snapshot: &HoldSnapshot) -> Result<()> {
    let exact = snapshot.fingerprint.as_ref().map(|fpr| format!("{fpr}!"));
    let selector = exact.as_deref().or(snapshot.key.as_deref());
    gpg.use_key(selector, PingMode::Background).map(|_| ())
}

fn exact_target(snapshot: &HoldSnapshot) -> Option<SigningTarget> {
    snapshot
        .fingerprint
        .as_ref()
        .map(|fingerprint| SigningTarget {
            fingerprint: fingerprint.clone(),
            keygrip: snapshot.keygrip.clone(),
        })
}

/// Apply a ping outcome under the lock, discarding races.
fn apply_ping_result(pair: &Pair, generation: u64, result: Result<()>) {
    let mut shared = lock(pair);
    if shared.hold.generation == generation && shared.hold.enabled {
        match result {
            Ok(()) => shared
                .hold
                .record_ping_ok(Instant::now(), SystemTime::now()),
            Err(e) => shared.hold.record_ping_failure(e.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode_of(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn runtime_dir_is_created_private() {
        let base = tempfile::TempDir::new().unwrap();
        let dir = base.path().join("keyhold");
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn existing_runtime_dir_mode_is_tightened() {
        let base = tempfile::TempDir::new().unwrap();
        let dir = base.path().join("keyhold");
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        ensure_private_dir(&dir).unwrap();
        assert_eq!(mode_of(&dir), 0o700);
    }

    #[test]
    fn parent_directory_mode_is_left_alone() {
        let base = tempfile::TempDir::new().unwrap();
        fs::set_permissions(base.path(), fs::Permissions::from_mode(0o755))
            .unwrap();
        ensure_private_dir(&base.path().join("keyhold")).unwrap();
        assert_eq!(mode_of(base.path()), 0o755);
    }
}
