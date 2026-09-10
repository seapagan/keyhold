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
    path::PathBuf,
    process::{Command, Stdio},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant, SystemTime},
};

use crate::{
    error::{Error, Result},
    gpg::{Gpg, PingMode},
    ipc::{self, Request, Response},
    state::{Action, Hold},
};

/// How long `keyhold on` waits for a freshly spawned daemon to answer.
const START_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the daemon waits for a client to send its request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

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
    spawn_detached()?;
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
/// terminal and never touches a TTY.
// The only `unsafe` in the crate lives in this function; see the SAFETY note.
#[allow(unsafe_code)]
fn spawn_detached() -> Result<()> {
    use std::os::unix::process::CommandExt;

    let exe = std::env::current_exe()?;
    let mut cmd = Command::new(exe);
    cmd.arg("daemon")
        .current_dir("/")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // The daemon re-detects gpg itself, but runs with cwd "/": hand it an
    // absolute KEYHOLD_GPG so relative overrides keep working.
    if let Some(spec) = std::env::var_os(crate::gpg::GPG_ENV) {
        let path = PathBuf::from(&spec);
        if !path.is_absolute()
            && let Ok(cwd) = std::env::current_dir()
        {
            cmd.env(crate::gpg::GPG_ENV, cwd.join(path));
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

/// Run the daemon until a `shutdown` IPC request arrives.
///
/// Returns cleanly after removing the socket file.
pub fn run(gpg: Gpg) -> Result<()> {
    let paths = paths()?;
    let listener = bind(&paths)?;
    let pair: Pair = Arc::new((
        Mutex::new(Shared {
            hold: Hold::default(),
            shutdown: false,
        }),
        Condvar::new(),
    ));

    let accept_pair = Arc::clone(&pair);
    thread::Builder::new()
        .name("keyhold-accept".into())
        .spawn(move || accept_loop(listener, accept_pair))?;

    scheduler(&pair, &gpg);

    let _ = fs::remove_file(&paths.sock);
    Ok(())
}

/// Bind the daemon socket, recovering from stale socket files and refusing to
/// start when another daemon is live.
fn bind(paths: &Paths) -> Result<UnixListener> {
    fs::create_dir_all(&paths.dir)?;
    for _ in 0..3 {
        if paths.sock.exists() && UnixStream::connect(&paths.sock).is_ok() {
            return Err(Error::Daemon(
                "another keyhold daemon is already running".into(),
            ));
        }
        let _ = fs::remove_file(&paths.sock);
        match UnixListener::bind(&paths.sock) {
            Ok(listener) => {
                // Belt and braces: XDG_RUNTIME_DIR is already 0700 per spec.
                let _ = fs::set_permissions(
                    &paths.sock,
                    fs::Permissions::from_mode(0o700),
                );
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
        if let Ok(stream) = stream {
            let pair = Arc::clone(&pair);
            let _ = thread::Builder::new()
                .name("keyhold-conn".into())
                .spawn(move || handle(stream, pair));
        }
        if lock(&pair).shutdown {
            return;
        }
    }
}

fn handle(stream: UnixStream, pair: Pair) {
    let _ = stream.set_read_timeout(Some(REQUEST_TIMEOUT));
    let _ = stream.set_write_timeout(Some(REQUEST_TIMEOUT));
    let response = match ipc::read_request(&stream) {
        // Client disconnected without sending anything: nothing to do.
        Ok(None) => return,
        Ok(Some(request)) => apply(request, &pair),
        Err(e) => Response::err(e.to_string()),
    };
    let _ = ipc::write_response(&stream, &response);
}

fn apply(request: Request, pair: &Pair) -> Response {
    let mut shared = lock(pair);
    match request {
        Request::Ping => Response::ok(),
        Request::On {
            key,
            interval_ms,
            hold_ms,
        } => {
            if interval_ms == 0 {
                return Response::err("interval must be greater than zero");
            }
            shared.hold.turn_on(
                key,
                Duration::from_millis(interval_ms),
                hold_ms.map(Duration::from_millis),
                Instant::now(),
            );
            pair.1.notify_all();
            Response::ok()
        }
        Request::Off => {
            shared.hold.turn_off();
            shared.hold.clear_error();
            pair.1.notify_all();
            Response::ok()
        }
        Request::Status => Response::with_status(shared.hold.status()),
        Request::Shutdown => {
            shared.shutdown = true;
            pair.1.notify_all();
            Response::ok()
        }
    }
}

/// The keepalive scheduler.
///
/// Sleeps on the condvar until the next ping or deadline (or an IPC wake-up),
/// then acts. Pings run outside the shared lock; their results are applied
/// only if no `on`/`off` transition happened meanwhile (generation check).
fn scheduler(pair: &Pair, gpg: &Gpg) {
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
                    Some(wake) => {
                        wake.saturating_duration_since(now)
                            + Duration::from_millis(1)
                    }
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
                let (generation, key) = {
                    let shared = lock(pair);
                    (shared.hold.generation, shared.hold.key.clone())
                };
                let result = gpg.ping(key.as_deref(), PingMode::Background);
                let mut shared = lock(pair);
                if shared.hold.generation == generation && shared.hold.enabled
                {
                    match result {
                        Ok(()) => shared
                            .hold
                            .record_ping_ok(Instant::now(), SystemTime::now()),
                        Err(e) => {
                            shared.hold.record_ping_failure(e.to_string())
                        }
                    }
                }
            }
        }
    }
}
