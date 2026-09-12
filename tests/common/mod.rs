// Each test binary includes only part of this module's API.
#![allow(dead_code)]

//! Shared helpers for integration tests: isolated runtime/config directories
//! plus immutable checked-in fake `gpg`/`gpgconf`/`gpg-connect-agent`
//! executables driven by marker files under a per-test scratch directory.
//!
//! The executables must remain static. Creating or rewriting executable files
//! in a multithreaded Rust test process can let a concurrently forked child
//! transiently inherit a writable descriptor; Linux may then reject exec with
//! `ETXTBSY` (`Text file busy`). Separate temporary directories do not prevent
//! that process-wide race. Each Keyhold child or [`Gpg`] instance therefore
//! receives only the non-secret `KEYHOLD_TEST_ROOT` path for its own mutable
//! state. This avoids both runtime executable creation and process-global
//! environment mutation. Passphrases remain files under that root and are
//! supplied to fake gpg through stdin, never argv or the environment.
//!
//! The fake gpg logs every invocation and can be told to fail all pings
//! (`fail_all`), only background pings (`fail_bg`, detected by the
//! `cancel` argument the daemon passes), or slow background pings
//! (`slow_bg`). With the `rich` marker it additionally emits a real
//! `--status-fd` stream (`SIG_CREATED` naming the configured signing
//! fingerprint, `PINENTRY_LAUNCHED` unless the `cached` marker suppresses
//! it), answers `--list-secret-keys` from a fixture file, and validates
//! loopback passphrases read from stdin against a file — never logging
//! the stdin secret. The fake gpgconf reports configured TTLs; the fake
//! gpg-connect-agent implements KEYINFO/CLEAR_PASSPHRASE with a command
//! log. Real GPG is never touched, and no test ever contacts a real
//! Secret Service (`DBUS_SESSION_BUS_ADDRESS` points nowhere).

use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

/// Fingerprints/keygrips of the default fake key hierarchy: a primary
/// plus two signing subkeys, the newest of which is GPG's default
/// signing key.
pub const PRIMARY_FPR: &str = "C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48";
pub const PRIMARY_ID: &str = "8FACE96FA6D9DB48";
pub const PRIMARY_GRIP: &str = "554FB2F0C3F74666FEE23A13A628C32C2310EBAF";
pub const SUB_FPR: &str = "54BD088B3AC62D6BC6E4F888212181504E7D2CD7";
pub const SUB_GRIP: &str = "4B88DD924C36F6085738E95FB112B482E33A3220";
pub const SUB2_FPR: &str = "97CF31DBA5F6012341995ED8F3C83A12ADCE45A1";
pub const SUB2_GRIP: &str = "F097020B875D80D64C742456496ECA8F47CED17F";
/// The passphrase the fake gpg accepts in loopback mode.
pub const FAKE_PASSPHRASE: &str = "correct horse battery staple";

/// Default fake agent TTLs (seconds), mirroring GnuPG's compiled-in
/// defaults: 10m idle, 2h hard max.
pub const DEFAULT_TTL_SECS: u64 = 600;
pub const MAX_TTL_SECS: u64 = 7200;

fn fixture_tool(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("gpg-tools")
        .join("unix")
        .join(name)
}

pub struct TestEnv {
    pub runtime: TempDir,
    pub config: TempDir,
    // Holds mutable logs, fixture data, and failure markers; must outlive
    // every spawned keyhold process.
    pub scratch: TempDir,
    pub bin: PathBuf,
    pub gpg: PathBuf,
    pub log: PathBuf,
    pub gpgconf: PathBuf,
    pub connect_agent: PathBuf,
    pub ca_log: PathBuf,
    pub keys_fixture: PathBuf,
    pub ttls: PathBuf,
    fail_all: PathBuf,
    fail_bg: PathBuf,
    slow_bg: PathBuf,
    rich: PathBuf,
    cached: PathBuf,
    lock: PathBuf,
    passphrase: PathBuf,
    key_cached: PathBuf,
    key_prot: PathBuf,
    gpgconf_fail: PathBuf,
}

impl TestEnv {
    pub fn new() -> Self {
        let runtime = TempDir::new().expect("temp runtime dir");
        let config = TempDir::new().expect("temp config dir");
        let scratch = TempDir::new().expect("temp scratch dir");

        let gpg = fixture_tool("fake-gpg");
        let log = scratch.path().join("gpg.log");
        let fail_all = scratch.path().join("fail-all");
        let fail_bg = scratch.path().join("fail-bg");
        let slow_bg = scratch.path().join("slow-bg");
        let rich = scratch.path().join("rich");
        let cached = scratch.path().join("cached");
        let lock = scratch.path().join("lock");
        let passphrase = scratch.path().join("passphrase");

        let gpgconf = fixture_tool("fake-gpgconf");
        let ttls = scratch.path().join("ttls");
        let gpgconf_fail = scratch.path().join("gpgconf-fail");

        let connect_agent = fixture_tool("fake-connect-agent");
        let ca_log = scratch.path().join("ca.log");
        let key_cached = scratch.path().join("key-cached");
        let key_prot = scratch.path().join("prot");

        let keys_fixture = scratch.path().join("keys.txt");
        fs::write(scratch.path().join("status-on-rich"), b"1")
            .expect("write fixture profile marker");

        let env = Self {
            bin: PathBuf::from(env!("CARGO_BIN_EXE_keyhold")),
            gpg,
            log,
            gpgconf,
            connect_agent,
            ca_log,
            keys_fixture,
            ttls,
            fail_all,
            fail_bg,
            slow_bg,
            rich,
            cached,
            lock,
            passphrase,
            key_cached,
            key_prot,
            gpgconf_fail,
            runtime,
            config,
            scratch,
        };
        env.write_keys_fixture(&format!(
            "sec:u:255:22:{PRIMARY_ID}:1789136976:::u:::scSC:::+::ed25519:::0:\n\
             fpr:::::::::{PRIMARY_FPR}:\n\
             grp:::::::::{PRIMARY_GRIP}:\n\
             uid:u::::1789136976::78F8::keyhold-test::::::::::0:\n\
             ssb:u:255:22:212181504E7D2CD7:1789136986::::::s:::+::ed25519::\n\
             fpr:::::::::{SUB_FPR}:\n\
             grp:::::::::{SUB_GRIP}:\n\
             ssb:u:255:22:F3C83A12ADCE45A1:1789137207::::::s:::+::ed25519::\n\
             fpr:::::::::{SUB2_FPR}:\n\
             grp:::::::::{SUB2_GRIP}:\n"
        ));
        env.set_cache_ttls(DEFAULT_TTL_SECS, MAX_TTL_SECS);
        env.set_expected_passphrase(FAKE_PASSPHRASE);
        env
    }

    /// The default secret-key listing fixture.
    fn write_keys_fixture(&self, fixture: &str) {
        fs::write(&self.keys_fixture, fixture).expect("write keys fixture");
    }

    /// Override the secret-key listing fixture.
    pub fn set_keys_fixture(&self, fixture: &str) {
        self.write_keys_fixture(fixture);
    }

    /// Configure the fake agent's TTLs (seconds).
    pub fn set_cache_ttls(&self, default_secs: u64, max_secs: u64) {
        fs::write(&self.ttls, format!("{default_secs} {max_secs}\n"))
            .expect("write ttls");
    }

    /// The passphrase the fake gpg accepts via `--passphrase-fd 0`.
    pub fn set_expected_passphrase(&self, passphrase: &str) {
        fs::write(&self.passphrase, passphrase).expect("write passphrase");
    }

    /// Enable the machine-readable status stream (`SIG_CREATED`,
    /// `PINENTRY_LAUNCHED`, loopback validation, listings).
    pub fn rich_gpg(&self) {
        fs::write(&self.rich, b"1").expect("write rich marker");
    }

    /// Simulate the key being already cached: successful signs omit
    /// `PINENTRY_LAUNCHED`.
    pub fn cached_key(&self) {
        fs::write(&self.cached, b"1").expect("write cached marker");
    }

    /// Simulate a locked key: background (cancel-mode) signs fail with
    /// `Operation cancelled` and a `KEY_CONSIDERED` record.
    pub fn locked_key(&self) {
        fs::write(&self.lock, b"1").expect("write lock marker");
    }

    /// The fake agent's KEYINFO cached flag for the primary/subkey grips.
    pub fn set_key_cached(&self, cached: bool) {
        if cached {
            fs::write(&self.key_cached, b"1").expect("write key-cached");
        } else {
            let _ = fs::remove_file(&self.key_cached);
        }
    }

    /// The fake agent's KEYINFO protection field (`P` or `C`).
    pub fn set_key_protection(&self, protection: &str) {
        fs::write(&self.key_prot, protection).expect("write key-protection");
    }

    /// Make the fake gpgconf fail.
    pub fn fail_gpgconf(&self) {
        fs::write(&self.gpgconf_fail, b"1").expect("write gpgconf-fail");
    }

    /// Make every fake gpg invocation fail.
    pub fn fail_all_pings(&self) {
        fs::write(&self.fail_all, b"1").expect("write fail-all marker");
    }

    /// Make only background (daemon) pings fail, like an expired cache.
    pub fn fail_background_pings(&self) {
        fs::write(&self.fail_bg, b"1").expect("write fail-bg marker");
    }

    /// Make background (daemon) pings take 2s, so keepalives are still
    /// in flight when `off`/`on` transitions happen.
    pub fn slow_background_pings(&self) {
        fs::write(&self.slow_bg, b"1").expect("write slow-bg marker");
    }

    /// Build a `keyhold` command with fully isolated environment. The
    /// bogus `DBUS_SESSION_BUS_ADDRESS` guarantees no test ever reaches
    /// a real Secret Service daemon.
    pub fn keyhold(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args)
            .env("XDG_RUNTIME_DIR", self.runtime.path())
            .env("XDG_CONFIG_HOME", self.config.path())
            .env("KEYHOLD_GPG", &self.gpg)
            .env("KEYHOLD_GPGCONF", &self.gpgconf)
            .env("KEYHOLD_GPG_CONNECT_AGENT", &self.connect_agent)
            .env("KEYHOLD_TEST_ROOT", self.scratch.path())
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                "unix:path=/nonexistent/keyhold-test-bus",
            );
        cmd
    }

    pub fn run(&self, args: &[&str]) -> Output {
        self.keyhold(args).output().expect("run keyhold")
    }

    /// Run and assert success, printing diagnostics on failure.
    pub fn succeed(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(
            out.status.success(),
            "keyhold {args:?} failed: {}\nstdout: {}\nstderr: {}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        );
        out
    }

    /// Run and assert failure.
    pub fn fail(&self, args: &[&str]) -> Output {
        let out = self.run(args);
        assert!(
            !out.status.success(),
            "keyhold {args:?} unexpectedly succeeded:\n{}",
            String::from_utf8_lossy(&out.stdout),
        );
        out
    }

    pub fn stdout(&self, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.run(args).stdout).into_owned()
    }

    pub fn stderr(&self, args: &[&str]) -> String {
        String::from_utf8_lossy(&self.run(args).stderr).into_owned()
    }

    pub fn sock(&self) -> PathBuf {
        self.runtime.path().join("keyhold").join("keyhold.sock")
    }

    pub fn status(&self) -> String {
        self.stdout(&["status"])
    }

    pub fn gpg_log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// The fake gpg-connect-agent command log.
    pub fn ca_log(&self) -> String {
        fs::read_to_string(&self.ca_log).unwrap_or_default()
    }
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        // Best effort: stop any daemon this test started.
        let _ = self.keyhold(&["daemon", "--stop"]).output();
    }
}

/// Poll until `cond` holds, at most `timeout`. Returns false on timeout.
pub fn wait_until(timeout: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if cond() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(25));
    }
}

/// Wait for a status substring (e.g. "Hold:   on").
pub fn wait_for_status(
    env: &TestEnv,
    needle: &str,
    timeout: Duration,
) -> bool {
    wait_until(timeout, || env.status().contains(needle))
}

/// Send one raw newline-framed JSON request over the daemon socket and
/// return the parsed response, for precise protocol-level assertions.
pub fn ipc_request(env: &TestEnv, request: &str) -> Option<serde_json::Value> {
    let mut stream = UnixStream::connect(env.sock()).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    stream.write_all(request.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    // The daemon answers once and closes the connection.
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    serde_json::from_str(response.trim()).ok()
}

/// The daemon's status snapshot via raw IPC (exact fields, no display
/// parsing).
pub fn status_of(env: &TestEnv) -> Option<serde_json::Value> {
    ipc_request(env, "{\"cmd\":\"status\"}")
        .and_then(|v| v.get("status").cloned())
}

/// Wait for a foreground child process to exit, killing it on timeout.
pub fn wait_with_kill(child: &mut std::process::Child, timeout: Duration) {
    if !wait_until(timeout, || matches!(child.try_wait(), Ok(Some(_)))) {
        let _ = child.kill();
        let _ = child.wait();
        panic!("daemon process did not exit within {timeout:?}");
    }
}

// ---------------------------------------------------------------------------
// In-process daemon harness (for stored-mode flows, which need a fake
// credential store injected into `daemon::run_with`).
// ---------------------------------------------------------------------------

use std::{
    collections::HashSet,
    path::Path,
    sync::{Arc, Condvar, Mutex},
};

use keyhold::{
    config::ShutdownPolicies,
    credential::{CredentialStore, CredentialTransactionGuard},
    daemon,
    gpg::{Gpg, SigningTarget},
};
use zeroize::Zeroizing;

/// A stateful fake gpg toolchain using immutable checked-in executables and a
/// per-instance mutable root. The fake agent's cache lifecycle is modelled by
/// a `locked` marker: CLEAR_PASSPHRASE
/// creates it, a successful loopback sign removes it, background
/// (cancel-mode) signs fail while it exists, and KEYINFO reports it.
pub struct DaemonTools {
    pub gpg: Gpg,
    _dir: TempDir,
    pub root: PathBuf,
    pub gpg_log: PathBuf,
    pub ca_log: PathBuf,
}

impl DaemonTools {
    pub fn new() -> Self {
        let dir = TempDir::new().expect("scratch dir");
        let root = dir.path().to_path_buf();
        let gpg_log = root.join("gpg.log");
        let ca_log = root.join("ca.log");
        fs::write(root.join("daemon-tools"), b"1")
            .expect("write fixture profile marker");

        let gpg = Gpg::with_tools(
            fixture_tool("fake-gpg"),
            Some(fixture_tool("fake-gpgconf")),
            Some(fixture_tool("fake-connect-agent")),
        )
        .with_tool_env("KEYHOLD_TEST_ROOT", root.as_os_str());

        let tools = Self {
            gpg,
            _dir: dir,
            gpg_log,
            ca_log,
            root,
        };
        tools.set_keys(&daemon_keys());
        tools.set_ttls(600, 7200);
        tools.set_passphrase(FAKE_PASSPHRASE);
        tools
    }

    pub fn set_keys(&self, fixture: &str) {
        fs::write(self.root.join("keys.txt"), fixture).unwrap();
    }

    pub fn set_ttls(&self, default_secs: u64, max_secs: u64) {
        fs::write(
            self.root.join("ttls"),
            format!("{default_secs} {max_secs}\n"),
        )
        .unwrap();
    }

    pub fn set_passphrase(&self, value: &str) {
        fs::write(self.root.join("passphrase"), value).unwrap();
    }

    /// The fake agent's KEYINFO protection field (`P`, `C`, `-`).
    pub fn set_key_protection(&self, protection: &str) {
        fs::write(self.root.join("prot"), protection).unwrap();
    }

    pub fn marker(&self, name: &str) {
        fs::write(self.root.join(name), b"1").unwrap();
    }

    pub fn unmark(&self, name: &str) {
        let _ = fs::remove_file(self.root.join(name));
    }

    pub fn has(&self, name: &str) -> bool {
        self.root.join(name).exists()
    }

    /// Simulate an external program dropping the cache entry.
    pub fn drop_cache(&self) {
        self.marker("locked");
    }

    pub fn gpg_log(&self) -> String {
        fs::read_to_string(&self.gpg_log).unwrap_or_default()
    }

    pub fn ca_log(&self) -> String {
        fs::read_to_string(&self.ca_log).unwrap_or_default()
    }

    /// Number of CLEAR_PASSPHRASE operations logged so far.
    pub fn clears(&self) -> usize {
        self.ca_log()
            .lines()
            .filter(|l| l.starts_with("CLEAR_PASSPHRASE"))
            .count()
    }

    /// Number of loopback (passphrase-fed) signing invocations.
    pub fn loopbacks(&self) -> usize {
        self.gpg_log()
            .lines()
            .filter(|l| l.contains("--passphrase-fd"))
            .count()
    }
}

/// The default in-process key hierarchy: primary + two signing subkeys.
fn daemon_keys() -> String {
    format!(
        "sec:u:255:22:{PRIMARY_ID}:1789136976:::u:::scSC:::+::ed25519:::0:\n\
         fpr:::::::::{PRIMARY_FPR}:\n\
         grp:::::::::{PRIMARY_GRIP}:\n\
         uid:u::::1789136976::78F8::keyhold-test::::::::::0:\n\
         ssb:u:255:22:212181504E7D2CD7:1789136986::::::s:::+::ed25519::\n\
         fpr:::::::::{SUB_FPR}:\n\
         grp:::::::::{SUB_GRIP}:\n\
         ssb:u:255:22:F3C83A12ADCE45A1:1789137207::::::s:::+::ed25519::\n\
         fpr:::::::::{SUB2_FPR}:\n\
         grp:::::::::{SUB2_GRIP}:\n"
    )
}

/// A thread-safe in-memory credential store with an operation log and
/// failure injection.
#[derive(Default)]
pub struct FakeStore {
    state: Mutex<FakeState>,
    locks: Arc<FakeLocks>,
}

#[derive(Default)]
struct FakeState {
    items: std::collections::HashMap<String, Vec<u8>>,
    fail_load: bool,
    fail_store: bool,
    fail_delete: bool,
    ops: Vec<String>,
    clear_gate: Option<std::sync::Arc<ClearGate>>,
}

#[derive(Default)]
struct FakeLocks {
    state: Mutex<FakeLockState>,
    released: Condvar,
    next_contention: Mutex<Option<std::sync::mpsc::Sender<String>>>,
    next_clear_contention: Mutex<Option<std::sync::mpsc::Sender<()>>>,
}

#[derive(Default)]
struct FakeLockState {
    held: HashSet<String>,
    transactions: usize,
    clear_active: bool,
}

struct FakeActivationGuard {
    keygrip: String,
    locks: Arc<FakeLocks>,
}

impl Drop for FakeActivationGuard {
    fn drop(&mut self) {
        let mut state = self
            .locks
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.held.remove(&self.keygrip);
        state.transactions -= 1;
        self.locks.released.notify_all();
    }
}

struct FakeClearGuard {
    locks: Arc<FakeLocks>,
}

impl Drop for FakeClearGuard {
    fn drop(&mut self) {
        let mut state = self
            .locks
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.clear_active = false;
        self.locks.released.notify_all();
    }
}

struct ClearGate {
    entered: std::sync::mpsc::Sender<()>,
    release: Mutex<std::sync::mpsc::Receiver<()>>,
}

pub struct ClearGateHandle {
    entered: std::sync::mpsc::Receiver<()>,
    release: Option<std::sync::mpsc::Sender<()>>,
}

impl ClearGateHandle {
    pub fn wait_until_entered(&self) {
        self.entered
            .recv_timeout(Duration::from_secs(5))
            .expect("clear_all was not entered");
    }

    pub fn release(mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl Drop for ClearGateHandle {
    fn drop(&mut self) {
        if let Some(release) = self.release.take() {
            let _ = release.send(());
        }
    }
}

impl FakeStore {
    fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        // Matching the daemon's locking style: a poisoned lock is
        // recovered from, never panicked on.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Preload a credential for `keygrip`.
    pub fn preload(&self, keygrip: &str, secret: &[u8]) {
        self.state()
            .items
            .insert(keygrip.to_string(), secret.to_vec());
    }

    pub fn make_loads_fail(&self) {
        self.state().fail_load = true;
    }

    pub fn make_stores_fail(&self) {
        self.state().fail_store = true;
    }

    pub fn make_deletes_fail(&self) {
        self.state().fail_delete = true;
    }

    /// Remove a stored credential, as `keyhold credential clear` would.
    pub fn remove(&self, keygrip: &str) {
        self.state().items.remove(keygrip);
    }

    pub fn contains_key(&self, keygrip: &str) -> bool {
        self.state().items.contains_key(keygrip)
    }

    pub fn credential(&self, keygrip: &str) -> Option<Vec<u8>> {
        self.state().items.get(keygrip).cloned()
    }

    pub fn operations(&self) -> Vec<String> {
        self.state().ops.clone()
    }

    pub fn block_next_clear(&self) -> ClearGateHandle {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        self.state().clear_gate = Some(std::sync::Arc::new(ClearGate {
            entered: entered_tx,
            release: Mutex::new(release_rx),
        }));
        ClearGateHandle {
            entered: entered_rx,
            release: Some(release_tx),
        }
    }

    pub fn observe_next_lock_contention(
        &self,
    ) -> std::sync::mpsc::Receiver<String> {
        let (sender, receiver) = std::sync::mpsc::channel();
        *self
            .locks
            .next_contention
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sender);
        receiver
    }

    pub fn observe_next_clear_contention(
        &self,
    ) -> std::sync::mpsc::Receiver<()> {
        let (sender, receiver) = std::sync::mpsc::channel();
        *self
            .locks
            .next_clear_contention
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(sender);
        receiver
    }
}

impl CredentialStore for FakeStore {
    fn lock_transaction(
        &self,
        keygrip: &str,
    ) -> keyhold::error::Result<Box<dyn CredentialTransactionGuard>> {
        let mut state = self
            .locks
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.clear_active
            && let Some(sender) = self
                .locks
                .next_contention
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        {
            let _ = sender.send(keygrip.to_string());
        }
        state = self
            .locks
            .released
            .wait_while(state, |state| state.clear_active)
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.transactions += 1;
        if state.held.contains(keygrip)
            && let Some(sender) = self
                .locks
                .next_contention
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        {
            let _ = sender.send(keygrip.to_string());
        }
        state = self
            .locks
            .released
            .wait_while(state, |state| state.held.contains(keygrip))
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.held.insert(keygrip.to_string());
        drop(state);
        Ok(Box::new(FakeActivationGuard {
            keygrip: keygrip.to_string(),
            locks: Arc::clone(&self.locks),
        }))
    }

    fn load(
        &self,
        keygrip: &str,
    ) -> keyhold::error::Result<Option<Zeroizing<Vec<u8>>>> {
        let mut state = self.state();
        state.ops.push(format!("load:{keygrip}"));
        if state.fail_load {
            return Err(keyhold::error::Error::SecretService(
                "injected load failure".into(),
            ));
        }
        Ok(state
            .items
            .get(keygrip)
            .map(|secret| Zeroizing::new(secret.clone())))
    }

    fn contains(&self, keygrip: &str) -> keyhold::error::Result<bool> {
        let mut state = self.state();
        state.ops.push(format!("contains:{keygrip}"));
        Ok(state.items.contains_key(keygrip))
    }

    fn store(
        &self,
        target: &SigningTarget,
        secret: &[u8],
    ) -> keyhold::error::Result<()> {
        let mut state = self.state();
        state.ops.push(format!(
            "store:{}",
            target.keygrip.as_deref().unwrap_or("?")
        ));
        if state.fail_store {
            return Err(keyhold::error::Error::SecretService(
                "injected store failure".into(),
            ));
        }
        let grip = target.keygrip.clone().unwrap_or_default();
        state.items.insert(grip, secret.to_vec());
        Ok(())
    }

    fn delete(&self, keygrip: &str) -> keyhold::error::Result<bool> {
        let mut state = self.state();
        state.ops.push(format!("delete:{keygrip}"));
        if state.fail_delete {
            return Err(keyhold::error::Error::SecretService(
                "injected delete failure".into(),
            ));
        }
        Ok(state.items.remove(keygrip).is_some())
    }

    fn clear_all(&self) -> keyhold::error::Result<usize> {
        let mut locks = self
            .locks
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if (locks.transactions != 0 || locks.clear_active)
            && let Some(sender) = self
                .locks
                .next_clear_contention
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take()
        {
            let _ = sender.send(());
        }
        locks = self
            .locks
            .released
            .wait_while(locks, |locks| {
                locks.transactions != 0 || locks.clear_active
            })
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.clear_active = true;
        drop(locks);
        let _barrier = FakeClearGuard {
            locks: Arc::clone(&self.locks),
        };
        let gate = {
            let mut state = self.state();
            state.ops.push("clear_all".into());
            state.clear_gate.take()
        };
        if let Some(gate) = gate {
            let _ = gate.entered.send(());
            let _ = gate
                .release
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .recv_timeout(Duration::from_secs(5));
        }
        let mut state = self.state();
        let count = state.items.len();
        state.items.clear();
        Ok(count)
    }
}

/// Owned in-process daemon. Its runtime directory outlives the daemon, and
/// dropping the handle performs best-effort shutdown and joins the thread.
pub struct TestDaemon {
    runtime: TempDir,
    sock: PathBuf,
    join: Option<thread::JoinHandle<keyhold::error::Result<()>>>,
}

impl TestDaemon {
    pub fn sock(&self) -> &Path {
        &self.sock
    }

    pub fn shutdown(&mut self) -> keyhold::error::Result<()> {
        if self.join.is_none() {
            return Ok(());
        }
        if self
            .join
            .as_ref()
            .is_some_and(thread::JoinHandle::is_finished)
        {
            return self.wait();
        }
        let response = ipc_at(&self.sock, "{\"cmd\":\"shutdown\"}")
            .ok_or_else(|| {
                keyhold::error::Error::Daemon(
                    "in-process daemon did not answer shutdown".into(),
                )
            })?;
        if response["ok"] != true {
            return Err(keyhold::error::Error::Daemon(
                response["error"].as_str().unwrap_or("unknown error").into(),
            ));
        }
        self.wait()
    }

    pub fn wait(&mut self) -> keyhold::error::Result<()> {
        let Some(join) = self.join.take() else {
            return Ok(());
        };
        join.join().map_err(|_| {
            keyhold::error::Error::Daemon(
                "in-process daemon thread panicked".into(),
            )
        })?
    }
}

impl Drop for TestDaemon {
    fn drop(&mut self) {
        let _ = self.shutdown();
        let _ = self.wait();
        let _ = &self.runtime;
    }
}

/// Spawn an in-process daemon against the given tools and store. Returns an
/// owned handle once its socket answers.
pub fn spawn_daemon(
    gpg: Gpg,
    store: std::sync::Arc<FakeStore>,
    policies: ShutdownPolicies,
) -> TestDaemon {
    let runtime = TempDir::new().expect("runtime dir");
    let sock = runtime.path().join("keyhold").join("keyhold.sock");
    let paths = daemon::Paths {
        dir: runtime.path().join("keyhold"),
        sock: sock.clone(),
    };
    let join = {
        let paths = paths.clone();
        thread::Builder::new()
            .name("test-daemon".into())
            .spawn(move || daemon::run_with(&paths, gpg, store, policies))
            .expect("spawn daemon thread")
    };
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if UnixStream::connect(&sock).is_ok() {
            return TestDaemon {
                runtime,
                sock,
                join: Some(join),
            };
        }
        if join.is_finished() {
            match join.join() {
                Ok(Err(e)) => panic!("in-process daemon failed to start: {e}"),
                Ok(Ok(())) => {
                    panic!("in-process daemon exited during startup")
                }
                Err(_) => panic!("in-process daemon panicked during startup"),
            }
        }
        thread::sleep(Duration::from_millis(25));
    }
    let mut daemon = TestDaemon {
        runtime,
        sock,
        join: Some(join),
    };
    let path = daemon.sock.clone();
    let _ = daemon.shutdown();
    panic!("in-process daemon remained alive but never answered on {path:?}")
}

/// Raw IPC against an explicit socket path.
pub fn ipc_at(sock: &Path, request: &str) -> Option<serde_json::Value> {
    let mut stream = UnixStream::connect(sock).ok()?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    stream.write_all(request.as_bytes()).ok()?;
    stream.write_all(b"\n").ok()?;
    let mut response = String::new();
    stream.read_to_string(&mut response).ok()?;
    serde_json::from_str(response.trim()).ok()
}

pub fn status_at(sock: &Path) -> Option<serde_json::Value> {
    ipc_at(sock, "{\"cmd\":\"status\"}").and_then(|v| v.get("status").cloned())
}

/// Run the stored-mode activation flow in-process and feed its result to
/// the daemon as a normal `on` request would.
pub fn stored_activation(
    gpg: &Gpg,
    store: &FakeStore,
    key: Option<&str>,
    interval_ms: u64,
    hold_ms: Option<u64>,
) -> keyhold::error::Result<keyhold::activation::PreparedActivation> {
    keyhold::activation::activate(
        gpg,
        true,
        key,
        Duration::from_millis(interval_ms),
        hold_ms.map(Duration::from_millis),
        store,
        &|| Err(keyhold::error::Error::Message("unexpected prompt".into())),
    )
}

/// An `on` request carrying the prepared activation metadata.
pub fn on_request(
    key: Option<&str>,
    prepared: &keyhold::activation::Prepared,
    interval_ms: u64,
    hold_ms: Option<u64>,
) -> String {
    let cache = prepared.cache.expect("stored activation has a plan");
    let started = cache
        .started_wall
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_millis() as u64);
    let activated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before Unix epoch")
        .as_millis();
    let activated =
        u64::try_from(activated).expect("activation timestamp fits u64");
    format!(
        "{{\"cmd\":\"on\",\"key\":{key},\"key_source\":\"default\",\
         \"interval_ms\":{interval_ms},\"hold_ms\":{hold},\
         \"activated_at_ms\":{activated},\
         \"fingerprint\":\"{fpr}\",\"keygrip\":\"{grip}\",\
         \"credential_mode\":\"session\",\
         \"default_cache_ttl_ms\":{def_ttl},\"max_cache_ttl_ms\":{max_ttl},\
         \"cache_started_at_ms\":{started}}}",
        key = match key {
            Some(k) => format!("\"{k}\""),
            None => "null".to_string(),
        },
        hold = match hold_ms {
            Some(ms) => ms.to_string(),
            None => "null".to_string(),
        },
        activated = activated,
        fpr = prepared
            .target
            .as_ref()
            .map(|t| t.fingerprint.clone())
            .unwrap_or_default(),
        grip = prepared
            .target
            .as_ref()
            .and_then(|t| t.keygrip.clone())
            .unwrap_or_default(),
        def_ttl = cache.default_ttl.as_millis() as u64,
        max_ttl = cache.max_ttl.as_millis() as u64,
        started = started
            .map(|ms| ms.to_string())
            .unwrap_or_else(|| "null".into()),
    )
}
