// Each test binary includes only part of this module's API.
#![allow(dead_code)]

//! Shared helpers for integration tests: isolated runtime/config
//! directories plus fake `gpg`/`gpgconf`/`gpg-connect-agent` scripts
//! driven by marker files.
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
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
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

/// Default fake agent TTLs (seconds): 10s idle, 30s hard max.
pub const DEFAULT_TTL_SECS: u64 = 10;
pub const MAX_TTL_SECS: u64 = 30;

pub struct TestEnv {
    pub runtime: TempDir,
    pub config: TempDir,
    // Holds the fake gpg/gpgconf/gpg-connect-agent scripts, their logs,
    // fixtures and failure markers; must outlive every spawned keyhold
    // process.
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

        let gpg = scratch.path().join("fake-gpg");
        let log = scratch.path().join("gpg.log");
        let fail_all = scratch.path().join("fail-all");
        let fail_bg = scratch.path().join("fail-bg");
        let slow_bg = scratch.path().join("slow-bg");
        let rich = scratch.path().join("rich");
        let cached = scratch.path().join("cached-key");
        let lock = scratch.path().join("lock-key");
        let passphrase = scratch.path().join("expected-passphrase");

        let gpgconf = scratch.path().join("fake-gpgconf");
        let ttls = scratch.path().join("cache-ttls");
        let gpgconf_fail = scratch.path().join("gpgconf-fail");

        let connect_agent = scratch.path().join("fake-gpg-connect-agent");
        let ca_log = scratch.path().join("connect-agent.log");
        let key_cached = scratch.path().join("key-cached");
        let key_prot = scratch.path().join("key-protection");

        let keys_fixture = scratch.path().join("secret-keys.txt");

        fs::write(&gpg, fake_gpg_script()).expect("write fake gpg");
        fs::set_permissions(&gpg, fs::Permissions::from_mode(0o755))
            .expect("chmod fake gpg");

        fs::write(
            &gpgconf,
            format!(
                "#!/bin/sh\n\
                 [ -e \"$KEYHOLD_FAKE_GPGCONF_FAIL\" ] && exit 1\n\
                 read def max < \"$KEYHOLD_FAKE_TTLS\" || exit 1\n\
                 printf '%s\\n' \
                 \"default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:$def::\" \
                 \"max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:$max::\"\n",
            ),
        )
        .expect("write fake gpgconf");
        fs::set_permissions(&gpgconf, fs::Permissions::from_mode(0o755))
            .expect("chmod fake gpgconf");

        fs::write(&connect_agent, fake_connect_agent_script())
            .expect("write fake gpg-connect-agent");
        fs::set_permissions(&connect_agent, fs::Permissions::from_mode(0o755))
            .expect("chmod fake gpg-connect-agent");

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
            .env("KEYHOLD_FAKE_LOG", &self.log)
            .env("KEYHOLD_FAKE_FAIL_ALL", &self.fail_all)
            .env("KEYHOLD_FAKE_FAIL_BG", &self.fail_bg)
            .env("KEYHOLD_FAKE_SLOW_BG", &self.slow_bg)
            .env("KEYHOLD_FAKE_RICH", &self.rich)
            .env("KEYHOLD_FAKE_CACHED", &self.cached)
            .env("KEYHOLD_FAKE_LOCK", &self.lock)
            .env("KEYHOLD_FAKE_PASSPHRASE", &self.passphrase)
            .env("KEYHOLD_FAKE_KEYS", &self.keys_fixture)
            .env("KEYHOLD_FAKE_CA_LOG", &self.ca_log)
            .env("KEYHOLD_FAKE_KEY_CACHED", &self.key_cached)
            .env("KEYHOLD_FAKE_KEY_PROT", &self.key_prot)
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

/// The fake `gpg` script. Signature semantics:
///
/// * invocations containing `--list-secret-keys` print the fixture;
/// * loopback invocations (`--passphrase-fd`) read one line from stdin
///   and validate it against `$KEYHOLD_FAKE_PASSPHRASE` (the secret is
///   never logged);
/// * background invocations (containing `cancel`) fail like a locked key
///   when the `lock` marker is present;
/// * otherwise the harmless sign succeeds, emitting a `--status-fd`
///   stream when the `rich` marker is present.
fn fake_gpg_script() -> String {
    let mut s = String::new();
    s.push_str("#!/bin/sh\n");
    // Machine-readable signing status goes to stdout (the daemon passes
    // --status-fd 1); the signature itself is discarded via --output
    // /dev/null, so stdout is free.
    s.push_str("list=0; loopback=0; background=0\n");
    s.push_str("for a in \"$@\"; do\n");
    s.push_str("  [ \"$a\" = --list-secret-keys ] && list=1\n");
    s.push_str("  [ \"$a\" = --passphrase-fd ] && loopback=1\n");
    s.push_str("  [ \"$a\" = cancel ] && background=1\n");
    s.push_str("done\n");
    s.push_str("echo \"$*\" >> \"$KEYHOLD_FAKE_LOG\"\n");
    s.push_str(
        "if [ \"$list\" = 1 ]; then cat \"$KEYHOLD_FAKE_KEYS\"; exit 0; fi\n",
    );
    s.push_str("if [ \"$background\" = 1 ] && [ -e \"$KEYHOLD_FAKE_SLOW_BG\" ]; then\n");
    s.push_str("  sleep 2\n");
    s.push_str("  echo bg-done >> \"$KEYHOLD_FAKE_LOG\"\n");
    s.push_str("fi\n");
    s.push_str("if [ \"$background\" = 1 ] && [ -e \"$KEYHOLD_FAKE_FAIL_BG\" ]; then\n");
    s.push_str("  echo 'gpg: signing failed: Operation cancelled' >&2\n");
    s.push_str("  exit 2\n");
    s.push_str("fi\n");
    s.push_str("if [ -e \"$KEYHOLD_FAKE_FAIL_ALL\" ]; then exit 2; fi\n");
    s.push_str("if [ \"$loopback\" = 1 ]; then\n");
    // Read the single passphrase line from stdin and compare. Never log
    // it; only the outcome is observable.
    s.push_str("  IFS= read -r supplied\n");
    s.push_str("  expected=$(cat \"$KEYHOLD_FAKE_PASSPHRASE\")\n");
    s.push_str("  if [ \"$supplied\" != \"$expected\" ]; then\n");
    s.push_str("    echo 'gpg: signing failed: Bad passphrase' >&2\n");
    s.push_str("    exit 2\n");
    s.push_str("  fi\n");
    s.push_str("fi\n");
    s.push_str(
        "if [ \"$background\" = 1 ] && [ -e \"$KEYHOLD_FAKE_LOCK\" ]; then\n",
    );
    s.push_str("  echo '[GNUPG:] KEY_CONSIDERED C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48 0'\n");
    s.push_str("  echo 'gpg: signing failed: Operation cancelled' >&2\n");
    s.push_str("  exit 2\n");
    s.push_str("fi\n");
    s.push_str("if [ -e \"$KEYHOLD_FAKE_RICH\" ]; then\n");
    s.push_str("  echo '[GNUPG:] KEY_CONSIDERED C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48 0'\n");
    s.push_str("  if [ \"$background\" != 1 ] && [ \"$loopback\" != 1 ] && [ ! -e \"$KEYHOLD_FAKE_CACHED\" ]; then\n");
    s.push_str("    echo '[GNUPG:] PINENTRY_LAUNCHED 2718 gnome3 1.3.2 not a tty dumb :0 ? 1000/1000 -'\n");
    s.push_str("  fi\n");
    s.push_str("  echo '[GNUPG:] SIG_CREATED D 22 10 00 1789136997 97CF31DBA5F6012341995ED8F3C83A12ADCE45A1'\n");
    s.push_str("fi\n");
    s.push_str("exit 0\n");
    s
}

/// The fake `gpg-connect-agent` script: KEYINFO and CLEAR_PASSPHRASE
/// over the same command line shape the real tool accepts.
fn fake_connect_agent_script() -> String {
    let mut s = String::new();
    s.push_str("#!/bin/sh\n");
    s.push_str("echo \"$*\" >> \"$KEYHOLD_FAKE_CA_LOG\"\n");
    s.push_str("cmd=$1\n");
    // CLEAR_PASSPHRASE --mode=normal <keygrip>
    s.push_str("case \"$cmd\" in\n");
    s.push_str("  'CLEAR_PASSPHRASE '*)\n");
    s.push_str("    echo OK\n");
    s.push_str("    exit 0\n");
    s.push_str("    ;;\n");
    s.push_str("  KEYINFO\\ *)\n");
    s.push_str("    grip=$(echo \"$cmd\" | cut -d' ' -f2)\n");
    s.push_str(
        "    case \"$grip\" in\n\
             0000000000000000000000000000000000000000)\n\
               echo 'ERR 67108891 Not found <GPG Agent>'\n\
               exit 0\n\
               ;;\n\
           esac\n",
    );
    s.push_str("    prot=P\n");
    s.push_str("    [ -f \"$KEYHOLD_FAKE_KEY_PROT\" ] && prot=$(cat \"$KEYHOLD_FAKE_KEY_PROT\")\n");
    s.push_str("    cached=-\n");
    s.push_str("    [ -e \"$KEYHOLD_FAKE_KEY_CACHED\" ] && cached=1\n");
    s.push_str("    echo \"S KEYINFO $grip D - - $cached $prot - - -\"\n");
    s.push_str("    echo OK\n");
    s.push_str("    exit 0\n");
    s.push_str("    ;;\n");
    s.push_str("esac\n");
    s.push_str("echo OK\n");
    s
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
