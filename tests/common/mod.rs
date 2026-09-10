// Each test binary includes only part of this module's API.
#![allow(dead_code)]

//! Shared helpers for integration tests: isolated runtime/config directories
//! plus a fake `gpg` script driven by marker files.
//!
//! The fake gpg logs every invocation and can be told to fail all pings
//! (`fail_all`) or only background pings (`fail_bg`, detected by the
//! `cancel` argument the daemon passes). Real GPG is never touched.
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::PathBuf,
    process::{Command, Output},
    thread,
    time::{Duration, Instant},
};

use tempfile::TempDir;

pub struct TestEnv {
    pub runtime: TempDir,
    pub config: TempDir,
    // Holds the fake gpg script, its log and the failure markers; must
    // outlive every spawned keyhold process.
    pub scratch: TempDir,
    pub bin: PathBuf,
    pub gpg: PathBuf,
    pub log: PathBuf,
    fail_all: PathBuf,
    fail_bg: PathBuf,
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
        let script = concat!(
            "#!/bin/sh\n",
            "echo \"$*\" >> \"$KEYHOLD_FAKE_LOG\"\n",
            "background=0\n",
            "for a in \"$@\"; do [ \"$a\" = cancel ] && background=1; done\n",
            "if [ \"$background\" = 1 ] && [ -e \"$KEYHOLD_FAKE_FAIL_BG\" ]; then\n",
            "  echo 'gpg: signing failed: Operation cancelled' >&2\n",
            "  exit 2\n",
            "fi\n",
            "if [ -e \"$KEYHOLD_FAKE_FAIL_ALL\" ]; then exit 2; fi\n",
            "exit 0\n",
        );
        fs::write(&gpg, script).expect("write fake gpg");
        fs::set_permissions(&gpg, fs::Permissions::from_mode(0o755))
            .expect("chmod fake gpg");
        Self {
            bin: PathBuf::from(env!("CARGO_BIN_EXE_keyhold")),
            gpg,
            log,
            fail_all,
            fail_bg,
            runtime,
            config,
            scratch,
        }
    }

    /// Build a `keyhold` command with fully isolated environment.
    pub fn keyhold(&self, args: &[&str]) -> Command {
        let mut cmd = Command::new(&self.bin);
        cmd.args(args)
            .env("XDG_RUNTIME_DIR", self.runtime.path())
            .env("XDG_CONFIG_HOME", self.config.path())
            .env("KEYHOLD_GPG", &self.gpg)
            .env("KEYHOLD_FAKE_LOG", &self.log)
            .env("KEYHOLD_FAKE_FAIL_ALL", &self.fail_all)
            .env("KEYHOLD_FAKE_FAIL_BG", &self.fail_bg);
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

    /// Make every fake gpg invocation fail.
    pub fn fail_all_pings(&self) {
        fs::write(&self.fail_all, b"1").expect("write fail-all marker");
    }

    /// Make only background (daemon) pings fail, like an expired cache.
    pub fn fail_background_pings(&self) {
        fs::write(&self.fail_bg, b"1").expect("write fail-bg marker");
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
