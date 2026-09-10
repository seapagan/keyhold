//! End-to-end daemon/CLI flow tests using a fake `gpg` executable and fully
//! isolated XDG directories. No real GPG keyring is ever touched.

mod common;

use std::{
    fs,
    io::{Read, Write},
    os::unix::net::UnixStream,
    process::Stdio,
    time::Duration,
};

use common::{TestEnv, wait_for_status, wait_with_kill};

const SECS: Duration = Duration::from_secs(1);

#[test]
fn status_reports_stopped_when_no_daemon() {
    let env = TestEnv::new();
    let text = env.status();
    assert_eq!(text, "Daemon: stopped\nHold:   off\n");
}

#[test]
fn on_enables_hold_after_foreground_ping() {
    let env = TestEnv::new();
    let out = env.succeed(&["on"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "Keyhold enabled (no expiry).\n"
    );

    let text = env.status();
    for needle in [
        "Daemon: running",
        "Hold:   on",
        "Key:    default",
        "Interval: 5m",
    ] {
        assert!(text.contains(needle), "status missing {needle:?}:\n{text}");
    }
    assert!(text.contains("Expires: never"), "{text}");

    // The foreground ping must be a real signing invocation without the
    // background `cancel` pinentry mode.
    let log = env.gpg_log();
    assert!(log.contains("--detach-sign"), "no signing call: {log}");
    assert!(
        !log.contains("cancel"),
        "foreground ping used cancel: {log}"
    );
}

#[test]
fn on_with_key_and_duration_reports_details() {
    let env = TestEnv::new();
    env.succeed(&["on", "--key", "DEADBEEF", "--for", "2h"]);
    let text = env.status();
    assert!(text.contains("Key:    DEADBEEF"), "{text}");
    assert!(text.contains("Expires: in 1h"), "{text}");
    assert!(text.contains("Interval: 5m"), "{text}");

    let log = env.gpg_log();
    assert!(log.contains("--local-user DEADBEEF"), "{log}");
}

#[test]
fn repeated_on_replaces_the_hold() {
    let env = TestEnv::new();
    env.succeed(&["on", "--for", "1h"]);
    env.succeed(&["on", "--for", "3h"]);
    assert!(env.status().contains("Expires: in 2h"));

    env.succeed(&["on", "--key", "XYZ"]);
    let text = env.status();
    assert!(text.contains("Expires: never"), "{text}");
    assert!(text.contains("Key:    XYZ"), "{text}");
}

#[test]
fn off_disables_and_is_idempotent() {
    let env = TestEnv::new();
    // `off` with no daemon running is a well-defined no-op.
    assert_eq!(env.stdout(&["off"]), "Keyhold disabled.\n");

    env.succeed(&["on"]);
    assert_eq!(env.stdout(&["off"]), "Keyhold disabled.\n");

    let text = env.status();
    assert!(text.contains("Daemon: running"), "{text}");
    assert!(text.contains("Hold:   off"), "{text}");

    assert_eq!(env.stdout(&["off"]), "Keyhold disabled.\n");
}

#[test]
fn timed_hold_expires_by_itself() {
    let env = TestEnv::new();
    env.succeed(&["on", "--for", "1s", "--interval", "200ms"]);
    assert!(env.status().contains("Hold:   on"));
    assert!(
        wait_for_status(&env, "Hold:   off", 5 * SECS),
        "hold did not expire: {}",
        env.status()
    );
    let text = env.status();
    assert!(text.contains("Daemon: running"), "{text}");
    assert!(!text.contains("Error:"), "{text}");
}

#[test]
fn daemon_pings_in_background_with_cancel_mode() {
    let env = TestEnv::new();
    env.succeed(&["on", "--interval", "100ms"]);
    assert!(
        wait_until_log(&env, 5 * SECS, 2),
        "expected background pings, log: {}",
        env.gpg_log()
    );
}

fn wait_until_log(env: &TestEnv, timeout: Duration, min: usize) -> bool {
    common::wait_until(timeout, || {
        env.gpg_log()
            .lines()
            .filter(|l| l.contains("cancel"))
            .count()
            >= min
    })
}

#[test]
fn background_ping_failure_stops_hold_and_reports_error() {
    let env = TestEnv::new();
    env.succeed(&["on", "--interval", "200ms", "--for", "1h"]);
    assert!(env.status().contains("Hold:   on"));

    // Simulate the GPG cache disappearing: background pings now fail.
    env.fail_background_pings();

    assert!(
        wait_for_status(&env, "Hold:   off", 5 * SECS),
        "hold did not stop: {}",
        env.status()
    );
    let text = env.status();
    assert!(text.contains("Error:"), "{text}");
    assert!(text.contains("cancelled"), "{text}");
    assert!(text.contains("Daemon: running"), "{text}");
}

#[test]
fn failed_foreground_unlock_leaves_hold_off() {
    let env = TestEnv::new();
    env.fail_all_pings();

    let out = env.fail(&["on", "--for", "1h"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("gpg"), "{stderr}");
    assert!(stderr.contains("NOT enabled"), "{stderr}");

    let text = env.status();
    assert!(text.contains("Hold:   off"), "{text}");
    // The foreground ping was really attempted.
    assert!(env.gpg_log().contains("--detach-sign"));
}

#[test]
fn stale_socket_file_is_recovered() {
    let env = TestEnv::new();
    fs::create_dir_all(env.sock().parent().unwrap()).unwrap();
    fs::write(env.sock(), b"junk from a dead daemon").unwrap();

    env.succeed(&["on"]);
    assert!(env.status().contains("Daemon: running"));
}

#[test]
fn second_foreground_daemon_is_rejected() {
    let env = TestEnv::new();
    let mut first = env
        .keyhold(&["daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for_status(&env, "Daemon: running", 5 * SECS),
        "first daemon did not start"
    );

    let out = env.fail(&["daemon"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("already running"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    env.succeed(&["daemon", "--stop"]);
    wait_with_kill(&mut first, 5 * SECS);
    assert!(env.status().contains("Daemon: stopped"));
}

#[test]
fn daemon_stop_removes_socket_and_auto_restart_works() {
    let env = TestEnv::new();
    env.succeed(&["on"]);
    assert_eq!(env.stdout(&["daemon", "--stop"]), "Daemon stopped.\n");
    assert!(common::wait_until(5 * SECS, || !env.sock().exists()));
    assert_eq!(env.status(), "Daemon: stopped\nHold:   off\n");

    // A subsequent `on` transparently starts a fresh daemon (hold was off).
    env.succeed(&["on"]);
    let text = env.status();
    assert!(text.contains("Daemon: running"), "{text}");
    assert!(text.contains("Hold:   on"), "{text}");
}

#[test]
fn daemon_stop_without_daemon_is_fine() {
    let env = TestEnv::new();
    assert_eq!(env.stdout(&["daemon", "--stop"]), "Daemon not running.\n");
}

#[test]
fn malformed_request_does_not_kill_daemon() {
    let env = TestEnv::new();
    env.succeed(&["on"]);

    let mut stream = UnixStream::connect(env.sock()).unwrap();
    stream.write_all(b"this is not json\n").unwrap();
    let mut response = String::new();
    let mut buf = [0u8; 1024];
    if let Ok(n) = stream.read(&mut buf) {
        response.push_str(&String::from_utf8_lossy(&buf[..n]));
    }
    assert!(response.contains("\"ok\":false"), "response: {response}");
    drop(stream);

    // An oversized request must also be refused harmlessly.
    let mut stream = UnixStream::connect(env.sock()).unwrap();
    let huge = vec![b'a'; 70_000];
    stream.write_all(&huge).unwrap();
    stream.write_all(b"\n").unwrap();
    drop(stream);

    let text = env.status();
    assert!(text.contains("Daemon: running"), "{text}");
    assert!(text.contains("Hold:   on"), "{text}");
}

#[test]
fn missing_gpg_executable_is_reported() {
    let env = TestEnv::new();
    let mut cmd = env.keyhold(&["on"]);
    cmd.env("KEYHOLD_GPG", "/nonexistent/fake-gpg");
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("gpg executable not found"), "{stderr}");
}

#[test]
fn missing_runtime_dir_is_reported() {
    let env = TestEnv::new();
    let mut cmd = env.keyhold(&["on"]);
    cmd.env_remove("XDG_RUNTIME_DIR");
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("XDG_RUNTIME_DIR"), "{stderr}");
}

#[test]
fn invalid_config_is_reported() {
    let env = TestEnv::new();
    fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "nonsense [",
    )
    .unwrap();

    let out = env.fail(&["on"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("invalid configuration"), "{stderr}");

    // `status` does not need configuration and keeps working.
    assert_eq!(env.status(), "Daemon: stopped\nHold:   off\n");
}

#[test]
fn config_file_supplies_defaults_and_cli_wins() {
    let env = TestEnv::new();
    fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "key = \"CAFEF00D\"\ninterval = \"9m\"\n",
    )
    .unwrap();

    env.succeed(&["on", "--for", "1h"]);
    let text = env.status();
    assert!(text.contains("Key:    CAFEF00D"), "{text}");
    assert!(text.contains("Interval: 9m"), "{text}");

    env.succeed(&["off"]);
    env.succeed(&["on", "--key", "0xBEEF", "--interval", "3m"]);
    let text = env.status();
    assert!(text.contains("Key:    0xBEEF"), "{text}");
    assert!(text.contains("Interval: 3m"), "{text}");
}

#[test]
fn on_message_matches_requested_duration() {
    let env = TestEnv::new();
    assert_eq!(
        env.stdout(&["on", "--for", "30m"]),
        "Keyhold enabled for 30m.\n"
    );
    env.succeed(&["off"]);
    assert_eq!(
        env.stdout(&["on", "--for", "1h30m"]),
        "Keyhold enabled for 1h 30m.\n"
    );
}
