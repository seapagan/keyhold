//! End-to-end daemon/CLI flow tests using a fake `gpg` executable and fully
//! isolated XDG directories. No real GPG keyring is ever touched.

mod common;

use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

use common::{TestEnv, wait_for_status, wait_with_kill};

const SECS: Duration = Duration::from_secs(1);

#[test]
fn status_reports_stopped_when_no_daemon() {
    let env = TestEnv::new();
    let text = env.status();
    assert_eq!(
        text,
        "Keyhold status\n\nDaemon       stopped\nHold         off\n"
    );
}

#[test]
fn on_enables_hold_after_foreground_ping() {
    let env = TestEnv::new();
    let out = env.succeed(&["on"]);
    // An indefinite ordinary hold truthfully warns about the hard
    // maximum; a finite hold under it stays silent.
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "warning: GnuPG's hard max-cache-ttl (2h) will eventually end an \
ordinary hold unless the cache entry is recreated externally\n\
Keyhold enabled (no expiry).\n"
    );

    let text = env.status();
    for needle in [
        "Daemon       running",
        "Hold         on",
        "Key          default",
        "Interval     5m",
    ] {
        assert!(text.contains(needle), "status missing {needle:?}:\n{text}");
    }
    assert!(text.contains("Remaining    no deadline"), "{text}");

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
    assert!(text.contains("Key          DEADBEEF"), "{text}");
    assert!(text.contains("Remaining    2h"), "{text}");
    assert!(text.contains("Interval     5m"), "{text}");

    let log = env.gpg_log();
    assert!(log.contains("--local-user DEADBEEF"), "{log}");
}

#[test]
fn repeated_on_replaces_the_hold() {
    let env = TestEnv::new();
    env.succeed(&["on", "--for", "1h"]);
    env.succeed(&["on", "--for", "3h"]);
    // A fresh hold rounds to the nearest minute, so it still reads `3h`.
    assert!(env.status().contains("Remaining    3h"));

    env.succeed(&["on", "--key", "XYZ"]);
    let text = env.status();
    assert!(text.contains("Remaining    no deadline"), "{text}");
    assert!(text.contains("Key          XYZ"), "{text}");
}

#[test]
fn off_disables_and_is_idempotent() {
    let env = TestEnv::new();
    // `off` with no daemon running is a well-defined no-op.
    assert_eq!(env.stdout(&["off"]), "Keyhold disabled.\n");

    env.succeed(&["on"]);
    assert_eq!(env.stdout(&["off"]), "Keyhold disabled.\n");

    let text = env.status();
    assert!(text.contains("Daemon       running"), "{text}");
    assert!(text.contains("Hold         off"), "{text}");

    assert_eq!(env.stdout(&["off"]), "Keyhold disabled.\n");
}

#[test]
fn timed_hold_expires_by_itself() {
    let env = TestEnv::new();
    env.succeed(&["on", "--for", "1s", "--interval", "200ms"]);
    assert!(env.status().contains("Hold         on"));
    assert!(
        wait_for_status(&env, "Hold         off", 5 * SECS),
        "hold did not expire: {}",
        env.status()
    );
    let text = env.status();
    assert!(text.contains("Daemon       running"), "{text}");
    assert!(!text.contains("Error        "), "{text}");
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
fn relative_gpg_override_survives_daemon_detachment() {
    let env = TestEnv::new();
    let mut cmd = env.keyhold(&["on", "--interval", "100ms"]);
    cmd.env("KEYHOLD_GPG", "fake-gpg");
    cmd.current_dir(env.gpg.parent().expect("fixture directory"));
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );

    // The detached daemon (cwd "/") must still find the fake gpg and keep
    // pinging it in the background.
    assert!(
        wait_until_log(&env, 5 * SECS, 1),
        "daemon did not ping via relative override, log: {}",
        env.gpg_log()
    );
    assert!(env.status().contains("Hold         on"));
}

#[test]
fn background_ping_failure_stops_hold_and_reports_error() {
    let env = TestEnv::new();
    env.succeed(&["on", "--interval", "200ms", "--for", "1h"]);
    assert!(env.status().contains("Hold         on"));

    // Simulate the GPG cache disappearing: background pings now fail.
    env.fail_background_pings();

    assert!(
        wait_for_status(&env, "Hold         off", 5 * SECS),
        "hold did not stop: {}",
        env.status()
    );
    let text = env.status();
    assert!(text.contains("Error        "), "{text}");
    assert!(text.contains("cancelled"), "{text}");
    assert!(text.contains("Daemon       running"), "{text}");
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
    assert!(text.contains("Hold         off"), "{text}");
    // The failed activation enabled nothing and recorded no successful use.
    let status = common::status_of(&env).expect("status via IPC");
    assert_eq!(status["hold_on"], false);
    assert!(status["last_ping_ms"].is_null());
    // The foreground ping was really attempted.
    assert!(env.gpg_log().contains("--detach-sign"));
}

#[test]
fn activation_is_reported_as_the_last_ping() {
    let env = TestEnv::new();
    let before = now_ms();
    env.succeed(&["on"]);

    // The successful foreground key use is recorded immediately: an
    // instant `status` reports it instead of omitting the row.
    let status = common::status_of(&env).expect("status via IPC");
    let last = status["last_ping_ms"]
        .as_u64()
        .expect("activation not recorded");
    assert!(last >= before, "stale or missing activation: {status}");

    let text = env.status();
    assert!(text.contains("Last ping    "), "{text}");

    // The activation is not itself a background ping: the first keepalive
    // stays one full interval after activation.
    assert!(!env.gpg_log().contains("cancel"), "{}", env.gpg_log());
}

#[test]
fn replacing_a_hold_records_a_fresh_activation() {
    let env = TestEnv::new();
    // Start a hold whose last background ping is now in the past.
    env.succeed(&["on", "--interval", "100ms", "--for", "1s"]);
    assert!(wait_for_status(&env, "Hold         off", 5 * SECS));

    let replaced_at = now_ms();
    env.succeed(&["on"]);

    // The replacement must display its own activation, never a timestamp
    // inherited from the expired hold's last background ping.
    let status = common::status_of(&env).expect("status via IPC");
    let last = status["last_ping_ms"]
        .as_u64()
        .expect("activation not recorded");
    assert!(last >= replaced_at, "stale previous-hold ping: {status}");
}

#[test]
fn in_flight_ping_cannot_mutate_a_disabled_hold() {
    let env = TestEnv::new();
    // Background keepalives start, then stall for 2s before failing:
    // `off` arrives while they are still running.
    env.slow_background_pings();
    env.fail_background_pings();
    env.succeed(&["on", "--interval", "100ms", "--for", "1h"]);
    assert!(
        common::wait_until(5 * SECS, || log_count(&env, "cancel") >= 1),
        "no background ping started: {}",
        env.gpg_log()
    );

    env.succeed(&["off"]);

    // Wait until every already-started keepalive has finished (failing);
    // none of those late results may re-enable the hold or record an error.
    assert!(
        common::wait_until(10 * SECS, || {
            log_count(&env, "bg-done") == log_count(&env, "cancel")
        }),
        "in-flight pings never finished: {}",
        env.gpg_log()
    );
    let text = env.status();
    assert!(text.contains("Hold         off"), "{text}");
    assert!(!text.contains("Error        "), "{text}");
    assert!(text.contains("Daemon       running"), "{text}");
}

#[test]
fn in_flight_ping_cannot_mutate_a_replaced_hold() {
    let env = TestEnv::new();
    env.slow_background_pings();
    env.fail_background_pings();
    env.succeed(&["on", "--interval", "100ms", "--for", "1h"]);
    assert!(
        common::wait_until(5 * SECS, || log_count(&env, "cancel") >= 1),
        "no background ping started: {}",
        env.gpg_log()
    );

    // Replace the hold while the old hold's keepalives are in flight; the
    // new hold's first background ping is 30s out, so nothing else runs.
    let replaced_at = now_ms();
    env.succeed(&["on", "--key", "NEWKEY", "--interval", "30s"]);

    assert!(
        common::wait_until(10 * SECS, || {
            log_count(&env, "bg-done") == log_count(&env, "cancel")
        }),
        "in-flight pings never finished: {}",
        env.gpg_log()
    );
    let text = env.status();
    assert!(text.contains("Hold         on"), "{text}");
    assert!(text.contains("Key          NEWKEY"), "{text}");
    assert!(!text.contains("Error        "), "{text}");
    assert!(text.contains("Daemon       running"), "{text}");

    // The replacement's activation remains the latest successful use.
    let status = common::status_of(&env).expect("status via IPC");
    let last = status["last_ping_ms"]
        .as_u64()
        .expect("activation not recorded");
    assert!(last >= replaced_at, "stale ping mutated state: {status}");
}

/// Number of fake-gpg log lines containing `needle`.
fn log_count(env: &TestEnv, needle: &str) -> usize {
    env.gpg_log().lines().filter(|l| l.contains(needle)).count()
}

#[test]
fn extreme_timing_values_cannot_kill_the_daemon() {
    let env = TestEnv::new();
    env.succeed(&["on"]);

    // A raw IPC client can send any u64. Values the platform can represent
    // (on Linux, every millisecond count) schedule normally...
    let request = format!(
        "{{\"cmd\":\"on\",\"key\":null,\"key_source\":\"default\",\"interval_ms\":{},\
         \"hold_ms\":null,\"activated_at_ms\":{}}}",
        u64::MAX,
        now_ms()
    );
    let response =
        common::ipc_request(&env, &request).expect("daemon responsive");
    assert_eq!(response["ok"], true, "{response}");
    let status = common::status_of(&env).expect("status via IPC");
    assert_eq!(status["interval_ms"].as_u64(), Some(u64::MAX));
    // The u64::MAX-ms ping is schedulable but its wall-clock projection
    // overflows epoch milliseconds: the field is absent, never zero
    // (which the CLI would render as "Next ping    in 0s").
    assert!(status["next_ping_ms"].is_null(), "{status}");
    let text = env.status();
    assert!(text.contains("Hold         on"), "{text}");
    assert!(!text.contains("Next ping"), "{text}");
    // ...including the widest hold deadline; remaining stays near u64::MAX.
    let request = format!(
        "{{\"cmd\":\"on\",\"key\":null,\"key_source\":\"default\",\"interval_ms\":300000,\
         \"hold_ms\":{},\"activated_at_ms\":{}}}",
        u64::MAX,
        now_ms()
    );
    let response =
        common::ipc_request(&env, &request).expect("daemon responsive");
    assert_eq!(response["ok"], true, "{response}");
    let status = common::status_of(&env).expect("status via IPC");
    let remaining = status["remaining_ms"].as_u64().expect("remaining");
    assert!(
        remaining > u64::MAX - 60_000,
        "remaining not representable: {status}"
    );
    // Ordinary intervals keep their next-ping display.
    let text = env.status();
    assert!(text.contains("Next ping    in "), "{text}");
    assert!(!text.contains("in 0s"), "{text}");

    // A zero interval stays a plain protocol error, not a crash.
    let response = common::ipc_request(
        &env,
        "{\"cmd\":\"on\",\"key\":null,\"key_source\":\"default\",\"interval_ms\":0,\"hold_ms\":null,\
         \"activated_at_ms\":0}",
    )
    .expect("daemon responsive");
    assert_eq!(response["ok"], false, "{response}");
    assert!(
        response["error"]
            .as_str()
            .is_some_and(|e| e.contains("greater than zero")),
        "{response}"
    );

    // The daemon is unharmed and fully operational afterwards.
    env.succeed(&["off"]);
    assert!(env.status().contains("Daemon       running"));
}

#[test]
fn huge_activation_timestamp_does_not_disturb_the_daemon() {
    let env = TestEnv::new();
    env.succeed(&["on"]);

    // `activated_at_ms` is display-only history: an absurd value must not
    // panic, must not touch monotonic scheduling, and is represented as-is.
    let before = now_ms();
    let request = format!(
        "{{\"cmd\":\"on\",\"key\":null,\"key_source\":\"default\",\"interval_ms\":300000,\
         \"hold_ms\":null,\"activated_at_ms\":{}}}",
        u64::MAX
    );
    let response =
        common::ipc_request(&env, &request).expect("daemon responsive");
    assert_eq!(response["ok"], true, "{response}");
    let status = common::status_of(&env).expect("status via IPC");
    assert_eq!(status["last_ping_ms"].as_u64(), Some(u64::MAX));
    let next = status["next_ping_ms"].as_u64().expect("next ping kept");
    assert!(
        next > before + 4 * 60_000,
        "monotonic scheduling disturbed: {status}"
    );

    env.succeed(&["off"]);
    assert!(env.status().contains("Daemon       running"));
}

#[test]
fn unrepresentable_cli_durations_are_rejected_before_side_effects() {
    let env = TestEnv::new();
    for flag in ["--for", "--interval"] {
        let out = env.fail(&["on", flag, "9223372036854775807s"]);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("invalid duration")
                && stderr.contains("largest duration keyhold can schedule"),
            "{flag}: {stderr}"
        );
    }
    // Rejected before any side effect: no daemon was started, no GPG call.
    assert_eq!(
        env.status(),
        "Keyhold status\n\nDaemon       stopped\nHold         off\n"
    );
    assert_eq!(env.gpg_log(), "");
}

/// Current wall-clock time in epoch milliseconds.
fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[test]
fn subsecond_durations_are_not_truncated_to_zero() {
    let env = TestEnv::new();
    assert_eq!(
        env.stdout(&["on", "--for", "500ms"]),
        "Keyhold enabled for 500ms.\n"
    );
    env.succeed(&["off"]);
    assert_eq!(
        env.stdout(&["on", "--for", "1s500ms"]),
        "Keyhold enabled for 1s 500ms.\n"
    );
}

#[test]
fn status_drops_millisecond_precision() {
    let env = TestEnv::new();
    env.succeed(&["on", "--for", "2s", "--interval", "2s"]);
    let text = env.status();
    // Sub-second remainder exists internally but never reaches the
    // display: remaining and ping times render at whole-second (or
    // coarser) precision.
    assert!(text.contains("Remaining    "), "{text}");
    assert!(text.contains("Next ping    in "), "{text}");
    assert!(text.contains("Last ping    "), "{text}");
    assert!(!text.contains("ms"), "{text}");
}

#[test]
fn stale_socket_file_is_recovered() {
    let env = TestEnv::new();
    fs::create_dir_all(env.sock().parent().unwrap()).unwrap();
    fs::write(env.sock(), b"junk from a dead daemon").unwrap();

    env.succeed(&["on"]);
    assert!(env.status().contains("Daemon       running"));
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
        wait_for_status(&env, "Daemon       running", 5 * SECS),
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
    assert!(env.status().contains("Daemon       stopped"));
}

#[test]
fn daemon_stop_removes_socket_and_auto_restart_works() {
    let env = TestEnv::new();
    env.succeed(&["on"]);
    assert_eq!(env.stdout(&["daemon", "--stop"]), "Daemon stopped.\n");
    assert!(common::wait_until(5 * SECS, || !env.sock().exists()));
    assert_eq!(
        env.status(),
        "Keyhold status\n\nDaemon       stopped\nHold         off\n"
    );

    // A subsequent `on` transparently starts a fresh daemon (hold was off).
    env.succeed(&["on"]);
    let text = env.status();
    assert!(text.contains("Daemon       running"), "{text}");
    assert!(text.contains("Hold         on"), "{text}");
}

#[test]
fn daemon_stop_without_daemon_is_fine() {
    let env = TestEnv::new();
    assert_eq!(env.stdout(&["daemon", "--stop"]), "Daemon not running.\n");
}

#[test]
fn daemon_background_starts_detached_and_returns() {
    let env = TestEnv::new();
    assert_eq!(env.stdout(&["daemon", "-b"]), "Daemon started.\n");

    let text = env.status();
    assert!(text.contains("Daemon       running"), "{text}");
    assert!(text.contains("Hold         off"), "{text}");
    // Starting the daemon alone must never invoke GPG (or pinentry).
    assert_eq!(env.gpg_log(), "");
}

#[test]
fn daemon_long_background_flag_matches_short() {
    let env = TestEnv::new();
    assert_eq!(env.stdout(&["daemon", "--background"]), "Daemon started.\n");

    let text = env.status();
    assert!(text.contains("Daemon       running"), "{text}");
    assert!(text.contains("Hold         off"), "{text}");
    assert_eq!(env.gpg_log(), "");
}

#[test]
fn repeated_background_start_is_idempotent() {
    let env = TestEnv::new();
    env.succeed(&["daemon", "-b"]);
    assert_eq!(env.stdout(&["daemon", "-b"]), "Daemon already running.\n");
}

#[test]
fn background_daemon_can_be_stopped_normally() {
    let env = TestEnv::new();
    env.succeed(&["daemon", "-b"]);
    assert_eq!(env.stdout(&["daemon", "--stop"]), "Daemon stopped.\n");
    assert_eq!(
        env.status(),
        "Keyhold status\n\nDaemon       stopped\nHold         off\n"
    );
}

#[test]
fn daemon_without_flags_stays_in_the_foreground() {
    let env = TestEnv::new();
    let mut child = spawn_daemon(&env);
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "foreground daemon did not start: {}",
        env.status()
    );

    // Bare `daemon` blocks the terminal: it must not return on its own.
    thread::sleep(Duration::from_millis(300));
    assert!(
        child.try_wait().unwrap().is_none(),
        "foreground daemon exited without --stop"
    );

    env.succeed(&["daemon", "--stop"]);
    wait_with_kill(&mut child, 5 * SECS);
    assert!(child.wait().unwrap().success());
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
    assert!(text.contains("Daemon       running"), "{text}");
    assert!(text.contains("Hold         on"), "{text}");
}

/// Spawn a foreground daemon with all streams silenced.
fn spawn_daemon(env: &TestEnv) -> std::process::Child {
    env.keyhold(&["daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap()
}

/// Send a named signal to a child via `/usr/bin/kill` (no unsafe needed).
fn send_signal(child: &std::process::Child, signal: &str) {
    let ok = Command::new("kill")
        .args([format!("-{signal}"), child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(ok.success(), "failed to send SIG{signal}");
}

#[test]
fn sigterm_shuts_the_daemon_down_cleanly() {
    let env = TestEnv::new();
    let mut daemon = spawn_daemon(&env);
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "daemon did not start: {}",
        env.status()
    );

    send_signal(&daemon, "TERM");

    wait_with_kill(&mut daemon, 5 * SECS);
    assert!(
        daemon.wait().unwrap().success(),
        "daemon did not exit successfully on SIGTERM"
    );
    assert!(
        common::wait_until(5 * SECS, || !env.sock().exists()),
        "socket file was not removed on SIGTERM"
    );
    assert_eq!(
        env.status(),
        "Keyhold status\n\nDaemon       stopped\nHold         off\n"
    );
}

#[test]
fn sigint_routes_through_the_same_clean_shutdown() {
    let env = TestEnv::new();
    let mut daemon = spawn_daemon(&env);
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "daemon did not start: {}",
        env.status()
    );

    send_signal(&daemon, "INT");

    wait_with_kill(&mut daemon, 5 * SECS);
    assert!(
        daemon.wait().unwrap().success(),
        "daemon did not exit successfully on SIGINT"
    );
    assert!(common::wait_until(5 * SECS, || !env.sock().exists()));
}

#[test]
fn sigterm_with_active_hold_exits_promptly_and_restarts_cleanly() {
    let env = TestEnv::new();
    let mut daemon = spawn_daemon(&env);
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "daemon did not start: {}",
        env.status()
    );

    // Keepalives genuinely running when the signal arrives.
    env.succeed(&["on", "--interval", "100ms"]);
    assert!(
        common::wait_until(5 * SECS, || log_count(&env, "cancel") >= 1),
        "no background ping started: {}",
        env.gpg_log()
    );

    send_signal(&daemon, "TERM");

    // Prompt exit despite an active 100ms hold: shutdown stops scheduling.
    wait_with_kill(&mut daemon, 5 * SECS);
    assert!(daemon.wait().unwrap().success());
    assert!(
        common::wait_until(5 * SECS, || !env.sock().exists()),
        "socket file was not removed on SIGTERM"
    );

    // The next daemon starts normally — no stale-socket recovery needed.
    let mut second = spawn_daemon(&env);
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "second daemon did not start: {}",
        env.status()
    );
    env.succeed(&["daemon", "--stop"]);
    wait_with_kill(&mut second, 5 * SECS);
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
fn daemon_stop_is_always_acknowledged() {
    // The shutdown acknowledgement must be written before daemon exit.
    // Repeat the whole cycle so the ordering guarantee is exercised, not
    // just sampled once: a lost acknowledgement makes `daemon --stop` fail
    // with "daemon closed the connection without a response".
    let env = TestEnv::new();
    for _ in 0..10 {
        let mut daemon = env
            .keyhold(&["daemon"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        assert!(
            wait_for_status(&env, "Daemon       running", 5 * SECS),
            "daemon did not start: {}",
            env.status()
        );
        assert_eq!(env.stdout(&["daemon", "--stop"]), "Daemon stopped.\n");
        wait_with_kill(&mut daemon, 5 * SECS);
        assert!(
            daemon.wait().unwrap().success(),
            "daemon did not exit successfully after --stop"
        );
        assert!(
            common::wait_until(5 * SECS, || !env.sock().exists()),
            "socket file was not removed"
        );
    }
}

#[test]
fn shutdown_for_a_vanished_client_still_terminates_cleanly() {
    // A client that sends a valid shutdown request and then breaks the
    // connection cannot be acknowledged — delivery over the broken socket
    // is impossible. The daemon must report the write failure, still
    // honour the shutdown, exit successfully and clean up its socket;
    // whether the kernel actually surfaces EPIPE for the single small
    // write does not change that contract.
    let env = TestEnv::new();
    let mut daemon = env
        .keyhold(&["daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "daemon did not start: {}",
        env.status()
    );

    let mut stream = UnixStream::connect(env.sock()).unwrap();
    stream.write_all(b"{\"cmd\":\"shutdown\"}\n").unwrap();
    let _ = stream.shutdown(std::net::Shutdown::Both);
    drop(stream);

    wait_with_kill(&mut daemon, 5 * SECS);
    assert!(
        daemon.wait().unwrap().success(),
        "daemon did not exit successfully after broken-client shutdown"
    );
    assert!(
        common::wait_until(5 * SECS, || !env.sock().exists()),
        "socket file was not removed"
    );
    assert_eq!(
        env.status(),
        "Keyhold status\n\nDaemon       stopped\nHold         off\n"
    );
}

#[test]
fn runtime_dir_and_socket_are_private() {
    let env = TestEnv::new();
    // A pre-existing, too-loose runtime dir must be tightened; the socket
    // must be 0700; $XDG_RUNTIME_DIR itself must not be touched.
    let base = env.runtime.path().to_path_buf();
    let dir = base.join("keyhold");
    fs::create_dir_all(&dir).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&base, fs::Permissions::from_mode(0o755)).unwrap();

    env.succeed(&["on"]);
    let mode = |p: &std::path::Path| {
        fs::metadata(p).unwrap().permissions().mode() & 0o777
    };
    assert_eq!(mode(&dir), 0o700, "runtime dir is not private");
    assert_eq!(mode(&env.sock()), 0o700, "socket is not private");
    assert_eq!(mode(&base), 0o755, "$XDG_RUNTIME_DIR was modified");
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
    assert_eq!(
        env.status(),
        "Keyhold status\n\nDaemon       stopped\nHold         off\n"
    );
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
    assert!(text.contains("Key          CAFEF00D"), "{text}");
    assert!(text.contains("Interval     9m"), "{text}");

    env.succeed(&["off"]);
    env.succeed(&["on", "--key", "0xBEEF", "--interval", "3m"]);
    let text = env.status();
    assert!(text.contains("Key          0xBEEF"), "{text}");
    assert!(text.contains("Interval     3m"), "{text}");
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

// ---------------------------------------------------------------------------
// Ordinary-mode truthfulness warnings and live status (rich fake gpg)
// ---------------------------------------------------------------------------

#[test]
fn ordinary_mode_warns_when_the_hold_exceeds_max_cache_ttl() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_cache_ttls(10, 30);
    // Fake TTLs: 10s default / 30s max.
    let out = env.succeed(&["on", "--for", "2h"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("warning: GnuPG's max-cache-ttl is 30s"),
        "missing max-ttl warning:\n{stdout}"
    );
    assert!(stdout.contains("cannot be guaranteed for 2h"), "{stdout}");
    assert!(
        stdout.contains("--store-passphrase"),
        "warning does not mention the opt-in:\n{stdout}"
    );
    // A warning, not a failure.
    assert!(stdout.contains("Keyhold enabled for 2h."));
}

#[test]
fn ordinary_mode_warns_at_and_above_max_cache_ttl() {
    // 30s hard max: a hold exactly at the maximum cannot be promised
    // (scheduling/process timing can make the hard expiry coincide
    // with or precede the endpoint), so the boundary is inclusive.
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_cache_ttls(10, 30);

    // One unit below: no max-ttl warning.
    let out = env.succeed(&["on", "--for", "29s"]);
    assert!(
        !String::from_utf8_lossy(&out.stdout).contains("max-cache-ttl is"),
        "29s must not warn:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // Exactly equal: warns.
    let out = env.succeed(&["on", "--for", "30s"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("max-cache-ttl is 30s"),
        "30s must warn:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );

    // One unit above: warns.
    let out = env.succeed(&["on", "--for", "31s"]);
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("max-cache-ttl is 30s"),
        "31s must warn:\n{}",
        String::from_utf8_lossy(&out.stdout)
    );
}

#[test]
fn ordinary_mode_warns_about_a_preexisting_cache_entry() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_cache_ttls(10, 30);
    env.cached_key();
    let out = env.succeed(&["on", "--for", "10s"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("already cached before this activation"),
        "missing already-cached warning:\n{stdout}"
    );
    // A short hold under the 30s max needs no max-ttl warning.
    assert!(!stdout.contains("max-cache-ttl is 30s"), "{stdout}");
}

#[test]
fn ordinary_indefinite_hold_warns_about_the_hard_maximum() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_cache_ttls(10, 30);
    let out = env.succeed(&["on"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("will eventually end an ordinary hold"),
        "{stdout}"
    );
}

#[test]
fn ordinary_mode_warns_when_interval_meets_default_ttl() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_cache_ttls(10, 30);
    let out = env.succeed(&["on", "--interval", "10s"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("not shorter than GnuPG's default-cache-ttl (10s)"),
        "{stdout}"
    );
}

#[test]
fn fresh_unlock_suppresses_the_already_cached_warning() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_cache_ttls(10, 30);
    let out = env.succeed(&["on", "--for", "10s"]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        !stdout.contains("already cached"),
        "warned despite a fresh unlock:\n{stdout}"
    );
    assert!(
        !stdout.contains("max-cache-ttl"),
        "warned for a hold under the maximum:\n{stdout}"
    );
}

#[test]
fn missing_ttl_tooling_degrades_to_a_silent_ordinary_hold() {
    let env = TestEnv::new();
    env.rich_gpg();
    let mut cmd = env.keyhold(&["on", "--for", "10s"]);
    // No gpgconf anywhere: neither the override nor PATH provides it.
    cmd.env_remove("KEYHOLD_GPGCONF")
        .env_remove("KEYHOLD_GPG_CONNECT_AGENT")
        .env("PATH", "/nonexistent");
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(!stdout.contains("warning"), "{stdout}");
    // TTL rows are absent from status rather than guessed.
    let text = env.status();
    assert!(!text.contains("GPG max TTL"), "{text}");
    assert!(!text.contains("Max expiry"), "{text}");
}

#[test]
fn status_reports_live_key_and_credential_rows() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_cache_ttls(10, 30);
    env.set_key_cached(true);
    env.succeed(&["on", "--for", "10s", "--interval", "100ms"]);
    let text = env.status();
    for needle in [
        "Key state    unlocked",
        "Credential   not in use",
        "GPG max TTL  30s",
        // A fresh foreground unlock established the epoch, so a
        // truthful countdown is shown (a pre-existing entry would read
        // "unknown"; see the already-cached warning test).
        "Max expiry   in 30s",
    ] {
        assert!(text.contains(needle), "missing {needle:?}:\n{text}");
    }
    // The resolved signing subkey drives the daemon's exact pings.
    assert!(
        wait_until_exact_pings(&env, 1),
        "daemon did not ping the exact subkey: {}",
        env.gpg_log()
    );
}

fn wait_until_exact_pings(env: &TestEnv, min: usize) -> bool {
    common::wait_until(5 * SECS, || {
        env.gpg_log()
            .lines()
            .filter(|l| {
                l.contains("cancel")
                    && l.contains(
                        "--local-user 97CF31DBA5F6012341995ED8F3C83A12ADCE45A1!",
                    )
            })
            .count()
            >= min
    })
}

#[test]
fn status_reports_locked_and_unprotected_key_states() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_key_cached(false);
    env.succeed(&["on", "--for", "10s"]);
    assert!(
        env.status().contains("Key state    locked"),
        "{}",
        env.status()
    );

    // An unprotected key is usable without any cached passphrase.
    let env2 = TestEnv::new();
    env2.rich_gpg();
    env2.set_key_protection("C");
    env2.succeed(&["on", "--for", "10s"]);
    let text = env2.status();
    assert!(
        text.contains("Key state    unlocked (unprotected)"),
        "{text}"
    );
}

#[test]
fn unprotected_key_activates_stored_mode_without_secret_service() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_key_protection("C");
    // -s with an unprotected key never needs the Secret Service.
    env.succeed(&["on", "-s", "--for", "10s"]);
    let text = env.status();
    assert!(text.contains("Credential   not needed"), "{text}");
    assert!(!env.ca_log().contains("CLEAR_PASSPHRASE"));
}

#[test]
fn stored_mode_without_secret_service_leaves_the_cache_untouched() {
    let env = TestEnv::new();
    env.rich_gpg();
    let out = env.fail(&["on", "-s"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("could not read the session credential"),
        "{stderr}"
    );
    assert!(stderr.contains("NOT enabled"), "{stderr}");
    // No CLEAR happened before the credential was available.
    assert!(!env.ca_log().contains("CLEAR_PASSPHRASE"));
    assert!(env.status().contains("Hold         off"));
}

#[test]
fn credential_clear_without_secret_service_is_an_error() {
    let env = TestEnv::new();
    let out = env.fail(&["credential", "clear"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("secret service error"), "{stderr}");
    // Nothing was started or cleared.
    assert!(env.status().contains("Daemon       stopped"));
    assert_eq!(env.ca_log(), "");
    assert_eq!(env.gpg_log(), "");
}

// ---------------------------------------------------------------------------
// Daemon-shutdown cleanup policies
// ---------------------------------------------------------------------------

fn write_config(env: &TestEnv, body: &str) {
    std::fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    std::fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        body,
    )
    .unwrap();
}

#[test]
fn lock_key_on_daemon_stop_clears_the_active_keygrip() {
    let env = TestEnv::new();
    env.rich_gpg();
    write_config(&env, "lock_key_on_daemon_stop = true\n");
    env.succeed(&["on", "--for", "1h"]);
    assert!(!env.ca_log().contains("CLEAR_PASSPHRASE"));

    env.succeed(&["daemon", "--stop"]);
    assert!(
        common::wait_until(5 * SECS, || {
            env.ca_log().contains(
            "CLEAR_PASSPHRASE --mode=normal F097020B875D80D64C742456496ECA8F47CED17F"
        )
        }),
        "cleanup clear missing: {}",
        env.ca_log()
    );
    // Only the active signing key's entry: exactly one clear.
    assert_eq!(
        env.ca_log()
            .lines()
            .filter(|l| l.starts_with("CLEAR_PASSPHRASE"))
            .count(),
        1,
        "{}",
        env.ca_log()
    );
}

#[test]
fn daemon_stop_uses_the_shutdown_config_edited_while_running() {
    let env = TestEnv::new();
    env.rich_gpg();
    // Both policies off at daemon start.
    write_config(&env, "");
    env.succeed(&["on", "--for", "1h"]);
    env.succeed(&["off"]);

    // Enabled while the daemon is still alive: the current config must
    // govern teardown, and the retained keygrip is still known.
    write_config(&env, "lock_key_on_daemon_stop = true\n");
    env.succeed(&["daemon", "--stop"]);
    assert!(
        common::wait_until(5 * SECS, || {
            env.ca_log().contains(
                "CLEAR_PASSPHRASE --mode=normal \
                 F097020B875D80D64C742456496ECA8F47CED17F",
            )
        }),
        "edited-in lock policy did not clear the retained key: {}",
        env.ca_log()
    );
    assert_eq!(
        env.ca_log()
            .lines()
            .filter(|l| l.starts_with("CLEAR_PASSPHRASE"))
            .count(),
        1,
        "{}",
        env.ca_log()
    );
}

#[test]
fn daemon_stop_uses_a_shutdown_config_disabled_while_running() {
    let env = TestEnv::new();
    env.rich_gpg();
    write_config(&env, "lock_key_on_daemon_stop = true\n");
    env.succeed(&["on", "--for", "1h"]);
    env.succeed(&["off"]);

    // The user disables the policy while the daemon is alive: a clean
    // read at shutdown takes the current (disabled) value.
    write_config(&env, "");
    env.succeed(&["daemon", "--stop"]);
    assert!(
        common::wait_until(5 * SECS, || !env.sock().exists()),
        "socket not removed"
    );
    assert!(
        !env.ca_log().contains("CLEAR_PASSPHRASE"),
        "disabled policy still cleared: {}",
        env.ca_log()
    );
}

#[test]
fn daemon_stop_with_unreadable_config_falls_back_to_start_policies() {
    let env = TestEnv::new();
    env.rich_gpg();
    write_config(&env, "lock_key_on_daemon_stop = true\n");
    env.succeed(&["on", "--for", "1h"]);
    env.succeed(&["off"]);

    // Malformed config at shutdown: the read fails, but a policy
    // enabled at startup is never silently weakened, and the socket is
    // still removed.
    write_config(&env, "this is not valid toml [[[ not even close\n");
    env.succeed(&["daemon", "--stop"]);
    assert!(
        common::wait_until(5 * SECS, || {
            !env.sock().exists()
                && env.ca_log().contains(
                    "CLEAR_PASSPHRASE --mode=normal \
                     F097020B875D80D64C742456496ECA8F47CED17F",
                )
        }),
        "fallback cleanup missing: {}",
        env.ca_log()
    );
}

#[test]
fn daemon_stop_without_policies_clears_nothing() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.succeed(&["on", "--for", "1h"]);
    env.succeed(&["daemon", "--stop"]);
    assert!(
        common::wait_until(5 * SECS, || !env.sock().exists()),
        "socket not removed"
    );
    assert!(
        !env.ca_log().contains("CLEAR_PASSPHRASE"),
        "{}",
        env.ca_log()
    );
}

#[test]
fn off_never_runs_the_shutdown_policies() {
    let env = TestEnv::new();
    env.rich_gpg();
    write_config(
        &env,
        "lock_key_on_daemon_stop = true\nclear_secret_on_daemon_stop = true\n",
    );
    env.succeed(&["on", "--for", "1h"]);
    env.succeed(&["off"]);
    thread::sleep(Duration::from_millis(300));
    assert!(
        !env.ca_log().contains("CLEAR_PASSPHRASE"),
        "{}",
        env.ca_log()
    );
    // The daemon is still running.
    assert!(env.status().contains("Daemon       running"));
}

#[test]
fn sigint_runs_the_same_cleanup_as_stop() {
    let env = TestEnv::new();
    env.rich_gpg();
    write_config(&env, "lock_key_on_daemon_stop = true\n");
    let mut daemon = spawn_daemon(&env);
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "daemon did not start"
    );
    env.succeed(&["on", "--for", "1h"]);

    send_signal(&daemon, "INT");
    wait_with_kill(&mut daemon, 5 * SECS);
    assert!(daemon.wait().unwrap().success());
    assert!(
        common::wait_until(5 * SECS, || {
            env.ca_log().contains(
            "CLEAR_PASSPHRASE --mode=normal F097020B875D80D64C742456496ECA8F47CED17F"
        )
        }),
        "SIGINT cleanup missing: {}",
        env.ca_log()
    );
}

#[test]
fn cleanup_failure_does_not_break_shutdown() {
    let env = TestEnv::new();
    env.rich_gpg();
    // clear_secret policy, but no Secret Service exists in tests.
    write_config(&env, "clear_secret_on_daemon_stop = true\n");
    let mut daemon = env
        .keyhold(&["daemon"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    assert!(
        wait_for_status(&env, "Daemon       running", 5 * SECS),
        "daemon did not start"
    );
    env.succeed(&["on", "--for", "1h"]);

    send_signal(&daemon, "TERM");
    // The cleanup error is reported (detached: stderr is /dev/null),
    // and the daemon still exits successfully with the socket removed.
    wait_with_kill(&mut daemon, 5 * SECS);
    assert!(daemon.wait().unwrap().success());
    assert!(
        common::wait_until(5 * SECS, || !env.sock().exists()),
        "socket not removed despite cleanup failure"
    );
}

/// `keyhold off` ends the hold, not the retained security state: with
/// a resolved key the live `Key state`/`Credential` rows stay visible
/// while hold timing rows disappear.
#[test]
fn status_after_off_reports_the_retained_key_state() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_key_cached(true);
    env.succeed(&["on", "--for", "10s"]);
    env.succeed(&["off"]);

    let text = env.status();
    assert!(text.contains("Hold         off"), "{text}");
    assert!(text.contains("Key          default"), "{text}");
    assert!(text.contains("Key state    unlocked"), "{text}");
    assert!(text.contains("Credential   not in use"), "{text}");
    for absent in ["Interval", "Remaining", "Next ping", "Last ping"] {
        assert!(!text.contains(absent), "{absent} shown while off:\n{text}");
    }

    // The row is a live snapshot: an external cache clear flips it.
    env.set_key_cached(false);
    let text = env.status();
    assert!(text.contains("Key state    locked"), "{text}");
}

/// The same retained rows after a timed hold expires by itself.
#[test]
fn status_after_expiry_reports_the_retained_key_state() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_key_cached(true);
    env.succeed(&["on", "--for", "500ms", "--interval", "100ms"]);
    assert!(
        wait_for_status(&env, "Hold         off", 5 * SECS),
        "hold did not expire: {}",
        env.status()
    );
    let text = env.status();
    assert!(text.contains("Key state    unlocked"), "{text}");
    assert!(text.contains("Credential   not in use"), "{text}");
    assert!(!text.contains("Next ping"), "{text}");
}

/// Without a previously resolved key there is nothing truthful to
/// show: no key rows are fabricated while the hold is off.
#[test]
fn status_after_off_without_a_resolved_key_shows_no_key_rows() {
    let env = TestEnv::new();
    // No `rich` marker: activation cannot resolve a signing target.
    env.succeed(&["on", "--for", "10s"]);
    env.succeed(&["off"]);
    let text = env.status();
    assert_eq!(
        text,
        "Keyhold status\n\nDaemon       running\nHold         off\n"
    );
}
