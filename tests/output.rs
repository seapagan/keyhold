//! Terminal presentation tests: `keyhold`'s wiring of `colored_text`.
//!
//! Colour policy itself (terminal detection, `NO_COLOR`/`FORCE_COLOR`/
//! `CLICOLOR`, depth) belongs to `colored_text` and is not retested here;
//! these tests prove the binary actually styles its semantic fragments
//! and stays plain for captured output.

mod common;

use std::process::Output;

use common::TestEnv;

/// Run keyhold with extra environment variables set (and `NO_COLOR`
/// removed unless explicitly provided, so forcing works even when the
/// test runner exports it).
fn run_with(env: &TestEnv, args: &[&str], vars: &[(&str, &str)]) -> Output {
    let mut cmd = env.keyhold(args);
    cmd.env_remove("NO_COLOR");
    for (key, value) in vars {
        cmd.env(key, value);
    }
    cmd.output().expect("run keyhold")
}
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Remove ANSI SGR sequences so visible text can be asserted next to
/// escape assertions on the raw string.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.next() == Some('[') {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}
#[test]
fn captured_output_stays_plain() {
    let env = TestEnv::new();

    let out = env.succeed(&["on", "--for", "30m"]);
    let stdout = text(&out.stdout);
    assert_eq!(stdout, "Keyhold enabled for 30m.\n");

    let out = env.succeed(&["off"]);
    assert_eq!(text(&out.stdout), "Keyhold disabled.\n");

    let out = env.succeed(&["daemon", "--stop"]);
    assert_eq!(text(&out.stdout), "Daemon stopped.\n");

    // Error output on stderr is plain text with the usual prefix.
    env.fail_all_pings();
    let out = env.fail(&["on"]);
    let stderr = text(&out.stderr);
    assert!(stderr.starts_with("keyhold: error:"), "{stderr}");
    assert!(!stderr.contains('\x1b'), "{stderr:?}");
    // No ANSI leaked into any captured stdout either.
    assert!(!text(&out.stdout).contains('\x1b'));
}

#[test]
fn forced_color_styles_success_output() {
    let env = TestEnv::new();

    // `enabled` green, the duration cyan, connecting prose plain.
    let out = run_with(&env, &["on", "--for", "30m"], &[("FORCE_COLOR", "1")]);
    let stdout = text(&out.stdout);
    assert!(out.status.success(), "{stdout}");
    assert!(stdout.contains("Keyhold "), "{stdout:?}");
    assert!(stdout.contains("\x1b[32m"), "no green: {stdout:?}");
    assert!(stdout.contains("\x1b[36m30m"), "no cyan: {stdout:?}");

    // Deactivation is the yellow inactive state.
    let out = run_with(&env, &["off"], &[("FORCE_COLOR", "1")]);
    assert!(text(&out.stdout).contains("\x1b[33m"));

    // Daemon stop success is green; "not running" is yellow (deterministic:
    // wait for the socket file to disappear between the two stops).
    let out = run_with(&env, &["daemon", "--stop"], &[("FORCE_COLOR", "1")]);
    let stdout = text(&out.stdout);
    assert_eq!(strip_ansi(&stdout), "Daemon stopped.\n", "{stdout:?}");
    assert!(stdout.contains("\x1b[32m"), "{stdout:?}");
    assert!(
        common::wait_until(std::time::Duration::from_secs(5), || {
            !env.sock().exists()
        }),
        "socket file was not removed"
    );
    let out = run_with(&env, &["daemon", "--stop"], &[("FORCE_COLOR", "1")]);
    let stdout = text(&out.stdout);
    assert_eq!(strip_ansi(&stdout), "Daemon not running.\n", "{stdout:?}");
    assert!(stdout.contains("\x1b[33m"), "{stdout:?}");
}

#[test]
fn forced_color_styles_error_output_on_stderr() {
    let env = TestEnv::new();
    env.fail_all_pings();

    let out = run_with(&env, &["on"], &[("FORCE_COLOR", "1")]);
    assert!(!out.status.success());
    let stderr = text(&out.stderr);
    assert!(stderr.contains("error:"), "{stderr}");
    assert!(stderr.contains("\x1b[31m"), "no red prefix: {stderr:?}");
    // The message body itself stays unstyled.
    assert!(stderr.contains("the hold was NOT enabled"), "{stderr}");
}

#[test]
fn no_color_beats_forced_color() {
    let env = TestEnv::new();
    let out = run_with(
        &env,
        &["on", "--for", "30m"],
        &[("FORCE_COLOR", "1"), ("NO_COLOR", "1")],
    );
    assert!(out.status.success());
    let stdout = text(&out.stdout);
    assert_eq!(stdout, "Keyhold enabled for 30m.\n");
    assert!(!stdout.contains('\x1b'), "{stdout:?}");
}

#[test]
fn status_uses_aligned_two_column_layout() {
    const STOPPED: &str =
        "Keyhold status\n\nDaemon     stopped\nHold       off\n";
    const RUNNING_OFF: &str =
        "Keyhold status\n\nDaemon     running\nHold       off\n";

    // Stopped daemon: heading plus two rows, values in one column.
    let env = TestEnv::new();
    assert_eq!(env.status(), STOPPED);

    // Running daemon, hold on: only meaningful rows, same value column.
    env.succeed(&["on", "--for", "1h"]);
    let text = env.status();
    assert!(text.starts_with("Keyhold status\n\n"), "{text}");
    let rows: Vec<&str> = text.lines().skip(2).collect();
    assert_eq!(rows[0], "Daemon     running", "{text}");
    assert_eq!(rows[1], "Hold       on", "{text}");
    assert!(text.contains("Key        default"), "{text}");
    assert!(text.contains("Interval   5m"), "{text}");
    assert!(text.contains("Remaining  "), "{text}");
    assert!(text.contains("Last ping  "), "{text}");
    assert!(text.contains("Next ping  in "), "{text}");
    for row in &rows {
        assert!(
            row.len() > 11
                && !row[11..].is_empty()
                && row[..11].ends_with("  "),
            "misaligned row: {row:?}"
        );
    }

    // Running daemon, hold off: timing/key/ping rows are omitted.
    env.succeed(&["off"]);
    assert_eq!(env.status(), RUNNING_OFF);
}

#[test]
fn status_styling_does_not_shift_alignment() {
    let env = TestEnv::new();
    env.succeed(&["on", "--for", "1h"]);
    let out = run_with(&env, &["status"], &[("FORCE_COLOR", "1")]);
    assert!(out.status.success());
    let stdout = text(&out.stdout);
    assert!(stdout.contains('\x1b'), "not styled: {stdout:?}");

    // Strip the ANSI sequences: the visible layout is identical to the
    // plain rendering, so styling never affected the columns.
    let plain = strip_ansi(&stdout);
    assert!(plain.starts_with("Keyhold status\n\n"), "{plain}");
    for row in plain.lines().skip(2) {
        assert!(
            row.len() > 11
                && !row[11..].is_empty()
                && row[..11].ends_with("  "),
            "misaligned styled row: {row:?}"
        );
    }
    assert!(plain.contains("Daemon     running"), "{plain}");
    assert!(plain.contains("Hold       on"), "{plain}");
}
