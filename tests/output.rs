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
