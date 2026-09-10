//! CLI-surface integration tests (parsing, help, validation errors).

mod common;

use common::TestEnv;

#[test]
fn help_lists_commands_and_options() {
    let env = TestEnv::new();
    let out = env.succeed(&["--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in ["on", "off", "status", "daemon", "Usage:"] {
        assert!(text.contains(needle), "help missing {needle}:\n{text}");
    }
    // Clap's generated `help` subcommand is disabled: `--help` is the
    // only help convention.
    assert!(
        !text.contains("Print this message"),
        "root help still advertises a help subcommand:\n{text}"
    );
}

#[test]
fn subcommand_help_is_available() {
    let env = TestEnv::new();
    let out = env.succeed(&["on", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in ["--for", "--key", "--git-key", "--interval"] {
        assert!(text.contains(needle), "on help missing {needle}:\n{text}");
    }
}

#[test]
fn subcommand_help_works_for_every_subcommand() {
    let env = TestEnv::new();
    for subcommand in ["on", "off", "status", "daemon"] {
        let out = env.succeed(&[subcommand, "--help"]);
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(
            text.contains("Usage:"),
            "{subcommand} --help broken:\n{text}"
        );
    }
}

#[test]
fn help_subcommand_is_disabled() {
    let env = TestEnv::new();
    let out = env.fail(&["help"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("unrecognized subcommand"), "{stderr}");
}

#[test]
fn version_is_reported() {
    let env = TestEnv::new();
    let out = env.succeed(&["--version"]);
    assert!(
        String::from_utf8_lossy(&out.stdout)
            .contains(env!("CARGO_PKG_VERSION"))
    );
}

#[test]
fn no_arguments_shows_help() {
    let env = TestEnv::new();
    let out = env.fail(&[]);
    let text = String::from_utf8_lossy(&out.stderr);
    assert!(text.contains("Usage:"), "expected usage help:\n{text}");
}

#[test]
fn unitless_duration_is_rejected() {
    let env = TestEnv::new();
    let out = env.fail(&["on", "--for", "5"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("duration"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn zero_durations_are_rejected() {
    let env = TestEnv::new();
    let out = env.fail(&["on", "--for", "0s"]);
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("greater than zero")
    );
    env.fail(&["on", "--interval", "0m"]);
}

#[test]
fn daemon_help_lists_background_and_stop() {
    let env = TestEnv::new();
    let out = env.succeed(&["daemon", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in ["-b, --background", "--stop"] {
        assert!(
            text.contains(needle),
            "daemon help missing {needle}:\n{text}"
        );
    }
}

#[test]
fn background_conflicts_with_stop() {
    let env = TestEnv::new();
    for args in [
        vec!["daemon", "--background", "--stop"],
        vec!["daemon", "-b", "--stop"],
    ] {
        let out = env.fail(&args);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("cannot be used with"),
            "keyhold {args:?} not rejected:\n{stderr}"
        );
    }
}

#[test]
fn unknown_subcommand_is_rejected() {
    let env = TestEnv::new();
    env.fail(&["explode"]);
}
