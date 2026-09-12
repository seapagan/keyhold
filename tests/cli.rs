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

#[test]
fn on_help_lists_store_passphrase_flags() {
    let env = TestEnv::new();
    let out = env.succeed(&["on", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    for needle in ["-s, --store-passphrase", "--no-store-passphrase"] {
        assert!(text.contains(needle), "on help missing {needle}:\n{text}");
    }
    // The security distinction stays visible in the help text.
    assert!(
        text.contains("opt-in") || text.contains("opt in"),
        "help does not mark the mode as opt-in:\n{text}"
    );
}

#[test]
fn store_passphrase_conflicts_with_no_store() {
    let env = TestEnv::new();
    for args in [
        vec!["on", "--store-passphrase", "--no-store-passphrase"],
        vec!["on", "-s", "--no-store-passphrase"],
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
fn credential_help_lists_clear() {
    let env = TestEnv::new();
    let out = env.succeed(&["credential", "--help"]);
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("clear"), "{text}");
    assert!(text.contains("Usage:"), "{text}");
}

#[test]
fn config_store_passphrase_true_enables_stored_mode() {
    let env = TestEnv::new();
    env.rich_gpg();
    std::fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    std::fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "store_passphrase = true\n",
    )
    .unwrap();

    // Stored mode requires the Secret Service, which the test
    // environment deliberately lacks: the failure proves the config
    // option took effect (ordinary mode needs no Secret Service).
    let out = env.fail(&["on"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("could not read the session credential")
            || stderr.contains("session credential mode"),
        "{stderr}"
    );
    // Retrieve-before-clear: no GPG cache entry was touched.
    assert!(!env.ca_log().contains("CLEAR_PASSPHRASE"));
    assert!(env.status().contains("Hold         off"));
}

#[test]
fn no_store_passphrase_overrides_the_config_default() {
    let env = TestEnv::new();
    env.rich_gpg();
    std::fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    std::fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "store_passphrase = true\n",
    )
    .unwrap();

    // The explicit per-invocation override restores ordinary mode.
    let out = env.succeed(&["on", "--no-store-passphrase", "--for", "1h"]);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "Keyhold enabled for 1h.\n"
    );
    assert!(env.status().contains("Hold         on"));
}

#[test]
fn cli_store_passphrase_short_form_enables_stored_mode() {
    let env = TestEnv::new();
    env.rich_gpg();
    let out = env.fail(&["on", "-s"]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("session credential"),
        "-s did not enable stored mode:\n{stderr}"
    );
}

#[test]
fn shutdown_policy_config_defaults_are_off_and_parse() {
    let env = TestEnv::new();
    std::fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    std::fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "clear_secret_on_daemon_stop = true\nlock_key_on_daemon_stop = true\n",
    )
    .unwrap();
    // The options parse; daemon start/stop with both enabled works even
    // though the (absent) Secret Service cannot be cleared.
    env.succeed(&["daemon", "-b"]);
    assert!(env.status().contains("Daemon       running"));
    env.succeed(&["daemon", "--stop"]);
    assert!(env.status().contains("Daemon       stopped"));
}
