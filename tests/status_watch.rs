//! Status watch CLI and configuration contracts, without a real daemon.

mod common;

use clap::Parser;
use common::TestEnv;
use keyhold::{
    cli::{Cli, Command},
    config,
};
use std::{fs, time::Duration};

fn configure(env: &TestEnv, text: &str) {
    let dir = env.config.path().join("keyhold");
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.toml"), text).unwrap();
}

#[test]
fn status_accepts_watch_aliases_and_refresh_durations() {
    for args in [
        vec!["status", "-w"],
        vec!["status", "--watch"],
        vec!["status", "--no-watch"],
        vec!["status", "-w", "-i", "0.5"],
        vec!["status", "--interval", "2.25"],
        vec!["status", "--interval", "500ms"],
        vec!["status", "--interval", "1m"],
        vec!["status", "--interval", "0.25"],
    ] {
        assert!(
            Cli::try_parse_from(
                std::iter::once("keyhold").chain(args.clone())
            )
            .is_ok(),
            "{args:?}"
        );
    }
}

#[test]
fn status_rejects_conflicts_invalid_intervals_and_global_watch_flags() {
    for flags in [
        vec!["--watch", "--no-watch"],
        vec!["-w", "--no-watch"],
        vec!["--no-watch", "--interval", "2"],
    ] {
        let err = Cli::try_parse_from(
            ["keyhold", "status"].into_iter().chain(flags),
        )
        .unwrap_err();
        assert_eq!(err.kind(), clap::error::ErrorKind::ArgumentConflict);
    }
    for value in [
        "0",
        "0s",
        "0.249",
        "249ms",
        "-1",
        "NaN",
        "inf",
        "1e999",
        "18446744073709551616",
        "banana",
    ] {
        assert!(
            Cli::try_parse_from(["keyhold", "status", "-i", value]).is_err(),
            "{value}"
        );
    }
    for args in [["keyhold", "-w", "status"], ["keyhold", "on", "-w"]] {
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn watch_help_and_noninteractive_guard_are_wired() {
    let env = TestEnv::new();
    let help = env.stdout(&["status", "--help"]);
    for needle in ["--watch", "--no-watch", "--interval", "refresh"] {
        assert!(help.contains(needle), "{help}");
    }
    for args in [vec!["status", "-w"], vec!["status", "-i", "0.5"]] {
        let out = env.fail(&args);
        assert!(out.stdout.is_empty());
        assert!(String::from_utf8_lossy(&out.stderr).contains("interactive"));
    }
    assert!(!env.sock().exists());
    assert!(env.gpg_log().is_empty());
}

#[test]
fn config_watch_precedence_preserves_one_shot_output() {
    let env = TestEnv::new();
    let stopped = keyhold::presentation::format_status_stopped();
    assert_eq!(env.stdout(&["status"]), stopped);
    configure(&env, "interval = \"5m\"\n[status]\ninterval = 0.5\n");
    assert_eq!(env.stdout(&["status"]), stopped);
    configure(&env, "[status]\nwatch = true\ninterval = \"500ms\"\n");
    let out = env.fail(&["status"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("interactive"));
    assert_eq!(env.stdout(&["status", "--no-watch"]), stopped);
    configure(&env, "[status]\nwatch = false\ninterval = 2\n");
    assert_eq!(env.stdout(&["status"]), stopped);
    env.fail(&["status", "--watch"]);
}

#[test]
fn dotted_status_watch_defaults_control_dispatch() {
    let env = TestEnv::new();
    configure(&env, "'status' . \"watch\" = true # enabled");
    let out = env.fail(&["status"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("interactive"));
    configure(&env, "status.watch = false");
    let out = env.succeed(&["status"]);
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        keyhold::presentation::format_status_stopped()
    );
}

#[test]
fn invalid_status_config_fails_before_terminal_setup() {
    let env = TestEnv::new();
    for raw in [
        "unknown = true",
        "[status]\nunknown = true",
        "[status]\nwatch = 1",
        "[status]\ninterval = 0",
        "[status]\ninterval = 0.249",
        "[status]\ninterval = -2",
        "[status]\ninterval = nan",
        "[status]\ninterval = inf",
        "[status]\ninterval = \"249ms\"",
        "[status]\ninterval = \"bad\"",
    ] {
        configure(&env, raw);
        let out = env.fail(&["status", "-w"]);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(err.contains("invalid configuration file"), "{raw}: {err}");
        assert!(!err.contains('\x1b'));
        assert!(out.stdout.is_empty());
        if raw.starts_with("[status]") {
            let out = env.fail(&["status"]);
            assert!(
                String::from_utf8_lossy(&out.stderr)
                    .contains("invalid configuration file")
            );
        }
    }
}

#[test]
fn status_config_defaults_numbers_and_keepalive_are_independent() {
    let env = TestEnv::new();
    let defaults = config::load_from(env.config.path()).unwrap();
    assert!(!defaults.status.watch);
    assert_eq!(defaults.status.interval, Duration::from_secs(2));
    for (value, millis) in [
        ("2", 2000),
        ("2.25", 2250),
        ("0.25", 250),
        ("\"500ms\"", 500),
    ] {
        configure(
            &env,
            &format!("interval = \"1m\"\n[status]\ninterval = {value}"),
        );
        let config = config::load_from(env.config.path()).unwrap();
        assert_eq!(config.interval, Duration::from_secs(60));
        assert_eq!(config.status.interval, Duration::from_millis(millis));
        assert!(!config.status.watch);
    }
    configure(&env, "[status]");
    assert_eq!(
        config::load_from(env.config.path()).unwrap().status,
        defaults.status
    );
}

#[test]
fn effective_watch_options_follow_cli_then_config_then_defaults() {
    let env = TestEnv::new();
    configure(&env, "[status]\nwatch = true\ninterval = 1.5");
    let configured = config::load_from(env.config.path()).unwrap().status;
    for (flags, watch, millis) in [
        (vec![], true, 1500),
        (vec!["--no-watch"], false, 1500),
        (vec!["-i", "0.25"], true, 250),
        (vec!["-w", "-i", "2"], true, 2000),
    ] {
        let cli = Cli::try_parse_from(
            ["keyhold", "status"].into_iter().chain(flags),
        )
        .unwrap();
        let Command::Status(options) = cli.command else {
            panic!("status command")
        };
        let resolved = configured.resolve(&options);
        assert_eq!(resolved.watch, watch);
        assert_eq!(resolved.interval, Duration::from_millis(millis));
    }
    configure(&env, "[status]\nwatch = false\ninterval = 1");
    let configured = config::load_from(env.config.path()).unwrap().status;
    for flags in [vec!["-w"], vec!["-i", "0.5"]] {
        let cli = Cli::try_parse_from(
            ["keyhold", "status"].into_iter().chain(flags),
        )
        .unwrap();
        let Command::Status(options) = cli.command else {
            panic!("status command")
        };
        assert!(configured.resolve(&options).watch);
    }
}

#[test]
fn no_watch_bypasses_invalid_configuration() {
    let env = TestEnv::new();
    for raw in [
        "nonsense [",
        "status.watch = true\nbroken [",
        "interval = \"bad\"\n[status]\nwatch = true",
        "key = \"ABCD\"\ngit_key = true\n[status]\nwatch = true",
        "[status]\nwatch = 1",
        "[status]\ninterval = 0",
    ] {
        configure(&env, raw);
        let out = env.succeed(&["status", "--no-watch"]);
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            keyhold::presentation::format_status_stopped(),
            "{raw}"
        );
        for args in [
            ["status", "--watch"].as_slice(),
            &["status", "--interval", "0.5"],
        ] {
            let out = env.fail(args);
            assert!(
                String::from_utf8_lossy(&out.stderr)
                    .contains("invalid configuration file"),
                "{raw}"
            );
        }
    }
}

#[test]
fn status_config_detection_uses_toml_keys() {
    let env = TestEnv::new();
    for raw in [
        "status.watch = true\ninterval = \"bad\"",
        " \"status\" . 'watch' = true # enabled\nunknown = true",
        "['status'] # enabled\nwatch = 1",
        "[status]\nwatch = true\nbroken [",
        "status.watch = true\nbroken [",
        "nonsense [",
    ] {
        configure(&env, raw);
        let out = env.fail(&["status"]);
        assert!(
            String::from_utf8_lossy(&out.stderr)
                .contains("invalid configuration file"),
            "{raw}"
        );
    }
    for raw in [
        "interval = \"bad\" # status.watch = true",
        "# [status]\n# status.watch = true\nunknown = true",
        "key = \"status.watch = true [status]\"\ngit_key = true",
        "[other]\nstatus.watch = true",
        "\"status.watch\" = true",
    ] {
        configure(&env, raw);
        let out = env.succeed(&["status"]);
        assert_eq!(
            String::from_utf8(out.stdout).unwrap(),
            keyhold::presentation::format_status_stopped(),
            "{raw}"
        );
    }
}

#[test]
fn refresh_interval_boundaries_are_duration_based() {
    use keyhold::cli::parse_refresh_interval;
    for (text, duration) in [
        ("0.25", Duration::from_millis(250)),
        ("250ms", Duration::from_millis(250)),
        ("0.250000001", Duration::new(0, 250_000_001)),
        ("2.25", Duration::from_millis(2250)),
        ("9223372036854775807s", Duration::from_secs(i64::MAX as u64)),
    ] {
        assert_eq!(parse_refresh_interval(text).unwrap(), duration, "{text}");
    }
    for text in [
        "0.249999999",
        "0",
        "-0.5",
        "NaN",
        "inf",
        "-inf",
        "1e999",
        "18446744073709551616",
        "18446744073709551616s",
        "1..0",
    ] {
        assert!(parse_refresh_interval(text).is_err(), "{text}");
    }
}

#[test]
fn no_watch_preserves_status_query_errors() {
    use std::{io::Write, os::unix::net::UnixListener, thread};
    let env = TestEnv::new();
    configure(&env, "[status]\nwatch = 1");
    fs::create_dir_all(env.sock().parent().unwrap()).unwrap();
    let listener = UnixListener::bind(env.sock()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        for index in 0..2 {
            let deadline = std::time::Instant::now() + Duration::from_secs(3);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock =>
                    {
                        assert!(std::time::Instant::now() < deadline);
                        thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("{error}"),
                }
            };
            if index == 1 {
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                assert!(matches!(
                    keyhold::ipc::read_request(&stream).unwrap().unwrap(),
                    keyhold::ipc::Request::Status
                ));
                writeln!(
                    stream,
                    "{}",
                    serde_json::to_string(&keyhold::ipc::Response::err(
                        "status unavailable"
                    ))
                    .unwrap()
                )
                .unwrap();
            }
        }
    });
    let out = env.fail(&["status", "--no-watch"]);
    server.join().unwrap();
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("status unavailable")
    );
    assert!(out.stdout.is_empty());
}
