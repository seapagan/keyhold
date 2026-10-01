//! Keygrip-scoped lock operations against isolated GPG and store fakes.

mod common;

use std::{sync::Arc, thread, time::Duration};

use keyhold::credential::CredentialStore;

use common::{
    DaemonTools, FakeStore, SUB_GRIP, SUB2_GRIP, ipc_at, on_request,
    spawn_daemon, status_at, stored_activation,
};

fn lock_request(clear: bool) -> String {
    format!("{{\"cmd\":\"lock\",\"clear_credential\":{clear}}}")
}

struct Fixture {
    tools: DaemonTools,
    store: Arc<FakeStore>,
    daemon: common::TestDaemon,
    on: String,
}

impl Fixture {
    fn stored() -> Self {
        let tools = DaemonTools::new();
        let store = Arc::new(FakeStore::default());
        store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());
        let daemon =
            spawn_daemon(tools.gpg.clone(), store.clone(), Default::default());
        let prepared =
            stored_activation(&tools.gpg, &store, None, 60_000, None).unwrap();
        let on = on_request(None, &prepared, 60_000, None);
        assert_eq!(ipc_at(daemon.sock(), &on).unwrap()["ok"], true);
        drop(prepared);
        Self {
            tools,
            store,
            daemon,
            on,
        }
    }

    fn request_lock(&self, clear: bool) -> serde_json::Value {
        let response =
            ipc_at(self.daemon.sock(), &lock_request(clear)).unwrap();
        for text in [
            response.to_string(),
            self.tools.gpg_log(),
            self.tools.ca_log(),
            self.store.operations().join("\n"),
        ] {
            assert!(
                !text.contains(common::FAKE_PASSPHRASE),
                "secret leaked into metadata or diagnostics"
            );
        }
        response
    }

    fn assert_off(&self) {
        let status = status_at(self.daemon.sock()).unwrap();
        assert_eq!(status["hold_on"], false);
        assert_eq!(status["keygrip"], SUB2_GRIP);
        assert!(status["last_error"].is_null());
    }

    fn renew_now(&self) {
        let mut request: serde_json::Value =
            serde_json::from_str(&self.on).unwrap();
        request["max_cache_ttl_ms"] = 2_000.into();
        request["cache_started_at_ms"] = 1.into();
        assert_eq!(
            ipc_at(self.daemon.sock(), &request.to_string()).unwrap()["ok"],
            true
        );
    }

    fn spawn_lock(
        &self,
        clear: bool,
    ) -> thread::JoinHandle<serde_json::Value> {
        let sock = self.daemon.sock().to_path_buf();
        thread::spawn(move || ipc_at(&sock, &lock_request(clear)).unwrap())
    }

    fn assert_cli_status(&self, env: &common::TestEnv) {
        let output = self.cli(env, &["status"]);
        let text = String::from_utf8_lossy(&output.stdout);
        assert!(text.contains("Daemon       running"));
        assert!(text.contains("Hold         off"));
        assert!(text.contains("Key state    locked"));
        // The CLI deliberately has no Secret Service; the daemon's injected
        // store and retained provenance are checked separately above.
        assert_eq!(
            status_at(self.daemon.sock()).unwrap()["credential_mode"],
            "session"
        );
    }

    fn cli(
        &self,
        env: &common::TestEnv,
        args: &[&str],
    ) -> std::process::Output {
        self.command(env, args).output().unwrap()
    }

    fn command(
        &self,
        env: &common::TestEnv,
        args: &[&str],
    ) -> std::process::Command {
        let mut command = env.keyhold(args);
        command
            .env(
                "XDG_RUNTIME_DIR",
                self.daemon.sock().parent().unwrap().parent().unwrap(),
            )
            .env("KEYHOLD_TEST_ROOT", &self.tools.root);
        command
    }

    fn spawn_cli(
        &self,
        env: &common::TestEnv,
        args: &[&str],
    ) -> common::CliChild {
        common::CliChild(
            self.command(env, args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .unwrap(),
        )
    }
}

#[test]
fn ordinary_cli_activation_during_lock_cannot_recreate_its_cleared_cache() {
    let fixture = Fixture::stored();
    let env = common::TestEnv::new();
    let clear = common::ToolGate::new(&fixture.tools.root, "clear");
    let mut locking = fixture.spawn_cli(&env, &["lock"]);
    clear.wait_until_entered();
    assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    let foregrounds = fixture.tools.gpg_log();
    let on = fixture.cli(&env, &["on", "--for", "1h"]);
    assert!(!on.status.success());
    assert!(
        String::from_utf8_lossy(&on.stderr).contains("lock is in progress")
    );
    clear.release();
    assert!(locking.output().status.success());
    fixture.assert_off();
    assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    assert_eq!(
        fixture.tools.gpg_log(),
        foregrounds,
        "rejected activation touched GPG"
    );
}

#[test]
fn cli_lock_drains_in_flight_ordinary_activation_before_clearing_cache() {
    let fixture = Fixture::stored();
    let env = common::TestEnv::new();
    let foreground = common::ToolGate::new(&fixture.tools.root, "foreground");
    let clear = common::ToolGate::new(&fixture.tools.root, "clear");
    let mut activating = fixture.spawn_cli(&env, &["on", "--for", "1h"]);
    foreground.wait_until_entered();
    let mut locking = fixture.spawn_cli(&env, &["lock", "--clear"]);
    assert!(common::wait_until(Duration::from_secs(5), || {
        status_at(fixture.daemon.sock()).unwrap()["hold_on"] == false
    }));
    let foregrounds = fixture.tools.gpg_log();
    let later = fixture.cli(&env, &["on", "--for", "1h"]);
    assert!(!later.status.success());
    assert!(
        String::from_utf8_lossy(&later.stderr).contains("lock is in progress")
    );
    assert_eq!(fixture.tools.gpg_log(), foregrounds);
    foreground.release();
    let rejected = activating.output();
    assert!(!rejected.status.success());
    assert!(
        String::from_utf8_lossy(&rejected.stderr)
            .contains("lock is in progress")
    );
    clear.wait_until_entered();
    assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    assert!(!fixture.store.contains_key(SUB2_GRIP));
    assert!(locking.0.try_wait().unwrap().is_none());
    clear.release();
    assert!(locking.output().status.success());
    fixture.assert_off();
    assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    assert!(!fixture.store.contains_key(SUB2_GRIP));
}

#[test]
fn cli_lock_credential_policy_obeys_explicit_overrides_and_config() {
    for (config, flag, cleared) in [
        (None, None, false),
        (Some(false), None, false),
        (Some(true), None, true),
        (Some(false), Some("-c"), true),
        (Some(false), Some("--clear"), true),
        (Some(true), Some("-k"), false),
        (Some(true), Some("--keep-credential"), false),
    ] {
        let fixture = Fixture::stored();
        let env = common::TestEnv::new();
        if let Some(policy) = config {
            std::fs::create_dir_all(env.config.path().join("keyhold"))
                .unwrap();
            std::fs::write(
                env.config.path().join("keyhold/config.toml"),
                format!("clear_secret_on_lock = {policy}\n"),
            )
            .unwrap();
        }
        let mut args = vec!["lock"];
        args.extend(flag);
        let output = fixture.cli(&env, &args);
        assert!(
            output.status.success(),
            "lock failed for {config:?}, {flag:?}"
        );
        assert!(
            String::from_utf8_lossy(&output.stdout)
                .contains("GPG key locked.")
        );
        assert!(output.stderr.is_empty());
        assert_eq!(fixture.store.contains_key(SUB2_GRIP), !cleared);
        fixture.assert_off();
        fixture.assert_cli_status(&env);
        let activation = stored_activation(
            &fixture.tools.gpg,
            &fixture.store,
            None,
            60_000,
            None,
        );
        if cleared {
            assert!(
                activation
                    .unwrap_err()
                    .to_string()
                    .contains("unexpected prompt")
            );
        } else {
            assert!(activation.is_ok());
        }
    }
}

#[test]
fn cli_lock_reports_unprotected_keys_and_cleanup_errors_truthfully() {
    let fixture = Fixture::stored();
    let env = common::TestEnv::new();
    fixture.tools.set_key_protection("C");
    let output = fixture.cli(&env, &["lock", "-c"]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("not passphrase-protected"));
    assert!(!text.contains("GPG key locked"));
    assert!(!fixture.store.contains_key(SUB2_GRIP));
    fixture.assert_off();
    fixture.tools.set_key_protection("P");
    fixture.tools.marker("fail-clear");
    let output = fixture.cli(&env, &["lock"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ERR 67109139"));
    fixture.assert_off();
}

#[test]
fn lock_waits_for_in_flight_renewal_then_removes_its_recreated_cache() {
    for clear in [false, true] {
        let fixture = Fixture::stored();
        let load = fixture.store.block_next_load();
        fixture.renew_now();
        load.wait_until_entered();
        let contention = fixture.store.observe_next_lock_contention();
        let locking = fixture.spawn_lock(clear);
        assert_eq!(
            contention.recv_timeout(Duration::from_secs(5)).unwrap(),
            SUB2_GRIP
        );
        fixture.assert_off();
        assert!(
            !locking.is_finished(),
            "lock returned before renewal finished"
        );
        let loopbacks = fixture.tools.loopbacks();
        load.release();
        assert_eq!(locking.join().unwrap()["ok"], true);
        assert_eq!(fixture.tools.loopbacks(), loopbacks + 1);
        fixture.assert_off();
        assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
        assert_eq!(fixture.store.contains_key(SUB2_GRIP), !clear);
        // The global store barrier drains any remaining per-key transaction.
        fixture.store.clear_all().unwrap();
        assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    }
}

#[test]
fn renewal_queued_behind_lock_aborts_without_recreating_cache() {
    let fixture = Fixture::stored();
    let renewal = fixture.store.block_next_transaction();
    fixture.renew_now();
    renewal.wait_until_entered();
    let deletion = fixture.store.block_next_delete();
    let locking = fixture.spawn_lock(true);
    deletion.wait_until_entered();
    let contention = fixture.store.observe_next_lock_contention();
    renewal.release();
    assert_eq!(
        contention.recv_timeout(Duration::from_secs(5)).unwrap(),
        SUB2_GRIP
    );
    let loopbacks = fixture.tools.loopbacks();
    let loads = fixture.store.operations();
    fixture.assert_off();
    // An overlapping activation must not invalidate lock's postcondition.
    let on = ipc_at(fixture.daemon.sock(), &fixture.on).unwrap();
    assert_eq!(on["ok"], false);
    assert!(
        on["error"]
            .as_str()
            .unwrap()
            .contains("lock is in progress")
    );
    deletion.release();
    assert_eq!(locking.join().unwrap()["ok"], true);
    fixture.store.clear_all().unwrap();
    assert_eq!(fixture.tools.loopbacks(), loopbacks);
    assert_eq!(
        fixture
            .store
            .operations()
            .iter()
            .filter(|s| s.starts_with("load:"))
            .count(),
        loads.iter().filter(|s| s.starts_with("load:")).count()
    );
    fixture.assert_off();
    assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
}

#[test]
fn cache_failures_leave_hold_off_and_keep_successful_credential_deletion() {
    for (marker, error) in [
        ("fail-clear", "ERR 67109139"),
        ("malformed-ca", "malformed"),
        ("hang-clear", "timed out"),
    ] {
        let mut fixture = Fixture::stored();
        if marker == "hang-clear" {
            fixture.daemon.shutdown().unwrap();
            fixture.daemon = spawn_daemon(
                fixture
                    .tools
                    .gpg
                    .clone()
                    .with_unattended_timeout(Duration::from_millis(100)),
                fixture.store.clone(),
                Default::default(),
            );
            assert_eq!(
                ipc_at(fixture.daemon.sock(), &fixture.on).unwrap()["ok"],
                true
            );
        }
        fixture.tools.marker(marker);
        let response = fixture.request_lock(true);
        assert_eq!(response["ok"], false, "{response}");
        assert!(
            response["error"].as_str().unwrap().contains(error),
            "{response}"
        );
        assert!(response.get("lock_result").is_none());
        fixture.assert_off();
        assert!(!fixture.store.contains_key(SUB2_GRIP));
    }
}

#[test]
fn deletion_failure_still_clears_cache_and_reports_failure() {
    let fixture = Fixture::stored();
    fixture.store.make_deletes_fail();
    let response = fixture.request_lock(true);
    assert_eq!(response["ok"], false);
    assert!(
        response["error"]
            .as_str()
            .unwrap()
            .contains("session credential deletion failed")
    );
    fixture.assert_off();
    assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    assert!(fixture.store.contains_key(SUB2_GRIP));
    fixture.tools.marker("fail-clear");
    let response = fixture.request_lock(true);
    assert!(
        response["error"]
            .as_str()
            .unwrap()
            .contains("cache cleanup failed")
    );
    assert!(
        response["error"]
            .as_str()
            .unwrap()
            .contains("session credential deletion failed")
    );
}

#[test]
fn unprotected_lock_honours_credential_policy_without_claiming_locked() {
    for clear in [false, true] {
        let fixture = Fixture::stored();
        fixture.tools.set_key_protection("C");
        let clears = fixture.tools.clears();
        let response = fixture.request_lock(clear);
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["lock_result"], "unprotected");
        assert_eq!(fixture.tools.clears(), clears);
        assert_eq!(fixture.store.contains_key(SUB2_GRIP), !clear);
        fixture.assert_off();
    }
}

#[test]
fn lock_disables_hold_and_preserves_only_retained_identity_and_credentials() {
    let tools = DaemonTools::new();
    let store = Arc::new(FakeStore::default());
    store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());
    store.preload(SUB_GRIP, b"unrelated fixture");
    let daemon =
        spawn_daemon(tools.gpg.clone(), store.clone(), Default::default());
    let prepared =
        stored_activation(&tools.gpg, &store, None, 60_000, None).unwrap();
    assert_eq!(
        ipc_at(daemon.sock(), &on_request(None, &prepared, 60_000, None))
            .unwrap()["ok"],
        true
    );
    drop(prepared);

    let response = ipc_at(daemon.sock(), &lock_request(false)).unwrap();
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["lock_result"], "locked");
    let status = status_at(daemon.sock()).unwrap();
    assert_eq!(status["hold_on"], false);
    assert_eq!(status["keygrip"], SUB2_GRIP);
    assert_eq!(status["credential_mode"], "session");
    assert!(!tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    assert!(store.contains_key(SUB2_GRIP));
    assert!(store.contains_key(SUB_GRIP));
    assert!(tools.gpg.key_state(SUB_GRIP).unwrap().cached);
    let clears: Vec<_> = tools
        .ca_log()
        .lines()
        .filter(|line| line.starts_with("CLEAR_PASSPHRASE"))
        .map(str::to_owned)
        .collect();
    assert_eq!(
        clears,
        vec![format!("CLEAR_PASSPHRASE --mode=normal {SUB2_GRIP} /bye"); 2]
    );
    assert!(!tools.ca_log().contains("RELOADAGENT"));
    assert!(!tools.ca_log().contains("KILLAGENT"));
    assert!(
        !store
            .operations()
            .iter()
            .any(|op| op.starts_with("delete:") || op == "clear_all")
    );
}

#[test]
fn no_resolved_key_disables_hold_and_never_guesses_or_touches_store() {
    let tools = DaemonTools::new();
    let store = Arc::new(FakeStore::default());
    let daemon =
        spawn_daemon(tools.gpg.clone(), store.clone(), Default::default());
    for active in [false, true] {
        if active {
            let request = r#"{"cmd":"on","key":"unresolved","key_source":"explicit","interval_ms":60000,"hold_ms":null,"activated_at_ms":1}"#;
            assert_eq!(ipc_at(daemon.sock(), request).unwrap()["ok"], true);
        }
        let response = ipc_at(daemon.sock(), &lock_request(true)).unwrap();
        assert_eq!(response["ok"], false);
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("no managed/resolved GPG key")
        );
        assert!(
            response["error"]
                .as_str()
                .unwrap()
                .contains("the hold was disabled")
        );
        assert_eq!(status_at(daemon.sock()).unwrap()["hold_on"], false);
        assert!(tools.gpg_log().is_empty());
        assert!(tools.ca_log().is_empty());
        assert!(store.operations().is_empty());
    }
}

#[test]
fn lock_uses_retained_key_after_off_expiry_and_failure() {
    for transition in ["off", "expiry", "failure"] {
        let fixture = Fixture::stored();
        let mut on: serde_json::Value =
            serde_json::from_str(&fixture.on).unwrap();
        match transition {
            "off" => {
                assert_eq!(
                    ipc_at(fixture.daemon.sock(), r#"{"cmd":"off"}"#).unwrap()
                        ["ok"],
                    true
                );
            }
            "expiry" => {
                on["hold_ms"] = 1.into();
                assert_eq!(
                    ipc_at(fixture.daemon.sock(), &on.to_string()).unwrap()["ok"],
                    true
                );
            }
            _ => {
                fixture.store.make_loads_fail();
                fixture.renew_now();
            }
        }
        assert!(common::wait_until(Duration::from_secs(5), || status_at(
            fixture.daemon.sock()
        )
        .unwrap()["hold_on"]
            == false));
        // A changed default/key listing must never affect the retained target.
        fixture.tools.set_keys("invalid replacement key listing");
        let response = fixture.request_lock(false);
        assert_eq!(response["ok"], true, "{transition}: {response}");
        fixture.assert_off();
        assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
        assert!(fixture.tools.gpg.key_state(SUB_GRIP).unwrap().cached);
    }
}

#[test]
fn unknown_key_protection_locks_cached_and_already_uncached_keys() {
    for cached in [true, false] {
        let fixture = Fixture::stored();
        fixture.tools.set_key_protection("-");
        if !cached {
            fixture.tools.drop_cache();
        }
        let clears = fixture.tools.clears();
        let response = fixture.request_lock(false);
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(response["lock_result"], "locked");
        assert_eq!(fixture.tools.clears(), clears + 1);
        assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
        assert!(fixture.tools.gpg.key_state(SUB_GRIP).unwrap().cached);
        assert!(fixture.store.contains_key(SUB2_GRIP));
        fixture.assert_off();
    }
}

#[test]
fn protection_query_failure_does_not_override_successful_cache_clear() {
    let fixture = Fixture::stored();
    fixture.tools.marker("fail-keyinfo");
    let response = fixture.request_lock(false);
    assert_eq!(response["ok"], true, "{response}");
    assert_eq!(response["lock_result"], "locked");
    fixture.tools.unmark("fail-keyinfo");
    assert!(!fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    assert!(fixture.tools.gpg.key_state(SUB_GRIP).unwrap().cached);
    assert!(fixture.store.contains_key(SUB2_GRIP));
    fixture.assert_off();
}

#[test]
fn unknown_key_protection_does_not_hide_cache_clear_failure() {
    let fixture = Fixture::stored();
    fixture.tools.set_key_protection("-");
    fixture.tools.marker("fail-clear");
    let response = fixture.request_lock(false);
    assert_eq!(response["ok"], false);
    assert!(
        response["error"]
            .as_str()
            .unwrap()
            .contains("CLEAR_PASSPHRASE: agent returned ERR 67109139")
    );
    assert!(response.get("lock_result").is_none());
    assert!(fixture.tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
    fixture.assert_off();
}

#[test]
fn clear_lock_deletes_only_managed_credential_and_is_idempotent() {
    let tools = DaemonTools::new();
    let store = Arc::new(FakeStore::default());
    store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());
    store.preload(SUB_GRIP, b"unrelated fixture");
    let daemon =
        spawn_daemon(tools.gpg.clone(), store.clone(), Default::default());
    let prepared =
        stored_activation(&tools.gpg, &store, None, 60_000, None).unwrap();
    assert_eq!(
        ipc_at(daemon.sock(), &on_request(None, &prepared, 60_000, None))
            .unwrap()["ok"],
        true
    );
    drop(prepared);
    for _ in 0..2 {
        let response = ipc_at(daemon.sock(), &lock_request(true)).unwrap();
        assert_eq!(response["ok"], true, "{response}");
        assert!(!store.contains_key(SUB2_GRIP));
        assert!(store.contains_key(SUB_GRIP));
        assert!(!tools.gpg.key_state(SUB2_GRIP).unwrap().cached);
        assert_eq!(status_at(daemon.sock()).unwrap()["hold_on"], false);
    }
}
