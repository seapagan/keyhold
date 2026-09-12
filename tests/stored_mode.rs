//! In-process tests for the stored-passphrase mode: activation flow,
//! proactive renewal, recovery, credential-clear interaction, races and
//! daemon-shutdown cleanup — all against fake gpg tooling and a fake
//! credential store. No real GPG, D-Bus or Secret Service is touched.

mod common;

use std::{
    io::{Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    sync::Arc,
    thread,
    time::Duration,
};

use common::{
    DaemonTools, FakeStore, SUB_FPR, SUB_GRIP, SUB2_FPR, SUB2_GRIP, ipc_at,
    spawn_daemon, status_at, stored_activation, wait_until,
};
use keyhold::{
    activation,
    config::ShutdownPolicies,
    error::{Error, Result},
    gpg::{Gpg, KeyProtection, PingMode},
};
use zeroize::Zeroizing;

const SECS: Duration = Duration::from_secs(1);

/// A prompt stub that hands out the correct passphrase and records that
/// it was used.
struct Prompted {
    asked: std::sync::atomic::AtomicUsize,
    answer: &'static str,
}

impl Prompted {
    fn new(answer: &'static str) -> Self {
        Self {
            asked: std::sync::atomic::AtomicUsize::new(0),
            answer,
        }
    }

    fn count(&self) -> usize {
        self.asked.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn as_fn(&self) -> impl Fn() -> Result<Zeroizing<Vec<u8>>> + '_ {
        move || {
            self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(Zeroizing::new(self.answer.as_bytes().to_vec()))
        }
    }
}

fn no_prompt() -> Result<Zeroizing<Vec<u8>>> {
    Err(Error::Message("unexpected prompt".into()))
}

// ---------------------------------------------------------------------------
// Activation flow
// ---------------------------------------------------------------------------

#[test]
fn first_stored_activation_prompts_validates_and_stores() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();
    // Cache starts hot (unlocked) so probing resolves via SIG_CREATED.
    assert!(!tools.has("locked"));

    let prompted = Prompted::new(common::FAKE_PASSPHRASE);
    let prompt = prompted.as_fn();
    let prepared = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &prompt,
    )
    .expect("activation succeeds");
    assert_eq!(prompted.count(), 1, "exactly one prompt");
    assert!(prepared.credential_mutated, "fresh credential was stored");
    assert!(prepared.target.is_some());
    let cache = prepared.cache.expect("cache plan");
    assert_eq!(cache.mode, keyhold::state::CredentialMode::Session);
    assert!(cache.started_wall.is_some(), "epoch established");

    // The exact signing subkey resolved, the epoch established with a
    // keygrip-scoped clear, and the credential stored after validation.
    assert!(store.contains_key(SUB2_GRIP), "credential stored");
    let ops = store.operations();
    assert_eq!(
        ops.last().map(String::as_str),
        Some("store:F097020B875D80D64C742456496ECA8F47CED17F")
    );
    let ca = tools.ca_log();
    assert!(
        ca.contains(&format!("CLEAR_PASSPHRASE --mode=normal {SUB2_GRIP}")),
        "{ca}"
    );
    assert!(tools.loopbacks() >= 1, "loopback validation happened");
    // The passphrase never reached the gpg command line (stdin only).
    assert!(
        !tools.gpg_log().contains(common::FAKE_PASSPHRASE),
        "secret leaked to argv/log"
    );
}

#[test]
fn stored_activation_reuses_an_existing_credential_without_prompting() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();
    store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());

    let prepared = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &no_prompt,
    )
    .expect("reuse activation succeeds");
    assert_eq!(
        prepared.cache.unwrap().mode,
        keyhold::state::CredentialMode::Session
    );
    assert!(
        !prepared.credential_mutated,
        "reused credential was not replaced"
    );
    // Validated with the stored credential (loopback happened) and not
    // stored again.
    assert!(tools.loopbacks() >= 1);
    assert!(
        !store.operations().iter().any(|op| op.starts_with("store")),
        "no re-store: {:?}",
        store.operations()
    );
}

#[test]
fn stale_stored_credential_is_replaced_after_one_prompt() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();
    store.preload(SUB2_GRIP, b"stale-wrong-passphrase");

    let prompted = Prompted::new(common::FAKE_PASSPHRASE);
    let prompt = prompted.as_fn();
    let prepared = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &prompt,
    )
    .expect("replacement activation succeeds");
    assert_eq!(prompted.count(), 1);
    assert!(prepared.credential_mutated, "stale credential was replaced");
    assert_eq!(
        prepared.cache.unwrap().mode,
        keyhold::state::CredentialMode::Session
    );
    let ops = store.operations();
    // The stale item was deleted and the replacement stored, in order.
    let delete = ops
        .iter()
        .position(|op| op == &format!("delete:{SUB2_GRIP}"))
        .expect("stale deleted");
    let store_at = ops
        .iter()
        .position(|op| op == &format!("store:{SUB2_GRIP}"))
        .expect("replacement stored");
    assert!(delete < store_at, "{ops:?}");
}

#[test]
fn secret_service_outage_leaves_the_gpg_cache_untouched() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();
    store.make_loads_fail();

    let err = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &no_prompt,
    )
    .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("could not read the session credential"),
        "{text}"
    );
    assert!(text.contains("left untouched"), "{text}");
    assert!(text.contains("NOT enabled"), "{text}");
    // The retrieve-before-clear invariant: nothing was cleared.
    assert_eq!(tools.clears(), 0, "cache entry was cleared anyway");
}

#[test]
fn unprotected_key_needs_no_credential() {
    let tools = DaemonTools::new();
    tools.set_key_protection("C");
    let store = FakeStore::default();

    let prepared = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &no_prompt,
    )
    .expect("unprotected key activates");
    let cache = prepared.cache.unwrap();
    assert_eq!(cache.mode, keyhold::state::CredentialMode::NotNeeded);
    assert!(cache.started_wall.is_none());
    assert!(!prepared.credential_mutated);
    assert!(
        !store
            .operations()
            .iter()
            .any(|op| op != "load:F097020B875D80D64C742456496ECA8F47CED17F"
                || true),
        "store untouched: {:?}",
        store.operations()
    );
    assert_eq!(tools.clears(), 0, "no cache entry exists to clear");
}

#[test]
fn unknown_protection_is_rejected() {
    let tools = DaemonTools::new();
    tools.set_key_protection("-");
    let store = FakeStore::default();

    let err = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &no_prompt,
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("did not report the key's protection"),
        "{err}"
    );
    assert_eq!(tools.clears(), 0);
}

#[test]
fn wrong_typed_passphrase_fails_without_storing() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();
    let prompted = Prompted::new("definitely-wrong");

    let err = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &prompted.as_fn(),
    )
    .unwrap_err();
    assert!(err.to_string().contains("rejected the passphrase"), "{err}");
    assert!(err.to_string().contains("NOT enabled"), "{err}");
    assert!(
        !store.contains_key(SUB2_GRIP),
        "a rejected passphrase was stored"
    );
}

#[test]
fn store_failure_after_unlock_fails_the_activation() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();
    store.make_stores_fail();
    let prompted = Prompted::new(common::FAKE_PASSPHRASE);

    let err = activation::activate(
        &tools.gpg,
        true,
        None,
        Duration::from_secs(60),
        None,
        &store,
        &prompted.as_fn(),
    )
    .unwrap_err();
    assert!(
        err.to_string()
            .contains("storing the session credential failed"),
        "{err}"
    );
}

/// Regression: the agent can reject a command while
/// `gpg-connect-agent` still exits 0. When the cache clear is
/// rejected, stored activation must fail before any loopback sign —
/// a failed clear followed by a successful sign would validate
/// nothing (a hot cache would satisfy it).
#[test]
fn rejected_cache_clear_aborts_the_stored_activation() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();
    store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());
    tools.marker("fail-clear");

    let err =
        stored_activation(&tools.gpg, &store, None, 60_000, None).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("clearing the GPG cache entry failed"),
        "{text}"
    );
    assert!(
        text.contains("ERR 67109139"),
        "the agent's rejection is missing from the error: {text}"
    );
    assert!(text.contains("NOT enabled"), "{text}");
    // No loopback sign ran: the credential was never "validated"
    // against a possibly-hot cache.
    assert_eq!(
        tools.loopbacks(),
        0,
        "a loopback sign ran after the failed clear: {}",
        tools.gpg_log()
    );
}

/// The same guarantee for the daemon's proactive renewal: a rejected
/// clear stops the hold before any loopback sign.
#[test]
fn rejected_cache_clear_stops_renewal_before_any_loopback_sign() {
    let running = Running::start(ShutdownPolicies::default());
    // 2s hard max renews ~1.8s in.
    running.hold(60_000, 2);
    running.tools.marker("fail-clear");
    let loopbacks_before = running.tools.loopbacks();

    assert!(
        wait_until(10 * SECS, || running.status()["hold_on"] == false),
        "hold did not stop: {}",
        running.status()
    );
    let error = running.status()["last_error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        error.contains("gpg agent command failed"),
        "wrong error: {error}"
    );
    assert_eq!(
        running.tools.loopbacks(),
        loopbacks_before,
        "a loopback sign ran after the failed clear: {}",
        running.tools.gpg_log()
    );
}

/// A wedged loopback gpg during renewal must be killed and reported
/// (the hold stops cleanly), and must never block daemon shutdown.
#[test]
fn wedged_renewal_stops_the_hold_and_never_blocks_shutdown() {
    let mut tools = DaemonTools::new();
    tools.gpg = tools
        .gpg
        .clone()
        .with_unattended_timeout(Duration::from_millis(300));
    let store = Arc::new(FakeStore::default());
    store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());
    let mut daemon = spawn_daemon(
        tools.gpg.clone(),
        Arc::clone(&store),
        Default::default(),
    );
    let sock = daemon.sock().to_path_buf();

    // 2s hard max renews ~1.8s in; the renewal's loopback sign hangs.
    tools.set_ttls(600, 2);
    let prepared =
        stored_activation(&tools.gpg, &store, None, 60_000, None).unwrap();
    let request = common::on_request(None, &prepared, 60_000, None);
    assert_eq!(ipc_at(&sock, &request).unwrap()["ok"], true);
    tools.marker("hang-loopback");

    assert!(
        wait_until(10 * SECS, || status_at(&sock)
            .map(|s| s["hold_on"] == false)
            .unwrap_or(false)),
        "hold did not stop: {:?}",
        status_at(&sock)
    );
    let error = status_at(&sock).unwrap()["last_error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(error.contains("timed out"), "wrong error: {error}");

    // The wedged child was really killed: its heartbeat file stopped
    // growing.
    let beats = tools.root.join("beats");
    let count = || {
        std::fs::read_to_string(&beats)
            .unwrap_or_default()
            .lines()
            .count()
    };
    let first = count();
    thread::sleep(Duration::from_millis(800));
    assert_eq!(count(), first, "the wedged gpg kept running");

    // The scheduler is free: shutdown still completes promptly.
    assert_eq!(ipc_at(&sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"], true);
    assert!(
        wait_until(2 * SECS, || !sock.exists()),
        "daemon shutdown was blocked by the wedged operation"
    );
    daemon.wait().unwrap();
    drop(tools);
}

// ---------------------------------------------------------------------------
// Daemon: renewal, recovery, races, cleanup
// ---------------------------------------------------------------------------

/// A running in-process daemon plus its tooling and store.
struct Running {
    _daemon: common::TestDaemon,
    sock: std::path::PathBuf,
    tools: DaemonTools,
    store: Arc<FakeStore>,
}

impl Running {
    fn start(policies: ShutdownPolicies) -> Self {
        let tools = DaemonTools::new();
        // Each daemon needs its own tooling (logs are per-tools).
        let store = Arc::new(FakeStore::default());
        store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());
        let daemon =
            spawn_daemon(tools.gpg.clone(), Arc::clone(&store), policies);
        let sock = daemon.sock().to_path_buf();
        Self {
            _daemon: daemon,
            sock,
            tools,
            store,
        }
    }

    fn status(&self) -> serde_json::Value {
        status_at(&self.sock).expect("daemon responsive")
    }

    /// Activate a stored-mode hold with the given interval and TTLs.
    fn hold(&self, interval_ms: u64, max_ttl_secs: u64) {
        self.tools.set_ttls(600, max_ttl_secs);
        let prepared = stored_activation(
            &self.tools.gpg,
            &self.store,
            None,
            interval_ms,
            None,
        )
        .expect("stored activation");
        let request = common::on_request(None, &prepared, interval_ms, None);
        let response = ipc_at(&self.sock, &request).expect("ipc");
        assert_eq!(response["ok"], true, "{response}");
        assert_eq!(self.status()["hold_on"], true);
    }
}

#[test]
fn stored_hold_renews_proactively_before_the_hard_maximum() {
    let running = Running::start(ShutdownPolicies::default());
    // 2s hard max renews every ~1.8s; background pings are far apart so
    // only renewals touch the key.
    running.hold(60_000, 2);

    let first_expiry = running.status()["max_expires_at_ms"]
        .as_u64()
        .expect("expiry known");
    assert!(
        // The third clear is observed before its loopback sign
        // completes; wait for both halves of all three renewals.
        wait_until(10 * SECS, || running.tools.clears() >= 3
            && running.tools.loopbacks() >= 3,),
        "renewals did not happen: {} / {}",
        running.tools.ca_log(),
        running.tools.gpg_log()
    );
    let status = running.status();
    assert_eq!(status["hold_on"], true, "hold survived: {status}");
    assert!(status["last_error"].is_null(), "{status}");
    // Each renewal resets the epoch: expiry moved forward.
    let later_expiry = status["max_expires_at_ms"].as_u64().expect("expiry");
    assert!(
        later_expiry > first_expiry,
        "epoch did not reset: {first_expiry} -> {later_expiry}"
    );
    // Renewal = retrieve + clear + loopback sign, in that order per cycle.
    assert!(running.tools.loopbacks() >= 3);
    assert!(!running.tools.gpg_log().contains(common::FAKE_PASSPHRASE));
}

#[test]
fn unexpected_cache_loss_is_recovered_once() {
    let running = Running::start(ShutdownPolicies::default());
    // Long max TTL (no renewals); frequent pings.
    running.hold(200, 600);

    // Simulate an agent restart/external clear between pings. The
    // activation itself did one loopback; recovery is the next one.
    let baseline_loopbacks = running.tools.loopbacks();
    running.tools.drop_cache();
    let before = running.tools.clears();

    assert!(
        wait_until(5 * SECS, || {
            running.tools.loopbacks() > baseline_loopbacks
                && running.status()["last_error"].is_null()
        }),
        "recovery did not happen: {} / {}",
        running.tools.ca_log(),
        running.status()
    );
    let status = running.status();
    assert_eq!(status["hold_on"], true, "{status}");
    assert!(status["last_error"].is_null(), "{status}");
    // Recovery ran the full recreate sequence: clear + loopback.
    assert!(running.tools.clears() > before);
    assert!(running.tools.loopbacks() >= 1);
}

#[test]
fn failed_recovery_error_explains_both_halves() {
    let running = Running::start(ShutdownPolicies::default());
    // Frequent pings, no renewals: the ping path drives recovery.
    running.hold(200, 600);

    // The cache entry disappears AND the credential is gone: the ping
    // fails, recovery fails, and the recorded error must explain both.
    running.tools.drop_cache();
    running.store.remove(SUB2_GRIP);
    let clears_before = running.tools.clears();

    assert!(
        wait_until(5 * SECS, || running.status()["hold_on"] == false),
        "hold did not stop: {}",
        running.status()
    );
    let error = running.status()["last_error"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        error.contains("cancelled"),
        "ping failure not explained: {error}"
    );
    assert!(
        error.contains("no longer available"),
        "recovery failure not explained: {error}"
    );
    // Retrieve-before-clear held: no clear happened without a credential.
    assert_eq!(
        running.tools.clears(),
        clears_before,
        "{}",
        running.tools.ca_log()
    );
}

#[test]
fn missing_credential_at_renewal_stops_the_hold_without_clearing() {
    let running = Running::start(ShutdownPolicies::default());
    running.hold(60_000, 2);

    // `keyhold credential clear` while the hold is active.
    running.store.remove(SUB2_GRIP);
    let clears_before = running.tools.clears();

    assert!(
        wait_until(10 * SECS, || running.status()["hold_on"] == false),
        "hold did not stop: {}",
        running.status()
    );
    let status = running.status();
    let error = status["last_error"].as_str().unwrap_or_default();
    assert!(
        error.contains("no longer available"),
        "wrong error: {error}"
    );
    // Retrieve-before-clear: the renewal attempted no clear after the
    // credential disappeared.
    assert_eq!(
        running.tools.clears(),
        clears_before,
        "cleared without a credential: {}",
        running.tools.ca_log()
    );
}

#[test]
fn secret_service_outage_at_renewal_stops_the_hold_without_clearing() {
    let running = Running::start(ShutdownPolicies::default());
    running.hold(60_000, 2);
    let clears_before = running.tools.clears();

    running.store.make_loads_fail();
    assert!(
        wait_until(10 * SECS, || running.status()["hold_on"] == false),
        "hold did not stop: {}",
        running.status()
    );
    assert_eq!(
        running.tools.clears(),
        clears_before,
        "cleared during an outage: {}",
        running.tools.ca_log()
    );
}

#[test]
fn off_during_an_in_flight_renewal_cannot_re_enable_the_hold() {
    let tools = DaemonTools::new();
    let store = Arc::new(FakeStore::default());
    store.preload(SUB2_GRIP, common::FAKE_PASSPHRASE.as_bytes());
    let mut daemon = spawn_daemon(
        tools.gpg.clone(),
        Arc::clone(&store),
        Default::default(),
    );
    let sock = daemon.sock().to_path_buf();

    tools.set_ttls(600, 2);
    let prepared =
        stored_activation(&tools.gpg, &store, None, 60_000, None).unwrap();
    let baseline_clears = tools.clears();
    tools.marker("slow");
    let request = common::on_request(None, &prepared, 60_000, None);
    assert_eq!(ipc_at(&sock, &request).unwrap()["ok"], true);

    // Wait until the renewal's new clear has happened and its deliberately
    // slow loopback is still in progress (the fake remains locked).
    assert!(
        wait_until(5 * SECS, || {
            tools.clears() > baseline_clears && tools.has("locked")
        }),
        "no renewal started: {}",
        tools.ca_log()
    );
    // `off` arrives while the renewal is in flight.
    assert_eq!(ipc_at(&sock, "{\"cmd\":\"off\"}").unwrap()["ok"], true);

    // Completion removes the fake agent's locked marker. The late renewal
    // result is then known to have arrived and must have been discarded.
    assert!(
        wait_until(5 * SECS, || !tools.has("locked")),
        "renewal loopback did not complete"
    );
    let status = status_at(&sock).unwrap();
    assert_eq!(status["hold_on"], false, "{status}");
    assert!(status["last_error"].is_null(), "{status}");
    daemon.shutdown().unwrap();
}

#[test]
fn expiry_wins_over_renewal() {
    let running = Running::start(ShutdownPolicies::default());
    // A hold shorter than the first renewal deadline (which is ~1.8s out):
    // expiry must win and no renewal may recreate the entry afterwards.
    running.tools.set_ttls(600, 5);
    let prepared = stored_activation(
        tools_gpg(&running),
        &running.store,
        None,
        60_000,
        None,
    )
    .unwrap();
    let request = common::on_request(None, &prepared, 60_000, Some(500));
    assert_eq!(ipc_at(&running.sock, &request).unwrap()["ok"], true);

    assert!(
        wait_until(5 * SECS, || running.status()["hold_on"] == false),
        "hold did not expire: {}",
        running.status()
    );
    let clears = running.tools.clears(); // 1 from activation
    thread::sleep(Duration::from_millis(1500));
    assert_eq!(
        running.tools.clears(),
        clears,
        "renewal ran after expiry: {}",
        running.tools.ca_log()
    );
}

fn tools_gpg(running: &Running) -> &Gpg {
    &running.tools.gpg
}

#[test]
fn lock_key_on_daemon_stop_clears_only_the_active_keygrip() {
    let running = Running::start(ShutdownPolicies {
        clear_secret: false,
        lock_key: true,
    });
    running.hold(60_000, 600);
    let clears = running.tools.clears();

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"],
        true
    );
    assert!(
        wait_until(5 * SECS, || !running.sock.exists()),
        "socket not removed"
    );
    // Exactly one extra clear, for the exact signing keygrip.
    assert!(
        wait_until(5 * SECS, || running.tools.clears() == clears + 1),
        "cleanup did not run: {}",
        running.tools.ca_log()
    );
    let ca_log = running.tools.ca_log();
    let last_clear = ca_log
        .lines()
        .rev()
        .find(|l| l.starts_with("CLEAR_PASSPHRASE"))
        .expect("a cleanup clear");
    assert_eq!(
        last_clear,
        &format!("CLEAR_PASSPHRASE --mode=normal {SUB2_GRIP} /bye"),
        "wrong keygrip cleared: {}",
        running.tools.ca_log()
    );
    assert!(
        !running
            .store
            .operations()
            .iter()
            .any(|op| op == "clear_all")
    );
}

#[test]
fn clear_secret_on_daemon_stop_removes_the_credential() {
    let running = Running::start(ShutdownPolicies {
        clear_secret: true,
        lock_key: false,
    });
    running.hold(60_000, 600);
    let clears = running.tools.clears();

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"],
        true
    );
    assert!(wait_until(5 * SECS, || !running.sock.exists()));
    assert!(
        running
            .store
            .operations()
            .iter()
            .any(|op| op == "clear_all"),
        "secret not cleared: {:?}",
        running.store.operations()
    );
    // The lock policy is independent and off: no GPG clear happened.
    assert_eq!(running.tools.clears(), clears);
}

#[test]
fn shutdown_drains_accepted_handlers_before_cleanup_and_socket_removal() {
    let tools = DaemonTools::new();
    let store = Arc::new(FakeStore::default());
    let mut daemon = spawn_daemon(
        tools.gpg.clone(),
        Arc::clone(&store),
        ShutdownPolicies {
            clear_secret: true,
            lock_key: false,
        },
    );
    let sock = daemon.sock().to_path_buf();
    let mut accepted = UnixStream::connect(&sock).unwrap();
    accepted
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // A later status response proves the accept loop has already accepted
    // the earlier connection and spawned its handler.
    assert!(status_at(&sock).is_some());
    let clear_gate = store.block_next_clear();

    assert_eq!(ipc_at(&sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"], true);
    assert!(
        !store.operations().iter().any(|op| op == "clear_all"),
        "cleanup overtook an accepted handler"
    );

    accepted
        .write_all(
            b"{\"cmd\":\"on\",\"key\":\"LATE\",\
              \"key_source\":\"explicit\",\"interval_ms\":60000,\
              \"hold_ms\":null,\"activated_at_ms\":2000}\n",
        )
        .unwrap();
    let mut response = String::new();
    accepted.read_to_string(&mut response).unwrap();
    let response: serde_json::Value =
        serde_json::from_str(response.trim()).unwrap();
    assert_eq!(response["ok"], false, "{response}");
    assert_eq!(response["error"], "daemon is shutting down");
    drop(accepted);

    clear_gate.wait_until_entered();
    assert!(sock.exists(), "socket removed before cleanup completed");
    clear_gate.release();
    daemon.wait().unwrap();
    assert!(!sock.exists(), "socket remained after daemon joined");
    assert!(store.operations().iter().any(|op| op == "clear_all"));
}

#[test]
fn default_shutdown_policies_touch_nothing() {
    let running = Running::start(ShutdownPolicies::default());
    running.hold(60_000, 600);
    let clears = running.tools.clears();

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"],
        true
    );
    assert!(wait_until(5 * SECS, || !running.sock.exists()));
    assert_eq!(running.tools.clears(), clears);
    assert!(
        !running
            .store
            .operations()
            .iter()
            .any(|op| op == "clear_all"),
        "secret cleared without the policy: {:?}",
        running.store.operations()
    );
}

/// `on → off → daemon --stop` with the lock policy still clears the
/// retained key's cache entry: `off` stops holding, but shutdown
/// teardown targets the key that was last resolved.
#[test]
fn lock_on_daemon_stop_works_after_off() {
    let running = Running::start(ShutdownPolicies {
        clear_secret: false,
        lock_key: true,
    });
    running.hold(60_000, 600);
    let clears_before = running.tools.clears();

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"off\"}").unwrap()["ok"],
        true
    );
    let status = running.status();
    assert_eq!(status["hold_on"], false, "{status}");

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"],
        true
    );
    assert!(
        wait_until(5 * SECS, || running.tools.clears() == clears_before + 1),
        "the retained key was not locked on shutdown: {}",
        running.tools.ca_log()
    );
    let log = running.tools.ca_log();
    let last_clear = log
        .lines()
        .rev()
        .find(|l| l.starts_with("CLEAR_PASSPHRASE"))
        .expect("a cleanup clear");
    assert_eq!(
        last_clear,
        &format!("CLEAR_PASSPHRASE --mode=normal {SUB2_GRIP} /bye"),
        "wrong keygrip cleared: {}",
        running.tools.ca_log()
    );
}

/// The same after a timed hold expires by itself.
#[test]
fn lock_on_daemon_stop_works_after_expiry() {
    let running = Running::start(ShutdownPolicies {
        clear_secret: false,
        lock_key: true,
    });
    // A stored hold that expires in 300ms (its activation did one
    // clear; no renewal is scheduled within the hold's life).
    running.tools.set_ttls(600, 600);
    let prepared = stored_activation(
        tools_gpg(&running),
        &running.store,
        None,
        60_000,
        None,
    )
    .unwrap();
    let request = common::on_request(None, &prepared, 60_000, Some(300));
    assert_eq!(ipc_at(&running.sock, &request).unwrap()["ok"], true);
    assert!(
        wait_until(5 * SECS, || running.status()["hold_on"] == false),
        "hold did not expire: {}",
        running.status()
    );
    let clears_before = running.tools.clears();

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"],
        true
    );
    assert!(
        wait_until(5 * SECS, || running.tools.clears() == clears_before + 1),
        "the expired hold's key was not locked on shutdown: {}",
        running.tools.ca_log()
    );
    let log = running.tools.ca_log();
    let last_clear = log
        .lines()
        .rev()
        .find(|l| l.starts_with("CLEAR_PASSPHRASE"))
        .expect("a cleanup clear");
    assert!(
        last_clear.contains(SUB2_GRIP),
        "wrong keygrip cleared: {}",
        running.tools.ca_log()
    );
}

/// Replacing a hold with another key makes the newest resolved key the
/// shutdown target, cleared exactly once; the replaced key is
/// untouched.
#[test]
fn lock_on_daemon_stop_targets_the_replacement_key() {
    let running = Running::start(ShutdownPolicies {
        clear_secret: false,
        lock_key: true,
    });
    running.hold(60_000, 600);
    let clears_before = running.tools.clears();

    // A replacement hold resolving a different signing key (the older
    // subkey), as `keyhold on --key <subkey>` would send.
    let replacement = format!(
        "{{\"cmd\":\"on\",\"key\":\"4E7D2CD7\",\
         \"key_source\":\"explicit\",\"interval_ms\":60000,\
         \"hold_ms\":null,\"activated_at_ms\":1700000000000,\
         \"fingerprint\":\"{SUB_FPR}\",\"keygrip\":\"{SUB_GRIP}\",\
         \"credential_mode\":\"session\",\
         \"default_cache_ttl_ms\":600000,\"max_cache_ttl_ms\":600000,\
         \"cache_started_at_ms\":1700000000000}}"
    );
    assert_eq!(ipc_at(&running.sock, &replacement).unwrap()["ok"], true);
    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"off\"}").unwrap()["ok"],
        true
    );

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"],
        true
    );
    assert!(
        wait_until(5 * SECS, || running.tools.clears() == clears_before + 1),
        "expected exactly one shutdown clear: {}",
        running.tools.ca_log()
    );
    let log = running.tools.ca_log();
    let last_clear = log
        .lines()
        .rev()
        .find(|l| l.starts_with("CLEAR_PASSPHRASE"))
        .expect("a cleanup clear");
    assert_eq!(
        last_clear,
        &format!("CLEAR_PASSPHRASE --mode=normal {SUB_GRIP} /bye"),
        "wrong keygrip cleared: {}",
        running.tools.ca_log()
    );
}

/// A daemon that never resolved a key must not guess one: the lock
/// policy does nothing without retained metadata.
#[test]
fn lock_on_daemon_stop_without_a_resolved_key_clears_nothing() {
    let running = Running::start(ShutdownPolicies {
        clear_secret: false,
        lock_key: true,
    });
    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"],
        true
    );
    assert!(wait_until(5 * SECS, || !running.sock.exists()));
    assert_eq!(
        running.tools.clears(),
        0,
        "a key was cleared without any resolved key: {}",
        running.tools.ca_log()
    );
}

#[test]
fn off_does_not_clear_the_credential_or_the_cache() {
    let running = Running::start(ShutdownPolicies {
        clear_secret: true,
        lock_key: true,
    });
    running.hold(60_000, 600);
    let clears = running.tools.clears();

    assert_eq!(
        ipc_at(&running.sock, "{\"cmd\":\"off\"}").unwrap()["ok"],
        true
    );
    thread::sleep(Duration::from_millis(300));

    // `keyhold off` stops holding only: no cleanup policies run.
    assert_eq!(running.tools.clears(), clears, "cache was cleared");
    assert!(
        !running
            .store
            .operations()
            .iter()
            .any(|op| op == "clear_all"),
        "credential was cleared"
    );
    let status = running.status();
    assert_eq!(status["hold_on"], false, "{status}");
}

#[test]
fn cleanup_failure_still_removes_the_socket() {
    // clear_secret policy against a real (absent) Secret Service: the
    // cleanup fails, but the daemon must still shut down cleanly.
    let tools = DaemonTools::new();
    let mut daemon = spawn_daemon_with_failing_store(tools.gpg.clone());
    let sock = daemon.sock().to_path_buf();
    assert_eq!(ipc_at(&sock, "{\"cmd\":\"shutdown\"}").unwrap()["ok"], true);
    assert!(
        wait_until(5 * SECS, || !sock.exists()),
        "socket not removed despite cleanup failure"
    );
    daemon.wait().unwrap();
    drop(tools);
}

/// A daemon whose credential store always fails, with both cleanup
/// policies enabled.
fn spawn_daemon_with_failing_store(gpg: Gpg) -> common::TestDaemon {
    let store = Arc::new(FakeStore::default());
    store.make_loads_fail();
    store.make_stores_fail();
    let policies = ShutdownPolicies {
        clear_secret: true,
        lock_key: true,
    };
    spawn_daemon(gpg, store, policies)
}

// ---------------------------------------------------------------------------
// Ordinary mode remains untouched by the new plumbing
// ---------------------------------------------------------------------------

#[test]
fn ordinary_background_ping_still_uses_exact_target_when_resolved() {
    let tools = DaemonTools::new();
    let used = tools.gpg.use_key(None, PingMode::Foreground).unwrap();
    assert_eq!(
        used.target.map(|t| t.fingerprint),
        Some(SUB2_FPR.to_string())
    );
    // Live key state is reported from the fake agent.
    let state = tools.gpg.key_state(SUB2_GRIP).unwrap();
    assert_eq!(state.protection, KeyProtection::Passphrase);
    assert!(state.cached, "fake agent starts unlocked");
}

#[test]
fn ordinary_activation_does_not_mutate_credentials() {
    let tools = DaemonTools::new();
    let store = FakeStore::default();

    let prepared = activation::activate(
        &tools.gpg,
        false,
        None,
        Duration::from_secs(60),
        Some(Duration::from_secs(30)),
        &store,
        &no_prompt,
    )
    .unwrap();

    assert!(!prepared.credential_mutated);
    assert!(store.operations().is_empty());
}

/// Silence unused warnings for helpers only some configurations use.
#[allow(dead_code)]
fn _unused(_: &Path) {}
