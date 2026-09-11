//! Pure hold state machine.
//!
//! All scheduling uses monotonic [`Instant`]s so wall-clock adjustments cannot
//! break the hold timer; wall-clock [`SystemTime`] appears only in status
//! snapshots. Keeping this module free of I/O makes the timing behaviour
//! unit-testable with synthetic instants.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::gpg::SigningTarget;

use serde::{Deserialize, Serialize};

/// Status snapshot exchanged over IPC.
///
/// Metadata only: nothing here can contain secret material.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusData {
    /// Whether the hold is currently enabled.
    pub hold_on: bool,
    /// Selected key, or `None` for GPG's default key.
    pub key: Option<String>,
    /// Where the selected key came from (presentation metadata).
    pub key_source: KeySource,
    /// Ping interval in milliseconds.
    pub interval_ms: u64,
    /// Remaining hold time in milliseconds; `None` when indefinite or off.
    pub remaining_ms: Option<u64>,
    /// Epoch milliseconds of the last successful ping.
    pub last_ping_ms: Option<u64>,
    /// Epoch milliseconds of the next scheduled ping.
    pub next_ping_ms: Option<u64>,
    /// Last keepalive failure, retained until the next `on`/`off`.
    pub last_error: Option<String>,
    /// Fingerprint of the exact signing key (a subkey, not necessarily
    /// the primary); `None` when it could not be resolved.
    #[serde(default)]
    pub fingerprint: Option<String>,
    /// Agent keygrip of the exact signing key; `None` when unresolved.
    #[serde(default)]
    pub keygrip: Option<String>,
    /// Credential mode of the hold.
    #[serde(default)]
    pub credential_mode: CredentialMode,
    /// GnuPG's effective `default-cache-ttl`, when known.
    #[serde(default)]
    pub default_cache_ttl_ms: Option<u64>,
    /// GnuPG's effective `max-cache-ttl`, when known.
    #[serde(default)]
    pub max_cache_ttl_ms: Option<u64>,
    /// Epoch milliseconds when the current cache entry reaches GnuPG's
    /// hard maximum; `None` when the epoch is unknown.
    #[serde(default)]
    pub max_expires_at_ms: Option<u64>,
}

/// Credential mode of a hold (activation metadata; never a secret).
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    /// Ordinary passphrase-blind hold.
    #[default]
    None,
    /// A session credential backs proactive renewal and recovery.
    Session,
    /// The signing key needs no passphrase (unprotected key).
    NotNeeded,
}

/// Where the active key selector came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// No selector passed: GnuPG's normal default-key selection.
    Default,
    /// An explicitly chosen key (CLI `--key` or config `key`).
    Explicit,
    /// Git's effective `user.signingkey`, resolved at activation.
    Git,
}

/// What the daemon should do at a given instant. When several actions
/// are due at once, expiry wins over renewal, and renewal wins over a
/// regular ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Run one background keepalive ping.
    Ping,
    /// Proactively recreate the cache entry from the session credential
    /// before GnuPG's hard maximum expires (stored mode only).
    Renew,
    /// The `--for` deadline elapsed; disable the hold.
    Expire,
}

/// Runtime hold state, owned by the daemon.
///
/// No state survives a daemon restart: a fresh daemon starts with the hold
/// off.
#[derive(Debug)]
pub struct Hold {
    /// Whether keepalive is currently enabled.
    pub enabled: bool,
    /// Key selector (`None` = GPG default key).
    pub key: Option<String>,
    /// Where the key selector came from (display metadata only).
    pub key_source: KeySource,
    /// Ping interval.
    pub interval: Duration,
    /// Monotonic deadline imposed by `--for`.
    pub deadline: Option<Instant>,
    /// Monotonic time of the next scheduled ping.
    pub next_ping: Option<Instant>,
    /// Wall-clock time of the last successful ping.
    pub last_ping: Option<SystemTime>,
    /// Last keepalive failure message.
    pub last_error: Option<String>,
    /// Bumped on every successful `on`. Together with the enabled-state
    /// check, this discards scheduled work racing a replacement or `off`.
    pub generation: u64,
    /// Fingerprint of the exact signing key backing the hold, when
    /// resolved at activation.
    pub fingerprint: Option<String>,
    /// Agent keygrip of the exact signing key, when resolved.
    pub keygrip: Option<String>,
    /// How (and whether) a credential backs this hold.
    pub credential_mode: CredentialMode,
    /// GPG cache epoch tracking; `None` when no policy/epoch is known.
    pub cache: Option<CacheState>,
}

/// GPG cache tracking for an active hold.
#[derive(Debug, Clone, Copy)]
pub struct CacheState {
    /// GnuPG's effective `default-cache-ttl`.
    pub default_ttl: Duration,
    /// The hard maximum GnuPG enforces on the cache entry.
    pub max_ttl: Duration,
    /// Wall-clock time the current cache entry reaches GnuPG's hard
    /// maximum; the epoch keyhold established. Used for status
    /// countdowns. `None` when the entry's start predates keyhold.
    pub expires_wall: Option<SystemTime>,
    /// Monotonic time of the next proactive renewal (`None` unless the
    /// session credential backs the hold).
    pub renew_at: Option<Instant>,
}

/// Cache metadata supplied at activation: everything needed to derive
/// [`CacheState`] without secret material.
#[derive(Debug, Clone, Copy)]
pub struct CachePlan {
    /// Credential mode of the hold.
    pub mode: CredentialMode,
    /// GnuPG's effective `default-cache-ttl`.
    pub default_ttl: Duration,
    /// GnuPG's effective `max-cache-ttl`.
    pub max_ttl: Duration,
    /// Wall-clock time the cache entry's current epoch began. Known
    /// when keyhold itself (re)created the entry; `None` when the entry
    /// predates the activation, in which case no countdown is honest.
    pub started_wall: Option<SystemTime>,
}

/// The resolved signing target and cache plan handed to
/// [`Hold::turn_on`] as one unit.
#[derive(Debug, Clone, Copy, Default)]
pub struct Activation<'a> {
    /// The resolved exact signing key, when identifiable.
    pub target: Option<&'a SigningTarget>,
    /// GPG cache tracking metadata for the daemon.
    pub cache: Option<CachePlan>,
}

impl<'a> Activation<'a> {
    /// Cache tracking without a resolved target.
    pub fn cache_only(cache: CachePlan) -> Self {
        Self {
            target: None,
            cache: Some(cache),
        }
    }
}

/// How long before GnuPG's hard maximum a proactive renewal runs.
///
/// `min(60s, max_ttl/10)`, so a 2h maximum renews at 1h59m and a 5m
/// one at 4m30s; tiny TTLs naturally renew at 90%.
pub fn renew_margin(max_ttl: Duration) -> Duration {
    (max_ttl / 10).min(Duration::from_secs(60))
}

impl Default for Hold {
    fn default() -> Self {
        Self {
            enabled: false,
            key: None,
            key_source: KeySource::Default,
            interval: crate::cli::DEFAULT_INTERVAL,
            deadline: None,
            next_ping: None,
            last_ping: None,
            last_error: None,
            generation: 0,
            fingerprint: None,
            keygrip: None,
            credential_mode: CredentialMode::None,
            cache: None,
        }
    }
}

impl Hold {
    /// Enable (or replace) the hold at time `now`.
    ///
    /// `activated` is the wall-clock time of the successful key use that
    /// justifies the hold (the foreground ping of `keyhold on`); it becomes
    /// `last_ping`, so an immediate `status` reports the activation and
    /// a replacement hold never displays a timestamp inherited from the
    /// hold it replaced.
    ///
    /// `target`/`cache` carry the resolved exact signing key and GPG
    /// cache epoch metadata. In session mode a renewal deadline is
    /// scheduled from the epoch: `max_ttl` after the entry began, less
    /// [`renew_margin`]. Values that cannot be represented on the
    /// clocks are rejected like any other unschedulable input, leaving
    /// the state untouched.
    pub fn turn_on(
        &mut self,
        key: Option<String>,
        key_source: KeySource,
        interval: Duration,
        hold_for: Option<Duration>,
        now: Instant,
        activated: SystemTime,
        activation: Activation<'_>,
    ) -> Result<(), &'static str> {
        let next_ping = now
            .checked_add(interval)
            .ok_or("ping interval is too large to schedule")?;
        let deadline = hold_for.and_then(|d| now.checked_add(d));
        if hold_for.is_some() && deadline.is_none() {
            return Err("hold duration is too large to schedule");
        }
        let target = activation.target;
        let cache = match activation.cache {
            None => None,
            Some(plan) => {
                let expires_wall = plan
                    .started_wall
                    .and_then(|start| start.checked_add(plan.max_ttl));
                let renew_at = if plan.mode == CredentialMode::Session {
                    let started = plan
                        .started_wall
                        .ok_or("session mode requires a known cache epoch")?;
                    // Remaining hard-max lifetime from the epoch keyhold
                    // established, less the safety margin.
                    let elapsed =
                        activated.duration_since(started).unwrap_or_default();
                    let remaining = plan.max_ttl.saturating_sub(elapsed);
                    let after_margin =
                        remaining.saturating_sub(renew_margin(plan.max_ttl));
                    let at = now
                        .checked_add(after_margin)
                        .ok_or("cache TTL is too large to schedule")?;
                    // A nearly-expired epoch renews immediately: clamp to
                    // just after now instead of scheduling in the past.
                    Some(at.max(now + Duration::from_millis(1)))
                } else {
                    None
                };
                Some(CacheState {
                    default_ttl: plan.default_ttl,
                    max_ttl: plan.max_ttl,
                    expires_wall,
                    renew_at,
                })
            }
        };
        self.enabled = true;
        self.key = key;
        self.key_source = key_source;
        self.interval = interval;
        self.deadline = deadline;
        self.next_ping = Some(next_ping);
        self.last_ping = Some(activated);
        self.last_error = None;
        self.fingerprint = target.map(|t| t.fingerprint.to_owned());
        self.keygrip = target.and_then(|t| t.keygrip.to_owned());
        self.credential_mode = activation
            .cache
            .map_or(CredentialMode::None, |plan| plan.mode);
        self.cache = cache;
        self.generation += 1;
        Ok(())
    }

    /// Disable the hold, leaving any last error intact for `status`.
    /// Renewal/cache metadata dies with the hold, but the resolved
    /// fingerprint/keygrip and credential mode (non-secret provenance)
    /// are retained: the cache entry can outlive the hold, status needs
    /// to know whether Secret Service access was opted into, and daemon-
    /// shutdown cleanup may still need to clear it.
    pub fn turn_off(&mut self) {
        self.enabled = false;
        self.deadline = None;
        self.next_ping = None;
        self.cache = None;
    }

    /// Forget the last error (an explicit `off` acknowledges it).
    pub fn clear_error(&mut self) {
        self.last_error = None;
    }

    /// The action due at `now`, if any. Expiry wins over renewal, and
    /// renewal wins over a regular ping: an expiring hold must not
    /// recreate cache entries, and a due renewal must not be pushed out
    /// by the ping cadence.
    pub fn due_action(&self, now: Instant) -> Option<Action> {
        if !self.enabled {
            return None;
        }
        if self.deadline.is_some_and(|d| now >= d) {
            return Some(Action::Expire);
        }
        let renew_at = self.cache.as_ref().and_then(|c| c.renew_at);
        if renew_at.is_some_and(|r| now >= r) {
            return Some(Action::Renew);
        }
        if self.next_ping.is_some_and(|p| now >= p) {
            return Some(Action::Ping);
        }
        None
    }

    /// Earliest future instant the scheduler must wake for
    /// (`None` = nothing scheduled).
    pub fn next_wake(&self, now: Instant) -> Option<Instant> {
        if !self.enabled {
            return None;
        }
        [
            self.deadline,
            self.cache.as_ref().and_then(|c| c.renew_at),
            self.next_ping,
        ]
        .into_iter()
        .flatten()
        .filter(|t| *t > now)
        .min()
    }

    /// Record a successful ping at `now`.
    ///
    /// Checked rescheduling: if the next ping cannot be represented, no
    /// next ping is scheduled (`None`) instead of panicking.
    pub fn record_ping_ok(&mut self, now: Instant, wall: SystemTime) {
        self.last_ping = Some(wall);
        self.next_ping = now.checked_add(self.interval);
    }

    /// Record a successful renewal at `now`: the epoch restarts, so the
    /// hard-max countdown and the next renewal deadline are recomputed
    /// from a fresh entry, and the regular ping cadence continues.
    pub fn record_renewal(&mut self, now: Instant, wall: SystemTime) {
        self.record_ping_ok(now, wall);
        if let Some(cache) = &mut self.cache {
            cache.expires_wall = wall.checked_add(cache.max_ttl);
            let margin = renew_margin(cache.max_ttl);
            cache.renew_at =
                now.checked_add(cache.max_ttl.saturating_sub(margin));
        }
    }

    /// Record a failed ping: disable the hold and retain the reason.
    pub fn record_ping_failure(&mut self, reason: String) {
        self.turn_off();
        self.last_error = Some(reason);
    }

    /// Remaining hold time (`None` when off or indefinite; zero when elapsed).
    pub fn remaining(&self, now: Instant) -> Option<Duration> {
        if !self.enabled {
            return None;
        }
        self.deadline.map(|d| d.saturating_duration_since(now))
    }

    /// Build an IPC status snapshot.
    pub fn status(&self) -> StatusData {
        let now = Instant::now();
        // Wall-clock time as Unix epoch milliseconds, when representable.
        // Pre-epoch or u64-overflowing values are absent — never epoch
        // zero, which would display as "in 0s".
        let epoch = |t: SystemTime| -> Option<u64> {
            t.duration_since(UNIX_EPOCH)
                .ok()
                .and_then(|d| u64::try_from(d.as_millis()).ok())
        };
        let wall = SystemTime::now();
        // Duration length in milliseconds, when it fits the u64 IPC model.
        // Values that cannot fit are never truncated: the interval
        // saturates, and the remaining time is reported as absent, like
        // `next_ping_ms`.
        let millis =
            |d: Duration| -> Option<u64> { u64::try_from(d.as_millis()).ok() };
        StatusData {
            hold_on: self.enabled,
            key: self.key.clone(),
            key_source: self.key_source,
            interval_ms: millis(self.interval).unwrap_or(u64::MAX),
            remaining_ms: self.remaining(now).and_then(millis),
            last_ping_ms: self.last_ping.and_then(epoch),
            // Checked wall-clock projection: a far-future ping that cannot
            // be expressed in epoch milliseconds is reported as absent
            // rather than panicking or collapsing to zero.
            next_ping_ms: self.next_ping.and_then(|p| {
                wall.checked_add(p.saturating_duration_since(now))
                    .and_then(epoch)
            }),
            last_error: self.last_error.clone(),
            fingerprint: self.fingerprint.clone(),
            keygrip: self.keygrip.clone(),
            credential_mode: self.credential_mode,
            default_cache_ttl_ms: self
                .cache
                .and_then(|c| millis(c.default_ttl)),
            max_cache_ttl_ms: self.cache.and_then(|c| millis(c.max_ttl)),
            max_expires_at_ms: self
                .cache
                .and_then(|c| c.expires_wall)
                .and_then(epoch),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINUTE: Duration = Duration::from_secs(60);

    fn t0() -> Instant {
        Instant::now()
    }

    /// Synthetic wall-clock instant for activation timestamps.
    fn wall(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    #[test]
    fn first_ping_is_scheduled_one_interval_after_on() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            Some("ABCD".into()),
            KeySource::Explicit,
            MINUTE,
            None,
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        assert_eq!(hold.due_action(start), None);
        assert_eq!(hold.due_action(start + MINUTE), Some(Action::Ping));
        assert_eq!(hold.next_wake(start), Some(start + MINUTE));
        assert!(hold.remaining(start).is_none());
    }

    #[test]
    fn deadline_wins_over_ping() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            Some(MINUTE),
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        assert_eq!(hold.due_action(start + MINUTE), Some(Action::Expire));
    }

    #[test]
    fn turn_off_stops_all_scheduling() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            Some(MINUTE),
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        hold.turn_off();
        assert!(!hold.enabled);
        assert_eq!(hold.due_action(start + 10 * MINUTE), None);
        assert_eq!(hold.next_wake(start), None);
        assert_eq!(hold.remaining(start), None);
    }

    #[test]
    fn status_reports_millisecond_fields_exactly() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            Some(MINUTE),
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();

        let status = hold.status();
        assert_eq!(status.interval_ms, 60_000);
        // `status` samples `Instant::now()` itself, so the remaining time
        // can only have shrunk by the call overhead — never grown.
        assert!(status.remaining_ms.is_some_and(|ms| ms <= 60_000));
    }

    #[test]
    fn status_saturates_interval_beyond_the_u64_millisecond_model() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            Some(MINUTE),
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();

        // A millisecond length that overflows u64 cannot be scheduled
        // through `turn_on` (the checked `Instant` add rejects it long
        // before), so pin the field directly: the snapshot must saturate,
        // never truncate.
        hold.interval = Duration::from_secs(u64::MAX);
        assert_eq!(hold.status().interval_ms, u64::MAX);
    }

    #[test]
    fn ping_failure_disables_and_retains_error() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        hold.record_ping_failure(
            "gpg: signing failed: Operation cancelled".into(),
        );
        assert!(!hold.enabled);
        assert_eq!(hold.due_action(start + 10 * MINUTE), None);
        assert_eq!(
            hold.last_error.as_deref(),
            Some("gpg: signing failed: Operation cancelled")
        );
    }

    #[test]
    fn successful_ping_reschedules() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        let pinged_at = start + MINUTE;
        hold.record_ping_ok(pinged_at, SystemTime::now());
        assert_eq!(hold.due_action(pinged_at), None);
        assert_eq!(hold.next_ping, Some(pinged_at + MINUTE));
        assert!(hold.last_ping.is_some());
    }

    #[test]
    fn repeated_on_replaces_deadline_and_bumps_generation() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            Some(MINUTE),
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        let generation = hold.generation;
        let later = start + Duration::from_secs(10);
        hold.turn_on(
            Some("K".into()),
            KeySource::Explicit,
            Duration::from_secs(30),
            None,
            later,
            wall(2_000),
            Activation::default(),
        )
        .unwrap();
        assert_eq!(hold.generation, generation + 1);
        assert_eq!(hold.deadline, None);
        assert_eq!(hold.next_ping, Some(later + Duration::from_secs(30)));
        assert!(hold.last_error.is_none());
    }

    #[test]
    fn timed_hold_counts_down() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            Some(Duration::from_secs(3600)),
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        assert_eq!(
            hold.remaining(start + Duration::from_secs(60)),
            Some(Duration::from_secs(3540))
        );
    }

    #[test]
    fn activation_is_recorded_as_the_first_successful_use() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_234);
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            activated,
            Activation::default(),
        )
        .unwrap();
        assert_eq!(hold.last_ping, Some(activated));
        // The activation is already the latest successful use; the first
        // *background* ping stays one full interval after activation.
        assert_eq!(hold.due_action(start), None);
        assert_eq!(hold.next_ping, Some(start + MINUTE));
    }

    #[test]
    fn replacing_a_hold_never_inherits_the_previous_last_ping() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        hold.record_ping_ok(start + MINUTE, wall(1_060));
        let later = start + 2 * MINUTE;
        let fresh = wall(2_000);
        hold.turn_on(
            Some("K".into()),
            KeySource::Explicit,
            MINUTE,
            None,
            later,
            fresh,
            Activation::default(),
        )
        .unwrap();
        assert_eq!(hold.last_ping, Some(fresh));
    }

    #[test]
    fn unrepresentable_interval_is_rejected_without_changing_state() {
        let mut hold = Hold::default();
        let start = t0();
        let err = hold
            .turn_on(
                None,
                KeySource::Default,
                Duration::from_secs(u64::MAX),
                None,
                start,
                wall(1_000),
                Activation::default(),
            )
            .unwrap_err();
        assert!(err.contains("interval"), "{err}");
        assert!(!hold.enabled);
        assert_eq!(hold.generation, 0);
        assert_eq!(hold.next_ping, None);
    }

    #[test]
    fn unrepresentable_hold_duration_is_rejected_without_changing_state() {
        let mut hold = Hold::default();
        let start = t0();
        let err = hold
            .turn_on(
                None,
                KeySource::Default,
                MINUTE,
                Some(Duration::from_secs(u64::MAX)),
                start,
                wall(1_000),
                Activation::default(),
            )
            .unwrap_err();
        assert!(err.contains("hold"), "{err}");
        assert!(!hold.enabled);
        assert_eq!(hold.generation, 0);
    }

    #[test]
    fn largest_millisecond_values_remain_representable() {
        // u64::MAX milliseconds is the widest value the protocol can carry;
        // on platforms whose clocks can represent it (Linux) it schedules
        // normally instead of being rejected or truncated.
        let mut hold = Hold::default();
        let start = t0();
        let interval = Duration::from_millis(u64::MAX);
        hold.turn_on(
            None,
            KeySource::Explicit,
            interval,
            Some(interval),
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        assert_eq!(hold.next_ping, Some(start + interval));
        assert_eq!(hold.deadline, Some(start + interval));
        assert_eq!(hold.status().interval_ms, u64::MAX);
    }

    #[test]
    fn unrepresentable_status_timestamps_are_absent_not_zero() {
        // An ordinary interval projects onto a representable wall-clock
        // instant: the next ping is reported in epoch milliseconds.
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        let status = hold.status();
        let next = status.next_ping_ms.expect("next ping present");
        assert!(next > 1_700_000_000_000, "not epoch millis: {next}");
        assert_eq!(status.last_ping_ms, Some(1_000_000));

        // u64::MAX milliseconds stays schedulable monotonically, but the
        // wall-clock projection overflows epoch milliseconds: the display
        // field must be absent, never epoch zero ("in 0s").
        hold.turn_on(
            None,
            KeySource::Default,
            Duration::from_millis(u64::MAX),
            None,
            start,
            wall(1_000),
            Activation::default(),
        )
        .unwrap();
        assert!(hold.next_ping.is_some(), "monotonic schedule kept");
        let status = hold.status();
        assert_eq!(status.next_ping_ms, None);
        assert_eq!(status.last_ping_ms, Some(1_000_000));
    }

    /// A session-mode plan with a fresh epoch.
    fn session_plan(max_ttl: Duration, started: SystemTime) -> CachePlan {
        CachePlan {
            mode: CredentialMode::Session,
            default_ttl: Duration::from_secs(30),
            max_ttl,
            started_wall: Some(started),
        }
    }

    #[test]
    fn renew_margin_caps_at_sixty_seconds() {
        // 2h max => renewal at 1h59m (60s margin)...
        assert_eq!(
            renew_margin(Duration::from_secs(2 * 3600)),
            Duration::from_secs(60)
        );
        // ...5m max => 4m30s (30s margin)...
        assert_eq!(
            renew_margin(Duration::from_secs(5 * 60)),
            Duration::from_secs(30)
        );
        // ...and tiny TTLs naturally renew at 90%.
        assert_eq!(
            renew_margin(Duration::from_secs(10)),
            Duration::from_secs(1)
        );
    }

    #[test]
    fn session_hold_schedules_renewal_before_the_hard_maximum() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_000);
        let max_ttl = Duration::from_secs(2 * 3600);
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            activated,
            Activation::cache_only(session_plan(max_ttl, activated)),
        )
        .unwrap();
        let renew_at = hold
            .cache
            .as_ref()
            .and_then(|c| c.renew_at)
            .expect("renewal scheduled");
        assert_eq!(renew_at, start + max_ttl - Duration::from_secs(60));
        // Not due immediately, but due before the hard maximum.
        assert_eq!(hold.due_action(start), None);
        assert_eq!(hold.due_action(renew_at), Some(Action::Renew));
        // The status reports the hard-max expiry countdown inputs.
        let status = hold.status();
        assert_eq!(status.max_cache_ttl_ms, Some(7_200_000));
        assert_eq!(status.default_cache_ttl_ms, Some(30_000));
        assert_eq!(status.max_expires_at_ms, Some(1_000_000 + 7_200_000));
        assert_eq!(status.credential_mode, CredentialMode::Session);
    }

    #[test]
    fn five_minute_maximum_renews_at_four_thirty() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_000);
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            activated,
            Activation::cache_only(session_plan(
                Duration::from_secs(300),
                activated,
            )),
        )
        .unwrap();
        assert_eq!(
            hold.cache.as_ref().and_then(|c| c.renew_at),
            Some(start + Duration::from_secs(270))
        );
    }

    #[test]
    fn expiry_wins_over_renewal_and_renewal_over_ping() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_000);
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            Some(Duration::from_secs(300)),
            start,
            activated,
            Activation::cache_only(session_plan(
                Duration::from_secs(300),
                activated,
            )),
        )
        .unwrap();
        let renew_at = start + Duration::from_secs(270);
        // Everything due at once: expiry, renewal and a ping.
        assert_eq!(hold.due_action(start + MINUTE * 5), Some(Action::Expire));
        // With expiry out of the way, renewal beats the ping cadence.
        hold.deadline = None;
        assert_eq!(hold.due_action(renew_at), Some(Action::Renew));
        hold.cache.as_mut().unwrap().renew_at = None;
        assert_eq!(hold.due_action(renew_at), Some(Action::Ping));
        // The scheduler wakes for the earliest of all three.
        assert_eq!(
            hold.next_wake(start),
            Some(start + MINUTE) // the ping, before renewal/ping expiry
        );
    }

    #[test]
    fn successful_renewal_starts_a_fresh_epoch() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_000);
        let max_ttl = Duration::from_secs(300);
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            activated,
            Activation::cache_only(session_plan(max_ttl, activated)),
        )
        .unwrap();
        let renewed_at = start + Duration::from_secs(270);
        let renewed_wall = wall(1_300);
        hold.record_renewal(renewed_at, renewed_wall);
        let cache = hold.cache.as_ref().expect("cache kept");
        // New epoch: expiry and next renewal derive from the renewal
        // time, and the ping cadence continues from it too.
        assert_eq!(cache.expires_wall, Some(renewed_wall + max_ttl));
        assert_eq!(
            cache.renew_at,
            Some(renewed_at + max_ttl - renew_margin(max_ttl))
        );
        assert_eq!(hold.last_ping, Some(renewed_wall));
        assert_eq!(hold.next_ping, Some(renewed_at + MINUTE));
    }

    #[test]
    fn replacement_and_off_discard_old_renewal_work() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_000);
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            activated,
            Activation::cache_only(session_plan(
                Duration::from_secs(300),
                activated,
            )),
        )
        .unwrap();
        // A replacement hold without cache metadata drops the old plan.
        hold.turn_on(
            Some("NEW".into()),
            KeySource::Explicit,
            MINUTE,
            None,
            start + MINUTE,
            wall(2_000),
            Activation::default(),
        )
        .unwrap();
        assert!(hold.cache.is_none());
        assert_eq!(hold.credential_mode, CredentialMode::None);
        assert_eq!(
            hold.due_action(start + Duration::from_secs(600)),
            Some(Action::Ping)
        );

        // A session hold turned off has no future renewal work.
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            wall(3_000),
            Activation::cache_only(session_plan(
                Duration::from_secs(300),
                wall(3_000),
            )),
        )
        .unwrap();
        hold.turn_off();
        assert!(hold.cache.is_none());
        assert_eq!(hold.credential_mode, CredentialMode::Session);
        assert_eq!(hold.due_action(start + Duration::from_secs(3600)), None);
        assert_eq!(hold.next_wake(start), None);
    }

    #[test]
    fn ordinary_replacement_overwrites_retained_session_provenance() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_000);
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            activated,
            Activation::cache_only(session_plan(
                Duration::from_secs(300),
                activated,
            )),
        )
        .unwrap();
        hold.turn_off();

        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start + MINUTE,
            wall(2_000),
            Activation::default(),
        )
        .unwrap();

        assert_eq!(hold.credential_mode, CredentialMode::None);
    }

    #[test]
    fn session_mode_requires_a_known_epoch_and_representable_ttl() {
        let mut hold = Hold::default();
        let start = t0();
        let activated = wall(1_000);
        // Unknown epoch: rejected, not guessed.
        let err = hold
            .turn_on(
                None,
                KeySource::Default,
                MINUTE,
                None,
                start,
                activated,
                Activation::cache_only(CachePlan {
                    mode: CredentialMode::Session,
                    default_ttl: Duration::from_secs(30),
                    max_ttl: Duration::from_secs(300),
                    started_wall: None,
                }),
            )
            .unwrap_err();
        assert!(err.contains("epoch"), "{err}");
        assert!(!hold.enabled);
        // Unschedulable TTL: rejected without a panic, state untouched.
        let err = hold
            .turn_on(
                None,
                KeySource::Default,
                MINUTE,
                None,
                start,
                activated,
                Activation::cache_only(session_plan(
                    Duration::from_secs(u64::MAX),
                    activated,
                )),
            )
            .unwrap_err();
        assert!(err.contains("too large"), "{err}");
        assert!(!hold.enabled);
        assert_eq!(hold.generation, 0);
    }

    #[test]
    fn ordinary_hold_with_unknown_epoch_has_no_countdown() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(
            None,
            KeySource::Default,
            MINUTE,
            None,
            start,
            wall(1_000),
            Activation::cache_only(CachePlan {
                mode: CredentialMode::None,
                default_ttl: Duration::from_secs(30),
                max_ttl: Duration::from_secs(300),
                started_wall: None,
            }),
        )
        .unwrap();
        // Policy values display, but no expiry countdown is invented and
        // no renewal is ever scheduled for a non-session hold.
        let status = hold.status();
        assert_eq!(status.max_cache_ttl_ms, Some(300_000));
        assert_eq!(status.max_expires_at_ms, None);
        assert!(hold.cache.as_ref().is_some_and(|c| c.renew_at.is_none()));
    }
}
