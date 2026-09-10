//! Pure hold state machine.
//!
//! All scheduling uses monotonic [`Instant`]s so wall-clock adjustments cannot
//! break the hold timer; wall-clock [`SystemTime`] appears only in status
//! snapshots. Keeping this module free of I/O makes the timing behaviour
//! unit-testable with synthetic instants.

use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Status snapshot exchanged over IPC.
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

/// What the daemon should do at a given instant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Run one background keepalive ping.
    Ping,
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
    /// Bumped on every on/off transition so pings racing a transition are
    /// discarded.
    pub generation: u64,
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
        }
    }
}

impl Hold {
    /// Enable (or replace) the hold at time `now`.
    ///
    /// `activated` is the wall-clock time of the successful key use that
    /// justifies the hold (the foreground ping of `keyhold on`); it becomes
    /// `last_ping`, so an immediate `status` reports the activation and a
    /// replacement hold never displays a timestamp inherited from the hold
    /// it replaced.
    ///
    /// All scheduling arithmetic is checked: a value that cannot be added
    /// to the monotonic clock is rejected with a reason and the state is
    /// left untouched, so no external input can panic the daemon.
    pub fn turn_on(
        &mut self,
        key: Option<String>,
        key_source: KeySource,
        interval: Duration,
        hold_for: Option<Duration>,
        now: Instant,
        activated: SystemTime,
    ) -> Result<(), &'static str> {
        let next_ping = now
            .checked_add(interval)
            .ok_or("ping interval is too large to schedule")?;
        let deadline = hold_for.and_then(|d| now.checked_add(d));
        if hold_for.is_some() && deadline.is_none() {
            return Err("hold duration is too large to schedule");
        }
        self.enabled = true;
        self.key = key;
        self.key_source = key_source;
        self.interval = interval;
        self.deadline = deadline;
        self.next_ping = Some(next_ping);
        self.last_ping = Some(activated);
        self.last_error = None;
        self.generation += 1;
        Ok(())
    }

    /// Disable the hold, leaving any last error intact for `status`.
    pub fn turn_off(&mut self) {
        self.enabled = false;
        self.deadline = None;
        self.next_ping = None;
    }

    /// Forget the last error (an explicit `off` acknowledges it).
    pub fn clear_error(&mut self) {
        self.last_error = None;
    }

    /// The action due at `now`, if any. Expiry wins over ping.
    pub fn due_action(&self, now: Instant) -> Option<Action> {
        if !self.enabled {
            return None;
        }
        if self.deadline.is_some_and(|d| now >= d) {
            return Some(Action::Expire);
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
        [self.deadline, self.next_ping]
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
        StatusData {
            hold_on: self.enabled,
            key: self.key.clone(),
            key_source: self.key_source,
            interval_ms: self.interval.as_millis() as u64,
            remaining_ms: self.remaining(now).map(|d| d.as_millis() as u64),
            last_ping_ms: self.last_ping.and_then(epoch),
            // Checked wall-clock projection: a far-future ping that cannot
            // be expressed in epoch milliseconds is reported as absent
            // rather than panicking or collapsing to zero.
            next_ping_ms: self.next_ping.and_then(|p| {
                wall.checked_add(p.saturating_duration_since(now))
                    .and_then(epoch)
            }),
            last_error: self.last_error.clone(),
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
        )
        .unwrap();
        hold.turn_off();
        assert!(!hold.enabled);
        assert_eq!(hold.due_action(start + 10 * MINUTE), None);
        assert_eq!(hold.next_wake(start), None);
        assert_eq!(hold.remaining(start), None);
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
        hold.turn_on(None, KeySource::Default, MINUTE, None, start, activated)
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
        )
        .unwrap();
        assert!(hold.next_ping.is_some(), "monotonic schedule kept");
        let status = hold.status();
        assert_eq!(status.next_ping_ms, None);
        assert_eq!(status.last_ping_ms, Some(1_000_000));
    }
}
