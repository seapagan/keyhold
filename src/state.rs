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
    pub fn turn_on(
        &mut self,
        key: Option<String>,
        interval: Duration,
        hold_for: Option<Duration>,
        now: Instant,
        activated: SystemTime,
    ) {
        self.enabled = true;
        self.key = key;
        self.interval = interval;
        self.deadline = hold_for.map(|d| now + d);
        self.next_ping = Some(now + interval);
        self.last_ping = Some(activated);
        self.last_error = None;
        self.generation += 1;
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
    pub fn record_ping_ok(&mut self, now: Instant, wall: SystemTime) {
        self.last_ping = Some(wall);
        self.next_ping = Some(now + self.interval);
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
        let epoch = |t: SystemTime| {
            u64::try_from(
                t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis()),
            )
            .unwrap_or(0)
        };
        let wall = SystemTime::now();
        StatusData {
            hold_on: self.enabled,
            key: self.key.clone(),
            interval_ms: self.interval.as_millis() as u64,
            remaining_ms: self.remaining(now).map(|d| d.as_millis() as u64),
            last_ping_ms: self.last_ping.map(epoch),
            next_ping_ms: self
                .next_ping
                .map(|p| epoch(wall + p.saturating_duration_since(now))),
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
        hold.turn_on(Some("ABCD".into()), MINUTE, None, start, wall(1_000));
        assert_eq!(hold.due_action(start), None);
        assert_eq!(hold.due_action(start + MINUTE), Some(Action::Ping));
        assert_eq!(hold.next_wake(start), Some(start + MINUTE));
        assert!(hold.remaining(start).is_none());
    }

    #[test]
    fn deadline_wins_over_ping() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(None, MINUTE, Some(MINUTE), start, wall(1_000));
        assert_eq!(hold.due_action(start + MINUTE), Some(Action::Expire));
    }

    #[test]
    fn turn_off_stops_all_scheduling() {
        let mut hold = Hold::default();
        let start = t0();
        hold.turn_on(None, MINUTE, Some(MINUTE), start, wall(1_000));
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
        hold.turn_on(None, MINUTE, None, start, wall(1_000));
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
        hold.turn_on(None, MINUTE, None, start, wall(1_000));
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
        hold.turn_on(None, MINUTE, Some(MINUTE), start, wall(1_000));
        let generation = hold.generation;
        let later = start + Duration::from_secs(10);
        hold.turn_on(
            Some("K".into()),
            Duration::from_secs(30),
            None,
            later,
            wall(2_000),
        );
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
            MINUTE,
            Some(Duration::from_secs(3600)),
            start,
            wall(1_000),
        );
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
        hold.turn_on(None, MINUTE, None, start, activated);
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
        hold.turn_on(None, MINUTE, None, start, wall(1_000));
        hold.record_ping_ok(start + MINUTE, wall(1_060));
        let later = start + 2 * MINUTE;
        let fresh = wall(2_000);
        hold.turn_on(Some("K".into()), MINUTE, None, later, fresh);
        assert_eq!(hold.last_ping, Some(fresh));
    }
}
