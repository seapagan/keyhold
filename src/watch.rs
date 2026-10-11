//! Observation-only status polling; terminal input never waits for IPC.

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant, SystemTime},
};

use colored_text::Colorize;
use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use keyhold::{
    error::{Error, Result},
    presentation,
};

#[path = "watch_terminal.rs"]
mod terminal;

struct Attempt {
    result: Result<Option<String>>,
    finished: Instant,
    wall: SystemTime,
}

struct Monitor {
    text: String,
    last_success: Option<SystemTime>,
    state: &'static str,
    pending: bool,
    next: Instant,
}

impl Monitor {
    fn new(now: Instant) -> Self {
        Self {
            text: "Keyhold status\n\nWaiting for status…\n".into(),
            last_success: None,
            state: "waiting",
            pending: false,
            next: now,
        }
    }

    fn begin(&mut self, now: Instant) -> bool {
        if self.pending || now < self.next {
            return false;
        }
        self.pending = true;
        true
    }

    fn complete(
        &mut self,
        attempt: Attempt,
        started: Instant,
        interval: Duration,
    ) {
        self.pending = false;
        self.next = next_poll(started, attempt.finished, interval);
        match attempt.result {
            Ok(Some(text)) => {
                self.text = text;
                self.last_success = Some(attempt.wall);
                self.state = "updated";
            }
            Ok(None) => {
                self.text = presentation::format_status_stopped();
                self.state = "daemon stopped";
            }
            Err(error) => {
                self.text = format!(
                    "Keyhold status\n\nDaemon       {}\nError        {}\n",
                    "disconnected / unavailable".red(),
                    error
                );
                self.state = "failed; retrying";
            }
        }
    }

    fn frame(&self, interval: Duration) -> String {
        let last = self.last_success.map_or_else(
            || "none yet".into(),
            |t| humantime::format_rfc3339_seconds(t).to_string(),
        );
        let state = if self.pending {
            "polling; previous snapshot"
        } else {
            self.state
        };
        format!(
            "{}\nLast success: {last}\nRefresh: {} | {state}\nq: Quit (Esc / Ctrl+C)\n",
            self.text,
            humantime::format_duration(interval)
        )
    }
}

/// First future tick on the monotonic grid; missed ticks are discarded.
fn next_poll(
    started: Instant,
    finished: Instant,
    interval: Duration,
) -> Instant {
    let elapsed = finished.saturating_duration_since(started).as_nanos();
    let remainder = elapsed % interval.as_nanos();
    let remainder = Duration::new(
        (remainder / 1_000_000_000) as u64,
        (remainder % 1_000_000_000) as u32,
    );
    finished + (interval - remainder)
}

fn quits(event: &Event) -> bool {
    matches!(event, Event::Key(key) if key.kind != KeyEventKind::Release &&
        (matches!(key.code, KeyCode::Char('q' | 'Q') | KeyCode::Esc) ||
         (key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL))))
}

struct Worker {
    requests: mpsc::SyncSender<()>,
    responses: mpsc::Receiver<Attempt>,
}

impl Worker {
    fn new(
        mut provider: impl FnMut() -> Result<Option<String>> + Send + 'static,
    ) -> Result<Self> {
        let (requests, receive) = mpsc::sync_channel(1);
        let (send, responses) = mpsc::sync_channel(1);
        thread::Builder::new().name("status-watch".into()).spawn(
            move || {
                while receive.recv().is_ok() {
                    let result = provider();
                    let attempt = Attempt {
                        result,
                        finished: Instant::now(),
                        wall: SystemTime::now(),
                    };
                    if send.send(attempt).is_err() {
                        break;
                    }
                }
            },
        )?;
        // Dropping the channels ends this observation-only worker after any
        // in-flight probe; quitting never joins a blocked IPC/credential call.
        Ok(Self {
            requests,
            responses,
        })
    }
}

pub(super) fn run(
    interval: Duration,
    provider: impl FnMut() -> Result<Option<String>> + Send + 'static,
) -> Result<()> {
    terminal::require_interactive()?;
    let interrupted = Arc::new(AtomicBool::new(false));
    let mut terminal = terminal::Terminal::acquire(interrupted.clone())?;
    let worker = Worker::new(provider)?;
    let mut monitor = Monitor::new(Instant::now());
    let mut started = monitor.next;
    terminal.draw(&monitor.frame(interval))?;
    while !interrupted.load(Ordering::Relaxed) {
        poll_status(
            &worker,
            &mut monitor,
            &mut started,
            interval,
            &mut terminal,
        )?;
        if !wait_for_event(&monitor, interval, &mut terminal)? {
            break;
        }
    }
    Ok(())
}

fn poll_status(
    worker: &Worker,
    monitor: &mut Monitor,
    started: &mut Instant,
    interval: Duration,
    terminal: &mut terminal::Terminal,
) -> Result<()> {
    match worker.responses.try_recv() {
        Ok(attempt) => {
            monitor.complete(attempt, *started, interval);
            terminal.draw(&monitor.frame(interval))?;
        }
        Err(mpsc::TryRecvError::Empty) => {}
        Err(mpsc::TryRecvError::Disconnected) => {
            return Err(Error::Message("status worker stopped".into()));
        }
    }
    let now = Instant::now();
    if monitor.begin(now) {
        worker
            .requests
            .send(())
            .map_err(|_| Error::Message("status worker stopped".into()))?;
        *started = now;
        terminal.draw(&monitor.frame(interval))?;
    }
    Ok(())
}

fn wait_for_event(
    monitor: &Monitor,
    interval: Duration,
    terminal: &mut terminal::Terminal,
) -> Result<bool> {
    let timeout = if monitor.pending {
        Duration::from_millis(50)
    } else {
        monitor
            .next
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(100))
    };
    if !event::poll(timeout)? {
        return Ok(true);
    }
    let event = event::read()?;
    if quits(&event) {
        return Ok(false);
    }
    if matches!(event, Event::Resize(..)) {
        terminal.resize()?;
        terminal.draw(&monitor.frame(interval))?;
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_provider_cannot_overlap_or_build_up_missed_requests() {
        let now = Instant::now();
        let mut monitor = Monitor::new(now);
        assert!(monitor.begin(now));
        let finished = now + Duration::from_secs(20);
        assert!(!monitor.begin(finished));
        monitor.complete(
            Attempt {
                result: Ok(None),
                finished,
                wall: SystemTime::UNIX_EPOCH,
            },
            now,
            Duration::from_millis(250),
        );
        assert!(!monitor.begin(finished));
        assert!(!monitor.begin(finished + Duration::from_millis(249)));
        assert!(monitor.begin(finished + Duration::from_millis(250)));
        assert!(!monitor.begin(finished + Duration::from_secs(1)));
    }

    #[test]
    fn skipped_ticks_never_queue_a_backlog() {
        let start = Instant::now();
        for (finished_ms, next_ms) in
            [(0, 500), (499, 500), (500, 1000), (1700, 2000)]
        {
            assert_eq!(
                next_poll(
                    start,
                    start + Duration::from_millis(finished_ms),
                    Duration::from_millis(500)
                ),
                start + Duration::from_millis(next_ms)
            );
        }
    }

    #[test]
    fn failures_and_stops_do_not_fabricate_success_and_recovery_replaces_rows()
    {
        let now = Instant::now();
        let wall = SystemTime::UNIX_EPOCH + Duration::from_secs(100);
        let mut monitor = Monitor::new(now);
        let mut complete = |result, time| {
            monitor.complete(
                Attempt {
                    result,
                    finished: now,
                    wall: time,
                },
                now,
                Duration::from_secs(2),
            );
            monitor.frame(Duration::from_secs(2))
        };
        assert!(complete(Ok(None), wall).contains("Last success: none yet"));
        assert!(
            complete(Err(Error::Message("offline".into())), wall)
                .contains("Last success: none yet")
        );
        let success =
            complete(Ok(Some("Key state    unlocked\n".into())), wall);
        assert!(success.contains("1970-01-01T00:01:40Z"));
        let failure = complete(
            Err(Error::Message("offline".into())),
            wall + Duration::from_secs(100),
        );
        assert!(failure.contains("1970-01-01T00:01:40Z"));
        assert!(!failure.contains("unlocked"));
        assert!(failure.contains("failed; retrying"));
        let recovered = complete(
            Ok(Some("Hold         off\n".into())),
            wall + Duration::from_secs(200),
        );
        assert!(!recovered.contains("offline"));
        assert!(recovered.contains("1970-01-01T00:05:00Z"));
    }

    #[test]
    fn quit_keys_do_not_require_enter_or_accept_key_releases() {
        use crossterm::event::KeyEvent;
        for code in [KeyCode::Char('q'), KeyCode::Char('Q'), KeyCode::Esc] {
            assert!(quits(&Event::Key(KeyEvent::new(
                code,
                KeyModifiers::NONE
            ))));
        }
        assert!(quits(&Event::Key(KeyEvent::new(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        ))));
        assert!(!quits(&Event::Key(KeyEvent::new(
            KeyCode::Enter,
            KeyModifiers::NONE
        ))));
        assert!(!quits(&Event::Key(KeyEvent::new_with_kind(
            KeyCode::Char('q'),
            KeyModifiers::NONE,
            KeyEventKind::Release
        ))));
    }
}
