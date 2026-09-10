//! User-facing terminal presentation.
//!
//! Colour policy is delegated entirely to `colored_text`: terminal
//! detection, `NO_COLOR` / `FORCE_COLOR` / `CLICOLOR` handling and colour
//! depth are the crate's job. This module only chooses which semantic
//! fragments are styled — green for success/active states, yellow for
//! inactive-but-valid states, red for errors, cyan for key identifiers
//! and durations — and renders them to the right target. Redirected or
//! captured output stays plain automatically.
//!
//! Styling is applied to individual fragments after any layout has been
//! decided (labels stay plain, widths are computed from plain text), so
//! ANSI sequences can never affect alignment.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use colored_text::{Colorize, RenderTarget};

use crate::state::{KeySource, StatusData};

/// Print the success line for a timed hold.
pub fn enabled_for(duration: &str) {
    println!("Keyhold {} for {}.", "enabled".green(), duration.cyan());
}

/// Print the success line for an indefinite hold.
pub fn enabled_indefinitely() {
    println!("Keyhold {} (no expiry).", "enabled".green());
}

/// Print the confirmation for `keyhold off`.
pub fn disabled() {
    println!("Keyhold {}.", "disabled".yellow());
}

/// Print the confirmation for `keyhold daemon --stop`.
pub fn daemon_stopped() {
    println!("Daemon {}.", "stopped".green());
}

/// Print the notice that no daemon is running (idempotent stop/off).
pub fn daemon_not_running() {
    println!("Daemon {}.", "not running".yellow());
}

/// Print the confirmation for `keyhold daemon --background`.
pub fn daemon_started() {
    println!("Daemon {}.", "started".green());
}

/// Print the notice that a background start found the daemon running
/// (idempotent success).
pub fn daemon_already_running() {
    println!("Daemon {}.", "already running".yellow());
}

/// Print an application error to stderr with a red `error:` prefix.
///
/// Rendered for the stderr target so colour follows stderr, not stdout.
pub fn error(message: &str) {
    eprintln!(
        "{} {} {}",
        "keyhold:".dim().render(RenderTarget::Stderr),
        "error:".red().render(RenderTarget::Stderr),
        message,
    );
}

/// Every status row label. The label column width is derived from this
/// list, so no spacing is hand-counted.
const LABELS: [&str; 8] = [
    "Daemon",
    "Hold",
    "Key",
    "Interval",
    "Remaining",
    "Last ping",
    "Next ping",
    "Error",
];

/// Gap between the label and value columns.
const LABEL_GAP: usize = 2;

/// Width of the plain-text label column: widest label plus the gap.
///
/// Labels are fixed ASCII, so byte length is display width. Layout is
/// computed from these plain strings only; styling is applied afterwards
/// and can never affect alignment.
fn label_width() -> usize {
    LABELS.iter().map(|label| label.len()).max().unwrap_or(0) + LABEL_GAP
}

/// Print one aligned row: plain label, styled value.
fn row(label: &str, value: impl std::fmt::Display) {
    println!("{:<width$}{}", label, value, width = label_width());
}

/// Current wall-clock time in Unix epoch milliseconds (0 if the clock is
/// before the epoch). Used only for display deltas.
fn epoch_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis()),
    )
    .unwrap_or(0)
}

/// A duration value, styled cyan.
fn duration(ms: u64) -> colored_text::StyledText {
    humantime::format_duration(Duration::from_millis(ms))
        .to_string()
        .cyan()
}

/// Print the status snapshot for a stopped daemon.
pub fn status_stopped() {
    println!("{}", "Keyhold status".bold());
    println!();
    row("Daemon", "stopped".yellow());
    row("Hold", "off".yellow());
}

/// Print the aligned two-column status snapshot for a running daemon.
///
/// Only rows meaningful for the current state appear: key, timing and
/// ping rows require an active hold, and absent display timestamps (for
/// example an unrepresentable far-future next ping) omit their row.
pub fn print_status(data: &StatusData) {
    println!("{}", "Keyhold status".bold());
    println!();
    row("Daemon", "running".green());
    row(
        "Hold",
        if data.hold_on {
            "on".green()
        } else {
            "off".yellow()
        },
    );
    if data.hold_on {
        let key = data.key.clone().unwrap_or_else(|| "default".into());
        // Git-selected keys carry a dim suffix; layout is unaffected
        // because the value column is last.
        let value = match data.key_source {
            KeySource::Git => {
                format!("{} {}", key.cyan(), "(git)".dim())
            }
            _ => key.cyan().to_string(),
        };
        row("Key", value);
        row("Interval", duration(data.interval_ms));
        match data.remaining_ms {
            Some(ms) => row("Remaining", duration(ms)),
            None => row("Remaining", "no deadline".dim()),
        }
        let now = epoch_ms();
        if let Some(ms) = data.last_ping_ms {
            row(
                "Last ping",
                format!("{} ago", duration(now.saturating_sub(ms))),
            );
        }
        if let Some(ms) = data.next_ping_ms {
            row(
                "Next ping",
                format!("in {}", duration(ms.saturating_sub(now))),
            );
        }
    }
    if let Some(err) = &data.last_error {
        row("Error", err.red());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_width_is_the_widest_label_plus_gap() {
        assert_eq!(label_width(), 11);
        assert!(
            LABELS
                .iter()
                .all(|label| label.len() + LABEL_GAP <= label_width())
        );
    }
}
