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

/// Print an informational warning with a `warning:` prefix (yellow when
/// colour applies).
pub fn warning(message: &str) {
    println!("{} {}", "warning:".yellow(), message);
}

/// Print every activation warning, in order.
pub fn warnings(messages: &[String]) {
    for message in messages {
        warning(message);
    }
}

/// Print the confirmation for `keyhold credential clear`.
pub fn session_credentials_cleared() {
    println!("Session credentials {}.", "cleared".green());
}

/// Print the notice that `keyhold credential clear` found nothing.
pub fn no_session_credentials() {
    println!("No Keyhold session credentials {}.", "stored".yellow());
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
const LABELS: [&str; 12] = [
    "Daemon",
    "Hold",
    "Key",
    "Key state",
    "Credential",
    "GPG max TTL",
    "Max expiry",
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

/// The configured interval, at its natural precision (`5m`, `500ms`).
fn interval(ms: u64) -> colored_text::StyledText {
    humantime::format_duration(Duration::from_millis(ms))
        .to_string()
        .cyan()
}

/// Remaining hold time, rounded for humans: hours and minutes once at
/// least a minute is left (a fresh `--for 8h` hold reads `8h`, not
/// `7h 59m`), plain seconds below that.
fn remaining(ms: u64) -> colored_text::StyledText {
    let text = if ms >= 60_000 {
        // Round to the nearest minute (saturating: remaining can sit
        // near `u64::MAX` for unrepresentable deadlines), so a fresh
        // hold keeps its advertised time instead of dropping a minute.
        let minutes = ms.saturating_add(30_000) / 60_000;
        humantime::format_duration(Duration::from_secs(minutes * 60))
            .to_string()
    } else {
        // Capped at 59 so the display steps straight to `1m` at a
        // minute instead of ever showing `60s`.
        format!("{}s", (ms.saturating_add(500) / 1000).min(59))
    };
    text.cyan()
}

/// A ping delta at whole-second precision (`3s`, `4m 56s`).
fn ping_delta(ms: u64) -> colored_text::StyledText {
    humantime::format_duration(Duration::from_secs(
        ms.saturating_add(500) / 1000,
    ))
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
/// Row selection lives in [`status_rows`]; see its documentation for
/// which rows appear in which state.
pub fn print_status(
    data: &StatusData,
    key_state: Option<String>,
    credential: Option<String>,
) {
    println!("{}", "Keyhold status".bold());
    println!();
    for r in status_rows(data, key_state, credential) {
        row(r.label, r.value);
    }
}

/// One rendered status row.
#[derive(Debug)]
struct Row {
    label: &'static str,
    value: String,
}

/// The status rows for one snapshot, heading excluded.
///
/// Only rows meaningful for the current state appear:
///
/// * the key rows (`Key`, `Key state`, `Credential`) need an active
///   hold **or** retained resolved-key metadata — a hold being `off`
///   does not make the key's cache state or the session credential
///   disappear, so their live values stay visible while there is a
///   resolved key to query (`Key state`/`Credential` remain absent
///   when the caller could not resolve them);
/// * hold timing and cache-countdown rows (`GPG max TTL`, `Max
///   expiry`, `Interval`, `Remaining`, `Last ping`, `Next ping`)
///   require an active hold and are never fabricated from stale
///   metadata;
/// * `Error` shows the retained last failure either way.
fn status_rows(
    data: &StatusData,
    key_state: Option<String>,
    credential: Option<String>,
) -> Vec<Row> {
    let mut rows = Vec::new();
    rows.push(Row {
        label: "Daemon",
        value: "running".green().to_string(),
    });
    rows.push(Row {
        label: "Hold",
        value: if data.hold_on {
            "on".green().to_string()
        } else {
            "off".yellow().to_string()
        },
    });
    if data.hold_on || data.fingerprint.is_some() {
        let key = data.key.clone().unwrap_or_else(|| "default".into());
        // Git-selected keys carry a dim suffix; layout is unaffected
        // because the value column is last.
        let value = match data.key_source {
            KeySource::Git => {
                format!("{} {}", key.cyan(), "(git)".dim())
            }
            _ => key.cyan().to_string(),
        };
        rows.push(Row {
            label: "Key",
            value,
        });
        if let Some(state) = key_state {
            rows.push(Row {
                label: "Key state",
                value: state,
            });
        }
        if let Some(credential) = credential {
            rows.push(Row {
                label: "Credential",
                value: credential,
            });
        }
    }
    if data.hold_on {
        if let Some(ms) = data.max_cache_ttl_ms {
            rows.push(Row {
                label: "GPG max TTL",
                value: interval(ms).to_string(),
            });
        }
        match data.max_expires_at_ms {
            // A countdown is only honest when keyhold knows the epoch;
            // TTL values without an epoch display as unknown.
            Some(ms) if data.max_cache_ttl_ms.is_some() => {
                let now = epoch_ms();
                let value = format!(
                    "in {}{}",
                    ping_delta(ms.saturating_sub(now)),
                    if data.credential_mode
                        == crate::state::CredentialMode::Session
                    {
                        " (auto-renew)"
                    } else {
                        ""
                    },
                );
                rows.push(Row {
                    label: "Max expiry",
                    value,
                });
            }
            _ if data.max_cache_ttl_ms.is_some() => rows.push(Row {
                label: "Max expiry",
                value: "unknown".dim().to_string(),
            }),
            _ => {}
        }
        rows.push(Row {
            label: "Interval",
            value: interval(data.interval_ms).to_string(),
        });
        match data.remaining_ms {
            Some(ms) => rows.push(Row {
                label: "Remaining",
                value: remaining(ms).to_string(),
            }),
            None => rows.push(Row {
                label: "Remaining",
                value: "no deadline".dim().to_string(),
            }),
        }
        let now = epoch_ms();
        if let Some(ms) = data.last_ping_ms {
            rows.push(Row {
                label: "Last ping",
                value: format!("{} ago", ping_delta(now.saturating_sub(ms))),
            });
        }
        if let Some(ms) = data.next_ping_ms {
            rows.push(Row {
                label: "Next ping",
                value: format!("in {}", ping_delta(ms.saturating_sub(now))),
            });
        }
    }
    if let Some(err) = &data.last_error {
        rows.push(Row {
            label: "Error",
            value: err.red().to_string(),
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_width_is_the_widest_label_plus_gap() {
        assert_eq!(label_width(), 13);
        assert!(
            LABELS
                .iter()
                .all(|label| label.len() + LABEL_GAP <= label_width())
        );
    }

    /// A snapshot with only the fields `status_rows` branches on.
    fn snapshot(
        hold_on: bool,
        fingerprint: Option<&str>,
        keygrip: Option<&str>,
    ) -> StatusData {
        StatusData {
            hold_on,
            key: None,
            key_source: KeySource::Default,
            interval_ms: 300_000,
            remaining_ms: hold_on.then_some(600_000),
            last_ping_ms: None,
            next_ping_ms: None,
            last_error: None,
            fingerprint: fingerprint.map(str::to_string),
            keygrip: keygrip.map(str::to_string),
            credential_mode: crate::state::CredentialMode::None,
            default_cache_ttl_ms: None,
            max_cache_ttl_ms: None,
            max_expires_at_ms: None,
        }
    }

    fn labels(rows: &[Row]) -> Vec<&'static str> {
        rows.iter().map(|r| r.label).collect()
    }

    #[test]
    fn off_hold_with_a_retained_key_still_shows_live_state_rows() {
        let data = snapshot(false, Some("FPR"), Some("GRIP"));
        let rows = status_rows(
            &data,
            Some("unlocked".into()),
            Some("session stored (not in use)".into()),
        );
        assert_eq!(
            labels(&rows),
            vec!["Daemon", "Hold", "Key", "Key state", "Credential"]
        );
        // Hold timing rows stay absent: the hold is genuinely off.
        for absent in ["Interval", "Remaining", "Next ping", "Last ping"] {
            assert!(!labels(&rows).contains(&absent), "{absent} shown");
        }
    }

    #[test]
    fn off_hold_without_a_resolved_key_shows_no_key_rows() {
        let data = snapshot(false, None, None);
        // Unresolvable live values must not fabricate rows either.
        let rows = status_rows(&data, None, None);
        assert_eq!(labels(&rows), vec!["Daemon", "Hold"]);
    }

    #[test]
    fn off_hold_with_a_retained_key_never_fabricates_live_rows() {
        let data = snapshot(false, Some("FPR"), None);
        // Resolved key but no keygrip (no live state queryable): the
        // Key row shows, the live rows do not.
        let rows = status_rows(&data, None, None);
        assert_eq!(labels(&rows), vec!["Daemon", "Hold", "Key"]);
    }

    #[test]
    fn active_hold_shows_the_full_row_set() {
        let data = snapshot(true, Some("FPR"), Some("GRIP"));
        let rows = status_rows(&data, Some("locked".into()), None);
        assert_eq!(
            labels(&rows),
            vec![
                "Daemon",
                "Hold",
                "Key",
                "Key state",
                "Interval",
                "Remaining"
            ]
        );
    }

    #[test]
    fn retained_error_row_appears_while_off() {
        let mut data = snapshot(false, None, None);
        data.last_error = Some("the key expired".into());
        let rows = status_rows(&data, None, None);
        assert_eq!(labels(&rows), vec!["Daemon", "Hold", "Error"]);
    }

    #[test]
    fn interval_keeps_natural_precision() {
        assert_eq!(interval(300_000).plain_text(), "5m");
        assert_eq!(interval(90_000).plain_text(), "1m 30s");
        assert_eq!(interval(1_500).plain_text(), "1s 500ms");
    }

    #[test]
    fn remaining_rounds_to_nearest_minute_at_an_hour_scale() {
        // A fresh hold keeps its advertised time for the first half
        // minute instead of immediately dropping a minute.
        let eight_hours = 8 * 3_600_000;
        assert_eq!(remaining(eight_hours).plain_text(), "8h");
        assert_eq!(remaining(eight_hours - 1_000).plain_text(), "8h");
        assert_eq!(remaining(eight_hours - 29_999).plain_text(), "8h");
        assert_eq!(remaining(eight_hours - 30_001).plain_text(), "7h 59m");
        // Hours and minutes only, no seconds or milliseconds.
        assert_eq!(
            remaining(2 * 3_600_000 + 17 * 60_000).plain_text(),
            "2h 17m"
        );
        assert_eq!(remaining(59 * 60_000).plain_text(), "59m");
        // A near-`u64::MAX` deadline must not overflow the rounding add.
        let styled = remaining(u64::MAX);
        let text = styled.plain_text();
        assert!(!text.contains("ms"), "{text}");
    }

    #[test]
    fn remaining_below_a_minute_shows_rounded_seconds() {
        // Rounding to the nearest second would give 60; the cap keeps
        // the display at `59s` until a true minute shows `1m`.
        assert_eq!(remaining(59_499).plain_text(), "59s");
        assert_eq!(remaining(59_999).plain_text(), "59s");
        assert_eq!(remaining(60_000).plain_text(), "1m");
        assert_eq!(remaining(45_000).plain_text(), "45s");
        assert_eq!(remaining(1_499).plain_text(), "1s");
        assert_eq!(remaining(1_500).plain_text(), "2s");
        assert_eq!(remaining(499).plain_text(), "0s");
    }

    #[test]
    fn ping_deltas_show_whole_seconds_only() {
        assert_eq!(ping_delta(0).plain_text(), "0s");
        assert_eq!(ping_delta(499).plain_text(), "0s");
        assert_eq!(ping_delta(500).plain_text(), "1s");
        assert_eq!(ping_delta(3_400).plain_text(), "3s");
        assert_eq!(ping_delta(4 * 60_000 + 56_000).plain_text(), "4m 56s");
        assert_eq!(
            ping_delta(3_600_000 + 2 * 60_000 + 3_000).plain_text(),
            "1h 2m 3s"
        );
        // Near-`u64::MAX` deltas (absurd timestamps) must not overflow.
        let styled = ping_delta(u64::MAX);
        let text = styled.plain_text();
        assert!(text.ends_with('s') && !text.contains("ms"), "{text}");
    }
}
