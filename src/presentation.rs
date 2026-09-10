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
//! decided, so ANSI sequences can never affect alignment.

use colored_text::{Colorize, RenderTarget};

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
