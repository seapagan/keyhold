//! Normal-screen drawing confined to a reserved region below prior output.

use std::{
    io::{self, IsTerminal, Write},
    sync::{Arc, atomic::AtomicBool},
};

use crossterm::{
    cursor::{self, MoveTo, RestorePosition, SavePosition},
    queue,
    terminal::{self, Clear, ClearType},
};
use keyhold::error::{Error, Result};
use unicode_width::UnicodeWidthChar;

// Heading, all twelve existing rows, and the three-line watch footer.
const REGION_ROWS: u16 = 18;

pub(super) fn require_interactive() -> Result<()> {
    let usable_term = std::env::var("TERM")
        .is_ok_and(|term| !term.is_empty() && term != "dumb");
    if !io::stdin().is_terminal()
        || !io::stdout().is_terminal()
        || !usable_term
    {
        return Err(Error::Message("status watch requires interactive stdin and stdout terminals (TERM must be set and not dumb); use --no-watch for one-shot output".into()));
    }
    Ok(())
}

pub(super) struct Terminal {
    output: io::Stdout,
    signals: Vec<signal_hook::SigId>,
    raw: bool,
    top: u16,
    rows: u16,
    width: u16,
    height: u16,
    previous: Vec<String>,
}

impl Terminal {
    pub(super) fn acquire(interrupted: Arc<AtomicBool>) -> Result<Self> {
        let mut guard = Self {
            output: io::stdout(),
            signals: Vec::with_capacity(2),
            raw: false,
            top: 0,
            rows: 0,
            width: 0,
            height: 0,
            previous: Vec::new(),
        };
        guard.signals.push(signal_hook::flag::register(
            signal_hook::consts::SIGINT,
            interrupted.clone(),
        )?);
        guard.signals.push(signal_hook::flag::register(
            signal_hook::consts::SIGTERM,
            interrupted,
        )?);
        // Construct the guard before any fallible terminal operation.
        terminal::enable_raw_mode()?;
        guard.raw = true;
        let (width, height) = terminal::size()?;
        if width < 2 || height == 0 {
            return Err(Error::Message(
                "status watch terminal is too small".into(),
            ));
        }
        let (_, current) = cursor::position().map_err(|e| Error::Message(format!("status watch requires an interactive terminal supporting cursor queries: {e}")))?;
        let rows = REGION_ROWS.min(height);
        let mut reserve = Vec::new();
        for _ in 0..rows {
            reserve.extend_from_slice(b"\r\n");
        }
        guard.output.write_all(&reserve)?;
        guard.output.flush()?;
        let bottom = current.saturating_add(rows).min(height - 1);
        guard.top = bottom + 1 - rows;
        guard.rows = rows;
        guard.width = width;
        guard.height = height;
        Ok(guard)
    }

    pub(super) fn resize(&mut self) -> Result<()> {
        let (width, height) = terminal::size()?;
        self.height = height;
        if height == 0 {
            self.rows = 0;
            self.width = width;
            self.previous.clear();
            return Ok(());
        }
        let (_, bottom) = cursor::position()?;
        let bottom = bottom.min(height - 1);
        self.clear_resized_region(bottom, height)?;
        self.rows = self.rows.min(height).min(bottom.saturating_add(1));
        self.top = bottom.saturating_add(1).saturating_sub(self.rows);
        self.width = width;
        self.previous.clear();
        self.reserve_to(height, bottom)?;
        self.output.flush()?;
        Ok(())
    }

    fn clear_resized_region(
        &mut self,
        bottom: u16,
        height: u16,
    ) -> Result<()> {
        // Saved positions follow reflow in VTE; fixed coordinates do not.
        if !self.previous.is_empty() {
            queue!(self.output, RestorePosition)?;
            self.output.flush()?;
            let (_, top) = cursor::position()?;
            self.output.write_all(&clear_region(top, bottom, height)?)?;
            queue!(self.output, MoveTo(0, bottom))?;
        }
        Ok(())
    }

    fn reserve_to(&mut self, height: u16, bottom: u16) -> io::Result<()> {
        // Expansion reserves new blank lines; it never clears prior output.
        let wanted = REGION_ROWS.min(height);
        if wanted > self.rows {
            let extra = wanted - self.rows;
            for _ in 0..extra {
                self.output.write_all(b"\r\n")?;
            }
            let bottom =
                bottom.saturating_add(extra).min(height.saturating_sub(1));
            self.rows = wanted;
            self.top = bottom.saturating_add(1).saturating_sub(wanted);
        }
        Ok(())
    }

    pub(super) fn draw(&mut self, text: &str) -> Result<()> {
        let lines = viewport(text, self.width, self.rows);
        let frame = render_changes(&self.previous, &lines, self.top)?;
        self.output.write_all(&frame)?;
        self.output.flush()?;
        self.previous = lines;
        Ok(())
    }

    fn clear(&mut self) -> io::Result<()> {
        let (width, height) = terminal::size()?;
        if self.rows == 0 || height == 0 {
            return Ok(());
        }
        // Re-query after an unprocessed resize so Drop stays in our region.
        if width != self.width || height != self.height {
            self.resize().map_err(io::Error::other)?;
        }
        let blank = vec![String::new(); usize::from(self.rows)];
        let frame = render_changes(&[], &blank, self.top)?;
        self.output.write_all(&frame)?;
        queue!(self.output, MoveTo(0, self.top))?;
        self.output.flush()
    }
}

impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.clear();
        if self.raw {
            let _ = terminal::disable_raw_mode();
        }
        for signal in self.signals.drain(..) {
            signal_hook::low_level::unregister(signal);
        }
        // The cursor remains visible throughout; no visibility state is owned.
    }
}

fn clear_region(top: u16, bottom: u16, height: u16) -> io::Result<Vec<u8>> {
    let end = bottom.saturating_add(1).min(height);
    let rows = end.saturating_sub(top);
    render_changes(&[], &vec![String::new(); usize::from(rows)], top)
}

fn display_width(line: &str) -> u16 {
    let mut chars = line.chars().peekable();
    let mut width = 0u16;
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            let _ = sgr_sequence(&mut chars);
        } else {
            width =
                width.saturating_add(
                    UnicodeWidthChar::width(c).unwrap_or(0) as u16
                );
        }
    }
    width
}

fn viewport(text: &str, width: u16, height: u16) -> Vec<String> {
    let mut lines: Vec<_> = text
        .lines()
        .map(|s| clip_line(s, usize::from(width.saturating_sub(1))))
        .collect();
    let height = usize::from(height);
    if lines.len() > height && height > 0 {
        // Keep quit instructions visible when the terminal cannot fit all rows.
        let footer = lines.pop().unwrap_or_default();
        lines.truncate(height.saturating_sub(1));
        lines.push(footer);
    }
    lines.resize(height, String::new());
    lines
}

fn render_changes(
    previous: &[String],
    lines: &[String],
    top: u16,
) -> io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for (index, line) in lines.iter().enumerate() {
        if previous.get(index) == Some(line) {
            continue;
        }
        queue!(
            output,
            MoveTo(0, top + index as u16),
            Clear(ClearType::CurrentLine)
        )?;
        output.write_all(line.as_bytes())?;
    }
    if !output.is_empty() && !lines.is_empty() {
        // Anchor the first paragraph and leave the cursor at the final end.
        // Both positions then follow the owned footprint when VTE reflows.
        queue!(
            output,
            MoveTo(0, top),
            SavePosition,
            MoveTo(
                display_width(lines.last().unwrap()),
                top + lines.len() as u16 - 1
            )
        )?;
    }
    Ok(output)
}

/// Only SGR styling may survive; IPC/tool text cannot move the cursor.
fn clip_line(line: &str, columns: usize) -> String {
    let mut output = String::new();
    let mut chars = line.chars().peekable();
    let mut used = 0;
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            if let Some(sgr) = sgr_sequence(&mut chars) {
                output.push_str(&sgr);
            }
        } else if !c.is_control() {
            let width = UnicodeWidthChar::width(c).unwrap_or(0);
            if used + width > columns {
                break;
            }
            used += width;
            output.push(c);
        }
    }
    if output.contains('\x1b') {
        output.push_str("\x1b[0m");
    }
    output
}

fn sgr_sequence(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
) -> Option<String> {
    if chars.next()? != '[' {
        return None;
    }
    let mut sequence = String::from("\x1b[");
    for c in chars.by_ref() {
        sequence.push(c);
        if ('@'..='~').contains(&c) {
            return (c == 'm'
                && sequence[2..sequence.len() - 1]
                    .chars()
                    .all(|p| p.is_ascii_digit() || p == ';' || p == ':'))
            .then_some(sequence);
        }
        if sequence.len() > 64 {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shrinking_width_clears_reflowed_rows_above_and_below_cursor() {
        let previous = vec![
            "\x1b[32mabcdefgh\x1b[0m".into(),
            "界界界".into(),
            "footer".into(),
        ];
        let drawn =
            String::from_utf8(render_changes(&[], &previous, 3).unwrap())
                .unwrap();
        assert!(drawn.contains("\x1b[4;1H\x1b7"));
        assert!(drawn.ends_with("\x1b[6;7H"));
        // At three columns the paragraphs occupy 3, 3, and 2 rows.
        // Saved start and current end now delimit rows 3 through 10.
        let cleared =
            String::from_utf8(clear_region(3, 10, 20).unwrap()).unwrap();
        assert!(cleared.contains("\x1b[4;1H\x1b[2K"));
        assert!(cleared.contains("\x1b[11;1H\x1b[2K"));
        assert!(!cleared.contains("\x1b[3;1H"));
        // A non-reflowing terminal reports the original bounds instead.
        let unchanged =
            String::from_utf8(clear_region(3, 5, 20).unwrap()).unwrap();
        assert!(!unchanged.contains("\x1b[7;1H"));
        assert!(
            clear_region(0, 10, 4)
                .unwrap()
                .ends_with(b"\x1b[1;1H\x1b7\x1b[4;1H")
        );
    }

    #[test]
    fn reflowed_screen_has_no_stale_text_or_damage_above_owned_region() {
        let lines = vec!["abcdefgh".into(), "界界界".into(), "footer".into()];
        let frame = String::from_utf8(render_changes(&[], &lines, 3).unwrap())
            .unwrap();
        let mut screen = TestScreen::new();
        screen.feed(&frame);
        screen.reflow(3);
        let bottom = screen.cursor.0;
        screen.feed("\x1b8");
        let top = screen.cursor.0;
        let clear =
            String::from_utf8(clear_region(top, bottom, 30).unwrap()).unwrap();
        screen.feed(&clear);
        assert_eq!(screen.rows[0], "old");
        assert!(
            screen.rows[usize::from(top)..=usize::from(bottom)]
                .iter()
                .all(String::is_empty)
        );
        let fresh = vec!["off".into(), "q".into()];
        screen.feed(
            &String::from_utf8(render_changes(&[], &fresh, top).unwrap())
                .unwrap(),
        );
        assert_eq!(screen.rows[usize::from(top)], "off");
        assert!(
            !screen
                .rows
                .iter()
                .any(|row| row.contains("abc") || row.contains("foo"))
        );
    }

    struct TestScreen {
        rows: Vec<String>,
        cursor: (u16, u16),
        saved: (u16, u16),
    }

    impl TestScreen {
        fn new() -> Self {
            let mut rows = vec![String::new(); 30];
            rows[0] = "old".into();
            Self {
                rows,
                cursor: (0, 0),
                saved: (0, 0),
            }
        }

        fn feed(&mut self, text: &str) {
            let mut chars = text.chars();
            while let Some(c) = chars.next() {
                if c == '\x1b' {
                    match chars.next().unwrap() {
                        '7' => self.saved = self.cursor,
                        '8' => self.cursor = self.saved,
                        '[' => self.csi(&mut chars),
                        c => panic!("unexpected escape {c}"),
                    }
                } else {
                    self.rows[usize::from(self.cursor.0)].push(c);
                    self.cursor.1 +=
                        UnicodeWidthChar::width(c).unwrap_or(0) as u16;
                }
            }
        }

        fn csi(&mut self, chars: &mut std::str::Chars<'_>) {
            let mut params = String::new();
            for c in chars.by_ref() {
                match c {
                    'H' => {
                        let (row, col) = params.split_once(';').unwrap();
                        self.cursor = (
                            row.parse::<u16>().unwrap() - 1,
                            col.parse::<u16>().unwrap() - 1,
                        );
                        return;
                    }
                    'K' => {
                        self.rows[usize::from(self.cursor.0)].clear();
                        return;
                    }
                    c => params.push(c),
                }
            }
        }

        fn reflow(&mut self, columns: usize) {
            let mut rows = Vec::new();
            let saved_row = self.saved.0;
            let cursor_row = self.cursor.0;
            for (index, line) in self.rows.iter().enumerate() {
                let start = rows.len() as u16;
                let mut chunks = vec![String::new()];
                let mut width = 0;
                for c in line.chars() {
                    let cells = UnicodeWidthChar::width(c).unwrap_or(0);
                    if width + cells > columns {
                        chunks.push(String::new());
                        width = 0;
                    }
                    chunks.last_mut().unwrap().push(c);
                    width += cells;
                }
                if index == usize::from(saved_row) {
                    self.saved.0 = start;
                }
                if index == usize::from(cursor_row) {
                    self.cursor =
                        (start + chunks.len() as u16 - 1, width as u16);
                }
                rows.extend(chunks);
            }
            self.rows = rows;
        }
    }

    #[test]
    fn shrinking_rows_and_values_clear_only_owned_lines() {
        let before = viewport(
            "Daemon running\nHold on\nError long failure\nq: Quit",
            80,
            5,
        );
        let after = viewport("Daemon stopped\nHold off\nq: Quit", 80, 5);
        let output =
            String::from_utf8(render_changes(&before, &after, 7).unwrap())
                .unwrap();
        assert!(output.contains("\x1b[8;1H\x1b[2KDaemon stopped"));
        assert!(output.contains("\x1b[11;1H\x1b[2K"));
        assert!(!output.contains("\x1b[2J"));
        assert!(render_changes(&after, &after, 7).unwrap().is_empty());
        let restarted =
            viewport("Daemon running\nHold on\nKey short\nq: Quit", 80, 5);
        assert!(
            String::from_utf8(render_changes(&after, &restarted, 7).unwrap())
                .unwrap()
                .contains("Key short")
        );
    }

    #[test]
    fn narrow_viewports_ignore_ansi_width_and_remove_cursor_controls() {
        assert_eq!(clip_line("\x1b[32m界abc\x1b[0m", 3), "\x1b[32m界a\x1b[0m");
        assert_eq!(clip_line("ab\x1b[2Jcd\r\t", 4), "abcd");
        assert_eq!(
            viewport("heading\nlong error\nq: Quit", 5, 2),
            vec!["head", "q: Q"]
        );
        assert_eq!(viewport("long", 1, 1), vec![""]);
        assert!(viewport("long", 0, 0).is_empty());
    }
}
