//! Real PTY input/cleanup and status transitions against isolated fixtures.

mod common;

use std::{
    fs::File,
    io::{Read, Write},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU16, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

use common::TestEnv;
use rustix::{pty, termios};

struct PtyWatch {
    master: File,
    slave: File,
    original: termios::Termios,
    child: Child,
    output: mpsc::Receiver<Vec<u8>>,
    transcript: String,
    cursor_row: Arc<AtomicU16>,
    respond: Arc<AtomicBool>,
    stop_reader: Arc<AtomicBool>,
    reader: Option<thread::JoinHandle<()>>,
}

fn open_terminal() -> (File, File) {
    let master =
        pty::openpt(pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC)
            .unwrap();
    pty::grantpt(&master).unwrap();
    pty::unlockpt(&master).unwrap();
    let slave = File::from(
        pty::ioctl_tiocgptpeer(
            &master,
            pty::OpenptFlags::RDWR | pty::OpenptFlags::CLOEXEC,
        )
        .unwrap(),
    );
    termios::tcsetwinsize(
        &slave,
        termios::Winsize {
            ws_row: 30,
            ws_col: 100,
            ws_xpixel: 0,
            ws_ypixel: 0,
        },
    )
    .unwrap();
    (File::from(master), slave)
}

impl PtyWatch {
    fn new(env: &TestEnv, args: &[&str], respond: bool) -> Self {
        Self::at_row(env, args, respond, 24, None)
    }

    fn at_row(
        env: &TestEnv,
        args: &[&str],
        respond: bool,
        row: u16,
        redirect_stdin: Option<bool>,
    ) -> Self {
        let (master, slave) = open_terminal();
        let original = termios::tcgetattr(&slave).unwrap();
        let command = env.keyhold(args);
        // Crossterm must not read dimensions from the parent shell's /dev/tty.
        let child =
            Command::new("setsid")
                .arg(command.get_program())
                .args(command.get_args())
                .envs(command.get_envs().filter_map(|(key, value)| {
                    value.map(|value| (key, value))
                }))
                .env("TERM", "xterm-256color")
                .env("NO_COLOR", "1")
                .stdin(if redirect_stdin == Some(true) {
                    Stdio::null()
                } else {
                    slave.try_clone().unwrap().into()
                })
                .stdout(if redirect_stdin == Some(false) {
                    Stdio::piped()
                } else {
                    slave.try_clone().unwrap().into()
                })
                .stderr(slave.try_clone().unwrap())
                .spawn()
                .unwrap();
        let cursor_row = Arc::new(AtomicU16::new(row));
        let respond = Arc::new(AtomicBool::new(respond));
        let (output, reader, stop_reader) =
            read_pty(&master, cursor_row.clone(), respond.clone());
        Self {
            master,
            slave,
            original,
            child,
            output,
            transcript: String::new(),
            cursor_row,
            respond,
            stop_reader,
            reader: Some(reader),
        }
    }

    fn resize(&mut self, width: u16, height: u16) {
        self.cursor_row.fetch_min(height, Ordering::Relaxed);
        termios::tcsetwinsize(
            &self.slave,
            termios::Winsize {
                ws_row: height,
                ws_col: width,
                ws_xpixel: 0,
                ws_ypixel: 0,
            },
        )
        .unwrap();
        assert!(
            Command::new("kill")
                .args(["-WINCH", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }

    fn wait_for(&mut self, needle: &str) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !self.transcript.contains(needle) {
            let bytes = self
                .output
                .recv_timeout(
                    deadline
                        .saturating_duration_since(std::time::Instant::now()),
                )
                .unwrap_or_else(|e| {
                    panic!("missing {needle}: {e}\n{}", self.transcript)
                });
            self.transcript.push_str(&String::from_utf8_lossy(&bytes));
        }
    }

    fn finish(&mut self, success: bool) {
        common::wait_with_kill(&mut self.child, Duration::from_secs(3));
        assert_eq!(
            self.child.wait().unwrap().success(),
            success,
            "{}",
            self.transcript
        );
        while let Ok(bytes) =
            self.output.recv_timeout(Duration::from_millis(30))
        {
            self.transcript.push_str(&String::from_utf8_lossy(&bytes));
        }
        let restored = termios::tcgetattr(&self.slave).unwrap();
        assert_eq!(restored.input_modes, self.original.input_modes);
        assert_eq!(restored.output_modes, self.original.output_modes);
        assert_eq!(restored.control_modes, self.original.control_modes);
        assert_eq!(restored.local_modes, self.original.local_modes);
        assert_eq!(
            format!("{:?}", restored.special_codes),
            format!("{:?}", self.original.special_codes)
        );
        assert!(!self.transcript.contains("\x1b[?1049h"));
        assert!(!self.transcript.contains("\x1b[?25l"));
    }

    fn assert_raw(&self) {
        let raw = termios::tcgetattr(&self.slave).unwrap();
        let cooked = termios::LocalModes::ICANON | termios::LocalModes::ECHO;
        assert!(self.original.local_modes.contains(cooked));
        assert!(!raw.local_modes.intersects(cooked));
    }

    fn sigterm(&self) {
        assert!(
            Command::new("kill")
                .args(["-TERM", &self.child.id().to_string()])
                .status()
                .unwrap()
                .success()
        );
    }
}

fn read_pty(
    master: &File,
    reply_row: Arc<AtomicU16>,
    respond: Arc<AtomicBool>,
) -> (
    mpsc::Receiver<Vec<u8>>,
    thread::JoinHandle<()>,
    Arc<AtomicBool>,
) {
    let stop_reader = Arc::new(AtomicBool::new(false));
    let stop = stop_reader.clone();
    let mut reader = master.try_clone().unwrap();
    let mut reply = master.try_clone().unwrap();
    rustix::io::ioctl_fionbio(&reader, true).unwrap();
    let (send, output) = mpsc::channel();
    let handle = thread::spawn(move || {
        let mut buf = [0; 4096];
        let mut pending = Vec::new();
        while !stop.load(Ordering::Relaxed) {
            let count = match reader.read(&mut buf) {
                Ok(count) => count,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                Err(_) => break,
            };
            if count == 0 {
                break;
            }
            pending.extend_from_slice(&buf[..count]);
            if respond.load(Ordering::Relaxed)
                && pending.windows(4).any(|w| w == b"\x1b[6n")
            {
                let height =
                    termios::tcgetwinsize(&reader).unwrap().ws_row.max(1);
                let row =
                    reply_row.swap(height, Ordering::Relaxed).clamp(1, height);
                let _ = write!(reply, "\x1b[{row};1R");
                pending.clear();
            }
            if send.send(buf[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    (output, handle, stop_reader)
}

impl Drop for PtyWatch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        self.stop_reader.store(true, Ordering::Relaxed);
        if let Some(reader) = self.reader.take() {
            reader.join().unwrap();
        }
    }
}

#[test]
fn quit_keys_restore_terminal_without_starting_a_daemon() {
    for key in [b"q".as_slice(), b"Q", b"\x1b", b"\x03"] {
        let env = TestEnv::new();
        let mut watch = PtyWatch::new(&env, &["status", "-i", "0.25"], true);
        watch.wait_for("daemon stopped");
        assert!(watch.transcript.contains("Last success: none yet"));
        watch.master.write_all(key).unwrap();
        watch.finish(true);
        assert!(!env.sock().exists());
        assert!(env.gpg_log().is_empty());
    }
}

#[test]
fn scheduling_overflow_reports_an_error_and_restores_terminal() {
    let env = TestEnv::new();
    let mut watch =
        PtyWatch::new(&env, &["status", "-i", "9223372036854775807s"], true);
    watch.wait_for("status refresh interval is too large to schedule");
    watch.finish(false);
    assert!(!watch.transcript.contains("panicked"));
}

#[test]
fn sigterm_restores_terminal_while_waiting_for_the_next_refresh() {
    let env = TestEnv::new();
    let mut watch = PtyWatch::new(&env, &["status", "-i", "60"], true);
    watch.wait_for("daemon stopped");
    watch.assert_raw();
    watch.sigterm();
    watch.finish(true);
}

#[test]
fn sigterm_restores_terminal_during_a_stalled_poll() {
    let env = TestEnv::new();
    std::fs::create_dir_all(env.sock().parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(env.sock()).unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut watch = PtyWatch::new(&env, &["status", "-w"], true);
    watch.wait_for("polling; previous snapshot");
    let status = accept_with_timeout(&listener);
    status
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    assert!(matches!(
        keyhold::ipc::read_request(&status).unwrap().unwrap(),
        keyhold::ipc::Request::Status
    ));
    watch.assert_raw();
    watch.sigterm();
    // Keep the connection open without replying until watch has exited.
    watch.finish(true);
    drop(status);
}

fn accept_with_timeout(
    listener: &std::os::unix::net::UnixListener,
) -> std::os::unix::net::UnixStream {
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        match listener.accept() {
            Ok((stream, _)) => return stream,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "IPC accept timed out"
                );
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("IPC accept failed: {error}"),
        }
    }
}

#[test]
fn cursor_query_error_restores_raw_mode() {
    let env = TestEnv::new();
    let mut watch = PtyWatch::new(&env, &["status", "-w"], false);
    watch.wait_for("supporting cursor queries");
    watch.finish(false);
}

#[test]
fn conventional_sigint_restores_terminal_during_a_stalled_poll() {
    use std::os::unix::net::UnixListener;
    let env = TestEnv::new();
    std::fs::create_dir_all(env.sock().parent().unwrap()).unwrap();
    let listener = UnixListener::bind(env.sock()).unwrap();
    let (entered, waiting) = mpsc::channel();
    let (release, blocked) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut status, _) = listener.accept().unwrap();
        let mut buf = [0; 128];
        let count = status.read(&mut buf).unwrap();
        assert!(String::from_utf8_lossy(&buf[..count]).contains("status"));
        entered.send(()).unwrap();
        let _ = blocked.recv_timeout(Duration::from_secs(5));
    });
    let mut watch = PtyWatch::new(&env, &["status", "-i", "0.25"], true);
    waiting.recv_timeout(Duration::from_secs(5)).unwrap();
    assert!(
        Command::new("kill")
            .args(["-INT", &watch.child.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    watch.finish(true);
    release.send(()).unwrap();
    server.join().unwrap();
}

#[test]
fn stopped_daemon_can_start_stop_and_restart_while_watching() {
    let env = TestEnv::new();
    let mut watch = PtyWatch::new(&env, &["status", "-i", "0.25"], true);
    watch.wait_for("daemon stopped");
    env.succeed(&["daemon", "--background"]);
    watch.wait_for("updated");
    assert!(watch.transcript.contains("running"));
    watch.transcript.clear();
    env.succeed(&["daemon", "--stop"]);
    watch.wait_for("daemon stopped");
    watch.transcript.clear();
    env.succeed(&["daemon", "--background"]);
    watch.wait_for("updated");
    watch.master.write_all(b"q").unwrap();
    watch.finish(true);
    assert!(env.gpg_log().is_empty());
}

#[test]
fn resizing_to_a_narrow_short_terminal_keeps_quit_responsive() {
    let env = TestEnv::new();
    let mut watch = PtyWatch::new(&env, &["status", "-i", "0.25"], true);
    watch.wait_for("daemon stopped");
    watch.transcript.clear();
    watch.resize(18, 8);
    watch.wait_for("q: Quit");
    let narrow = drawn_rows(&watch.transcript, 18, 8);
    assert_eq!(narrow.get(&8).unwrap(), "q: Quit (Esc / Ct");
    assert!(narrow.values().any(|line| line == "Last success: non"));
    watch.transcript.clear();
    watch.resize(100, 30);
    watch.wait_for("q: Quit (Esc / Ctrl+C)");
    let expanded = drawn_rows(&watch.transcript, 100, 30);
    assert!(
        expanded
            .values()
            .any(|line| line == "Last success: none yet")
    );
    assert!(
        expanded
            .values()
            .any(|line| line == "q: Quit (Esc / Ctrl+C)")
    );
    watch.master.write_all(b"q").unwrap();
    watch.finish(true);
}

fn reply_to_status(listener: &std::os::unix::net::UnixListener, reply: &str) {
    let (mut stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let request = keyhold::ipc::read_request(&stream).unwrap().unwrap();
    assert!(matches!(request, keyhold::ipc::Request::Status));
    writeln!(stream, "{reply}").unwrap();
}

#[test]
fn communication_errors_retry_and_recover_without_stale_error_rows() {
    let env = TestEnv::new();
    std::fs::create_dir_all(env.sock().parent().unwrap()).unwrap();
    let listener = std::os::unix::net::UnixListener::bind(env.sock()).unwrap();
    let (recover, recovered) = mpsc::channel();
    let server = thread::spawn(move || {
        let error = keyhold::ipc::Response::err(format!(
            "unreachable {}\x1b[2J",
            "x".repeat(300)
        ));
        reply_to_status(&listener, &serde_json::to_string(&error).unwrap());
        recovered.recv_timeout(Duration::from_secs(5)).unwrap();
        let status = serde_json::json!({"ok": true, "status": {
            "hold_on": false, "key": null, "key_source": "default",
            "interval_ms": 300000, "remaining_ms": null,
            "last_ping_ms": null, "next_ping_ms": null, "last_error": null,
            "fingerprint": null, "keygrip": null, "credential_mode": "none",
            "default_cache_ttl_ms": null, "max_cache_ttl_ms": null,
            "max_expires_at_ms": null
        }});
        reply_to_status(&listener, &status.to_string());
    });
    let mut watch = PtyWatch::new(&env, &["status", "-i", "0.25"], true);
    watch.wait_for("failed; retrying");
    assert!(watch.transcript.contains("Last success: none yet"));
    assert!(watch.transcript.contains("disconnected / unavailable"));
    assert!(!watch.transcript.contains("\x1b[2J"));
    watch.transcript.clear();
    recover.send(()).unwrap();
    watch.wait_for("updated");
    assert!(watch.transcript.contains("running"));
    assert!(!watch.transcript.contains("unreachable"));
    watch.master.write_all(b"q").unwrap();
    watch.finish(true);
    server.join().unwrap();
}

// Decode the rows actually drawn, including clears, without fixing cursor bytes.
fn drawn_rows(
    transcript: &str,
    width: u16,
    height: u16,
) -> std::collections::BTreeMap<u16, String> {
    let parts: Vec<_> = transcript.split("\x1b[").collect();
    let mut rows = std::collections::BTreeMap::new();
    for pair in parts.windows(2) {
        let Some(position) = pair[0].strip_suffix('H') else {
            continue;
        };
        let Some(text) = pair[1].strip_prefix("2K") else {
            continue;
        };
        let (row, column) = position.split_once(';').unwrap();
        let row: u16 = row.parse().unwrap();
        assert!(
            (1..=height).contains(&row),
            "row {row} outside height {height}"
        );
        assert_eq!(column, "1");
        assert!(text.len() < usize::from(width), "unclipped row: {text}");
        rows.insert(row, text.to_owned());
    }
    rows
}

#[test]
fn watch_exit_returns_prompt_to_the_first_reserved_row() {
    for (row, expected) in [(2, 2), (24, 13)] {
        let env = TestEnv::new();
        let mut watch =
            PtyWatch::at_row(&env, &["status", "-w"], true, row, None);
        watch.wait_for("daemon stopped");
        assert_eq!(watch.transcript.matches("\r\n").count(), 17);
        let heading = format!("\x1b[{expected};1H\x1b[2KKeyhold status");
        assert!(watch.transcript.contains(&heading), "{}", watch.transcript);
        watch.master.write_all(b"q").unwrap();
        watch.finish(true);
        assert!(watch.transcript.ends_with(&format!("\x1b[{expected};1H")));
    }
}

#[test]
fn configured_watch_runs_on_an_interactive_terminal() {
    let env = TestEnv::new();
    let dir = env.config.path().join("keyhold");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("config.toml"),
        "interval = \"bad\"\nstatus.watch = true",
    )
    .unwrap();
    let mut watch = PtyWatch::new(&env, &["status"], true);
    watch.wait_for("daemon stopped");
    watch.master.write_all(b"q").unwrap();
    watch.finish(true);
}

#[test]
fn unchanged_resize_does_not_block_on_cursor_queries() {
    let env = TestEnv::new();
    let mut watch = PtyWatch::new(&env, &["status", "-i", "60"], true);
    watch.wait_for("daemon stopped");
    watch.respond.store(false, Ordering::Relaxed);
    watch.resize(100, 30);
    watch.master.write_all(b"q").unwrap();
    watch.finish(true);
    assert_eq!(watch.transcript.matches("\x1b[6n").count(), 1);
}

#[test]
fn failed_resize_cursor_query_restores_terminal() {
    let env = TestEnv::new();
    let mut watch = PtyWatch::new(&env, &["status", "-i", "60"], true);
    watch.wait_for("daemon stopped");
    watch.respond.store(false, Ordering::Relaxed);
    watch.resize(18, 8);
    watch.wait_for("error:");
    watch.finish(false);
}

#[test]
fn watch_observes_external_gpg_cache_changes() {
    let env = TestEnv::new();
    env.rich_gpg();
    env.set_key_cached(true);
    env.succeed(&["on"]);
    env.succeed(&["off"]);
    let mut watch = PtyWatch::new(&env, &["status", "-i", "0.25"], true);
    watch.wait_for("Key state    unlocked");
    watch.transcript.clear();
    env.set_key_cached(false);
    watch.wait_for("Key state    locked");
    watch.transcript.clear();
    env.set_key_cached(true);
    watch.wait_for("Key state    unlocked");
    watch.master.write_all(b"q").unwrap();
    watch.finish(true);
}

#[test]
fn redirected_stdin_or_stdout_keeps_configured_watch_one_shot() {
    for redirect_stdin in [true, false] {
        let env = TestEnv::new();
        let dir = env.config.path().join("keyhold");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("config.toml"), "status.watch = true")
            .unwrap();
        for args in [
            ["status"].as_slice(),
            &["status", "--no-watch"],
            &["status", "-w"],
            &["status", "-i", "0.5"],
        ] {
            let explicit = args.contains(&"-w") || args.contains(&"-i");
            let mut watch =
                PtyWatch::at_row(&env, args, true, 24, Some(redirect_stdin));
            watch.finish(!explicit);
            if explicit {
                assert!(watch.transcript.contains("requires interactive"));
            } else {
                if let Some(mut output) = watch.child.stdout.take() {
                    output.read_to_string(&mut watch.transcript).unwrap();
                }
                assert!(watch.transcript.contains("Daemon       stopped"));
                assert!(!watch.transcript.contains("\x1b[6n"));
            }
        }
    }
}
