//! Real PTY input/cleanup and status transitions against isolated fixtures.

mod common;

use std::{
    fs::File,
    io::{Read, Write},
    process::{Child, Command},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
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
}

impl PtyWatch {
    fn new(env: &TestEnv, args: &[&str], respond: bool) -> Self {
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
        let original = termios::tcgetattr(&slave).unwrap();
        let child = env
            .keyhold(args)
            .env("TERM", "xterm-256color")
            .env("NO_COLOR", "1")
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap())
            .spawn()
            .unwrap();
        let master = File::from(master);
        let cursor_row = Arc::new(AtomicU16::new(24));
        let output = read_pty(&master, cursor_row.clone(), respond);
        Self {
            master,
            slave,
            original,
            child,
            output,
            transcript: String::new(),
            cursor_row,
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
}

fn read_pty(
    master: &File,
    reply_row: Arc<AtomicU16>,
    respond: bool,
) -> mpsc::Receiver<Vec<u8>> {
    let mut reader = master.try_clone().unwrap();
    let mut reply = master.try_clone().unwrap();
    let (send, output) = mpsc::channel();
    thread::spawn(move || {
        let mut buf = [0; 4096];
        let mut pending = Vec::new();
        while let Ok(count) = reader.read(&mut buf) {
            if count == 0 {
                break;
            }
            pending.extend_from_slice(&buf[..count]);
            if respond && pending.windows(4).any(|w| w == b"\x1b[6n") {
                let row = reply_row.swap(30, Ordering::Relaxed);
                let _ = write!(reply, "\x1b[{row};1R");
                pending.clear();
            }
            if send.send(buf[..count].to_vec()).is_err() {
                break;
            }
        }
    });
    output
}

impl Drop for PtyWatch {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
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
        let (probe, _) = listener.accept().unwrap();
        drop(probe);
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
    assert!(watch.transcript.contains("\x1b[8;1H"));
    watch.transcript.clear();
    watch.resize(100, 30);
    watch.wait_for("Last success: none yet");
    watch.master.write_all(b"q").unwrap();
    watch.finish(true);
}

fn reply_to_status(listener: &std::os::unix::net::UnixListener, reply: &str) {
    // Existing status first opens a liveness connection, then sends Status.
    let (probe, _) = listener.accept().unwrap();
    drop(probe);
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
    assert!(!env.gpg_log().contains("--detach-sign"));
    assert!(env.ca_log().is_empty());
}
