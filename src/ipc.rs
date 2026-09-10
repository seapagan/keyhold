//! One-request/one-response JSON protocol, newline-framed, over the daemon's
//! per-user Unix socket.
//!
//! Deliberately small: no framework, no persistent connections, no async
//! runtime. Each client connects, sends one JSON object terminated by a
//! newline, reads one JSON response, and disconnects.

use std::{
    io::{self, BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    time::Duration,
};

use serde::{Deserialize, Serialize};

use crate::{
    daemon,
    error::{Error, Result},
    state::StatusData,
};

/// Largest request line accepted (defensive; real requests are tiny).
const MAX_REQUEST: usize = 64 * 1024;
/// Client-side I/O timeout.
const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// A request sent by a `keyhold` client to the daemon.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Request {
    /// Liveness probe.
    Ping,
    /// Enable or replace the hold.
    On {
        /// Key selector, or `None` for GPG's default key.
        key: Option<String>,
        /// Ping interval in milliseconds (must be positive).
        interval_ms: u64,
        /// Hold duration in milliseconds; `None` for an indefinite hold.
        hold_ms: Option<u64>,
    },
    /// Disable the hold.
    Off,
    /// Request a status snapshot.
    Status,
    /// Ask the daemon to exit.
    Shutdown,
}

/// A daemon response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// Whether the request succeeded.
    pub ok: bool,
    /// Failure reason when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Status snapshot (only for [`Request::Status`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusData>,
}

impl Response {
    /// Positive acknowledgement.
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
            status: None,
        }
    }

    /// Negative acknowledgement with a reason.
    pub fn err(reason: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(reason.into()),
            status: None,
        }
    }

    /// Positive acknowledgement carrying a status snapshot.
    pub fn with_status(status: StatusData) -> Self {
        Self {
            ok: true,
            error: None,
            status: Some(status),
        }
    }
}

/// Send one request to the running daemon and await its response.
pub fn request(req: &Request) -> Result<Response> {
    let stream = daemon::connect()?;
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    let payload =
        serde_json::to_vec(req).map_err(|e| Error::Ipc(e.to_string()))?;
    let mut writer = &stream;
    writer.write_all(&payload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;

    let mut line = String::new();
    let read = BufReader::new(&stream).read_line(&mut line)?;
    if read == 0 {
        return Err(Error::Ipc(
            "daemon closed the connection without a response".into(),
        ));
    }
    serde_json::from_str(line.trim_end())
        .map_err(|e| Error::Ipc(format!("malformed daemon response: {e}")))
}

/// Read one newline-framed request. `Ok(None)` means the client disconnected.
pub fn read_request(stream: &UnixStream) -> Result<Option<Request>> {
    let mut reader = BufReader::new(stream);
    let mut buf = Vec::new();
    let read = reader.read_until(b'\n', &mut buf)?;
    if read == 0 {
        return Ok(None);
    }
    if buf.len() > MAX_REQUEST {
        return Err(Error::Ipc("request too large".into()));
    }
    serde_json::from_slice(trim_trailing_whitespace(&buf))
        .map_err(|e| Error::Ipc(format!("malformed request: {e}")))
        .map(Some)
}

/// Write one newline-framed response.
pub fn write_response(stream: &UnixStream, response: &Response) -> Result<()> {
    let payload =
        serde_json::to_vec(response).map_err(|e| Error::Ipc(e.to_string()))?;
    let mut writer = io::BufWriter::new(stream);
    writer.write_all(&payload)?;
    writer.write_all(b"\n")?;
    writer.flush()?;
    Ok(())
}

fn trim_trailing_whitespace(mut buf: &[u8]) -> &[u8] {
    while buf.last().is_some_and(u8::is_ascii_whitespace) {
        buf = &buf[..buf.len() - 1];
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_roundtrip_through_json() {
        let req = Request::On {
            key: Some("ABCD".into()),
            interval_ms: 300_000,
            hold_ms: Some(7_200_000),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"cmd\":\"on\""), "{json}");
        let back: Request = serde_json::from_str(&json).unwrap();
        assert!(matches!(
            back,
            Request::On {
                key: Some(_),
                interval_ms: 300_000,
                hold_ms: Some(_)
            }
        ));

        let json = serde_json::to_string(&Request::Off).unwrap();
        assert_eq!(json, "{\"cmd\":\"off\"}");
    }

    #[test]
    fn response_omits_absent_fields() {
        let json = serde_json::to_string(&Response::ok()).unwrap();
        assert_eq!(json, "{\"ok\":true}");
        let back: Response = serde_json::from_str(&json).unwrap();
        assert!(back.ok && back.error.is_none() && back.status.is_none());
    }
}
