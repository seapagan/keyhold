//! GPG invocation layer.
//!
//! The keepalive operation is a detached signature of empty input written to
//! `/dev/null`: a real private-key operation with no lasting effect and no
//! artefacts. Two ping modes exist:
//!
//! * [`PingMode::Foreground`] — normal pinentry behaviour, used by
//!   `keyhold on` so the user can unlock the key if it is not cached yet.
//! * [`PingMode::Background`] — adds `--pinentry-mode cancel`, used by the
//!   daemon. If the cache has expired, gpg fails promptly
//!   ("Operation cancelled") instead of opening an unattended pinentry.
//!
//! Ordinary mode never uses loopback passphrase handling and never sees,
//! stores or transmits the passphrase: GnuPG and pinentry remain entirely
//! responsible for unlocking the key. The explicit opt-in session-credential
//! mode additionally offers [`Gpg::use_key_with_passphrase`], which feeds a
//! passphrase through the child's stdin only (`--passphrase-fd 0`); it is
//! never placed in argv, the environment or any file.
//!
//! All identity information (which key actually signed, its keygrip, agent
//! cache state, effective cache TTLs) comes from machine-readable output:
//! `--status-fd` records, `--with-colons --with-keygrip` listings,
//! `gpgconf --list-options` and `gpg-connect-agent` responses. Free-form
//! localized stderr is used for messages only, never for identity.

use std::{
    io::Read,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{Duration, Instant},
};

use crate::error::{Error, Result};

/// Environment variable overriding the `gpg` executable path.
///
/// Intended for the test suite and staged debugging; it does not change the
/// arguments keyhold passes to gpg.
pub const GPG_ENV: &str = "KEYHOLD_GPG";

/// Environment variable overriding the `gpgconf` executable path.
pub const GPGCONF_ENV: &str = "KEYHOLD_GPGCONF";

/// Environment variable overriding the `gpg-connect-agent` executable path.
pub const CONNECT_AGENT_ENV: &str = "KEYHOLD_GPG_CONNECT_AGENT";

/// libgpg-error packs the error code into the low 15 bits of the value
/// printed in Assuan `ERR <code>` replies and `--status-fd` `FAILURE`
/// records; the upper bits carry the error source.
const GPG_ERR_CODE_MASK: u64 = 0x7FFF;
/// `GPG_ERR_NOT_FOUND` (27): the agent's answer for an unknown keygrip.
const GPG_ERR_NOT_FOUND: u64 = 27;
/// `GPG_ERR_BAD_PASSPHRASE` (11): gpg rejected the supplied passphrase.
const GPG_ERR_BAD_PASSPHRASE: u64 = 11;
/// `GPG_ERR_CANCELED` (99): pinentry was cancelled (or suppressed via
/// `--pinentry-mode cancel`), i.e. the key was not unlocked.
const GPG_ERR_CANCELED: u64 = 99;

/// Execution bound for unattended operations: the stored-mode loopback
/// sign (renewal and recovery), `gpg-connect-agent` commands, secret
/// key listings and `gpgconf` queries. None of these ever interact
/// with a user, so a wedged child is killed and reported instead of
/// hanging the scheduler or blocking daemon shutdown forever. Tests
/// inject a shorter bound via [`Gpg::with_unattended_timeout`].
const UNATTENDED_TIMEOUT: Duration = Duration::from_secs(30);

/// How long a background ping may run before it is killed.
const BACKGROUND_TIMEOUT: Duration = Duration::from_secs(30);

/// Pinentry policy for a keepalive ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingMode {
    /// Normal pinentry behaviour; may prompt the user.
    Foreground,
    /// Never prompt: a locked key must produce a prompt-free error.
    Background,
}

/// The exact key the hold keeps cached: the fingerprint of the key that
/// actually signs (a signing subkey, not blindly the primary) plus its
/// agent keygrip, which identifies the passphrase cache entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningTarget {
    /// Fingerprint of the signing key (primary or subkey).
    pub fingerprint: String,
    /// Agent keygrip of the signing key (`None` only when gpg could not be
    /// consulted for it; stored-credential mode requires one).
    pub keygrip: Option<String>,
}

/// How the agent protects a key's passphrase entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyProtection {
    /// Passphrase protected: a cache entry exists and can expire.
    Passphrase,
    /// Clear: the key is stored without a passphrase (no cache involved).
    Clear,
    /// The agent reported no usable protection information.
    Unknown,
}

/// Snapshot of one keygrip's cache/protection state in the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AgentKeyState {
    /// Whether a passphrase is currently cached (unlocked).
    pub cached: bool,
    /// How the key is protected.
    pub protection: KeyProtection,
}

/// The parsed outcome of one `gpg-connect-agent` command exchange.
///
/// GnuPG exits 0 even when the agent rejects the command with an
/// Assuan `ERR` response (verified against GnuPG 2.4), so the terminal
/// response line — not the child's exit status — is the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentReply {
    /// Terminal `OK [info]`: the agent accepted the command. Carries
    /// every non-empty response line, information lines included.
    Ok(Vec<String>),
    /// Terminal `ERR <code> [<text>]`: the agent rejected the command.
    Err {
        /// The full numeric error code (a libgpg-error value).
        code: u64,
        /// The human-readable remainder of the line, when present.
        text: String,
    },
    /// No terminal line at all: an empty or malformed response.
    Malformed,
}

impl AgentReply {
    /// Convert into a result for commands whose only success criterion
    /// is the terminal `OK`: `ERR` and malformed replies become
    /// [`Error::AgentCommand`] carrying the command and the agent's
    /// machine-readable answer (never secret material).
    fn into_result(self, command: &str) -> Result<Vec<String>> {
        match self {
            AgentReply::Ok(lines) => Ok(lines),
            AgentReply::Err { code, text } => Err(Error::AgentCommand(
                format!("{command}: agent returned ERR {code} {text}"),
            )),
            AgentReply::Malformed => Err(Error::AgentCommand(format!(
                "{command}: no terminal OK/ERR line in the agent's reply"
            ))),
        }
    }

    /// Whether this is an `ERR` reply carrying the given libgpg-error
    /// code (masked to its low 15 bits).
    fn has_code(&self, wanted: u64) -> bool {
        matches!(
            self,
            AgentReply::Err { code, .. }
                if code & GPG_ERR_CODE_MASK == wanted
        )
    }
}

/// GnuPG's effective cache TTL policy for the agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CachePolicy {
    /// Idle timeout each key use refreshes.
    pub default_ttl: Duration,
    /// Absolute ceiling GnuPG enforces on a cache entry.
    pub max_ttl: Duration,
}

/// Result of one real key use: the exact key that signed, if gpg's
/// machine-readable status could be mapped, and whether a fresh foreground
/// unlock (pinentry) was required.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpgUse {
    /// The resolved signing target, when identifiable.
    pub target: Option<SigningTarget>,
    /// Whether gpg launched pinentry during this use (a fresh unlock).
    /// `None` means gpg produced no machine-readable status, so the
    /// question cannot be answered.
    pub pinentry_launched: Option<bool>,
}

/// Machine-readable status records distilled from one gpg `--status-fd`
/// stream.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GpgStatus {
    /// Fingerprint of the key that actually signed (`SIG_CREATED`).
    pub sig_created: Option<String>,
    /// Whether pinentry was launched (`PINENTRY_LAUNCHED`).
    pub pinentry_launched: bool,
    /// Primary fingerprints gpg considered (`KEY_CONSIDERED`), in order.
    pub key_considered: Vec<String>,
    /// Whether any `[GNUPG:]` record was seen at all. Without one there
    /// is no evidence either way about pinentry, so callers must treat
    /// `pinentry_launched` as unknown rather than false.
    pub saw_status: bool,
    /// The numeric error code of the last `FAILURE` record, when gpg
    /// emitted one. Machine-readable failure classification (the low
    /// 15 bits are the libgpg-error code); the location token is
    /// dropped. Localized stderr is never used for this.
    pub failure_code: Option<u64>,
}

/// One `sec`/`ssb` record from a colon-separated secret-key listing,
/// with its trailing `fpr` and `grp` records attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKeyRecord {
    /// Whether this is the primary key (`sec`) or a subkey (`ssb`).
    pub primary: bool,
    /// Long key id (16 hex chars).
    pub keyid: String,
    /// Full fingerprint (40 hex chars).
    pub fingerprint: String,
    /// Agent keygrip, when the listing provided one.
    pub keygrip: Option<String>,
    /// Creation time as a Unix timestamp, when present.
    pub created: Option<u64>,
    /// Capability string (`scSC`, `s`, `e`, ...).
    pub capabilities: String,
    /// Whether the record is usable (not revoked/expired/disabled/invalid).
    pub usable: bool,
}

impl SecretKeyRecord {
    /// Whether this key can create signatures.
    pub fn can_sign(&self) -> bool {
        self.capabilities.contains('s')
    }
}

/// A primary key and its subkeys, as one unit from the listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlock {
    /// The primary (`sec`) record.
    pub primary: SecretKeyRecord,
    /// The subkey (`ssb`) records that followed it.
    pub subkeys: Vec<SecretKeyRecord>,
}

/// A located `gpg` executable plus the companion tools keyhold shells out
/// to for cache management.
#[derive(Debug, Clone)]
pub struct Gpg {
    path: PathBuf,
    gpgconf: Option<PathBuf>,
    connect_agent: Option<PathBuf>,
    /// Execution bound for unattended child operations.
    unattended_timeout: Duration,
}

impl Gpg {
    /// Locate `gpg` plus companion tools: the `KEYHOLD_*` overrides if
    /// set (resolved to absolute paths, since the daemon runs with cwd
    /// `/`), otherwise the first executables on `$PATH`.
    pub fn detect() -> Result<Self> {
        let path = detect_tool(GPG_ENV, "gpg", true)?.ok_or_else(|| {
            Error::GpgNotFound("gpg (not found on $PATH)".into())
        })?;
        let gpgconf = detect_tool(GPGCONF_ENV, "gpgconf", false)?;
        let connect_agent =
            detect_tool(CONNECT_AGENT_ENV, "gpg-connect-agent", false)?;
        Ok(Self {
            path,
            gpgconf,
            connect_agent,
            unattended_timeout: UNATTENDED_TIMEOUT,
        })
    }

    /// Build an instance from explicit tool paths (test injection point).
    pub fn with_tools(
        path: PathBuf,
        gpgconf: Option<PathBuf>,
        connect_agent: Option<PathBuf>,
    ) -> Self {
        Self {
            path,
            gpgconf,
            connect_agent,
            unattended_timeout: UNATTENDED_TIMEOUT,
        }
    }

    /// Return a copy with a different execution bound for unattended
    /// operations (test injection point; production always uses the
    /// `UNATTENDED_TIMEOUT` default).
    pub fn with_unattended_timeout(mut self, timeout: Duration) -> Self {
        self.unattended_timeout = timeout;
        self
    }

    /// Perform one keepalive key use: detached-sign empty input, discard
    /// the signature, and report what gpg's status stream says about the
    /// key that signed.
    ///
    /// With `key` unset, GPG's normal default-key selection applies.
    pub fn use_key(
        &self,
        key: Option<&str>,
        mode: PingMode,
    ) -> Result<GpgUse> {
        let mut cmd = self.sign_command(key, mode);
        let output = match mode {
            PingMode::Foreground => run_blocking(&mut cmd),
            PingMode::Background => run_with_timeout(
                &mut cmd,
                BACKGROUND_TIMEOUT,
                "gpg keepalive sign",
            ),
        }?;
        if !output.success {
            return Err(Error::GpgFailed(message(
                &output.stderr,
                output.code,
            )));
        }
        let status = parse_status(&String::from_utf8_lossy(&output.stdout));
        let target = status
            .sig_created
            .as_deref()
            .and_then(|fpr| self.target_for_fingerprint(fpr).ok().flatten());
        let pinentry_launched =
            status.saw_status.then_some(status.pinentry_launched);
        Ok(GpgUse {
            target,
            pinentry_launched,
        })
    }

    /// Resolve the exact signing target for `key` without any interactive
    /// prompt, whether the key is currently cached or locked.
    ///
    /// A cached key is probed by a successful harmless sign (`SIG_CREATED`
    /// names the signing key). A locked key fails with `Operation
    /// cancelled`; the `KEY_CONSIDERED` record names the primary key and
    /// the secret-key listing supplies the signing key/keygrip GPG's
    /// default selection would use (the newest usable signing-capable key
    /// of that keyblock, honouring a selector that names a specific
    /// subkey).
    pub fn probe_target(&self, key: Option<&str>) -> Result<SigningTarget> {
        let mut cmd = self.sign_command(key, PingMode::Background);
        let output = run_with_timeout(
            &mut cmd,
            BACKGROUND_TIMEOUT,
            "gpg keepalive sign",
        )?;
        let status = parse_status(&String::from_utf8_lossy(&output.stdout));
        if output.success
            && let Some(fpr) = status.sig_created.as_deref()
        {
            return self.target_for_fingerprint(fpr)?.ok_or_else(|| {
                Error::GpgTarget(
                    "gpg signed but the signing key could not be \
                     resolved to a fingerprint/keygrip"
                        .into(),
                )
            });
        }
        // A locked key (pinentry suppressed by `--pinentry-mode cancel`)
        // is classified from the machine-readable FAILURE code, never
        // from localized stderr (verified against GnuPG 2.4: cancelled
        // sign → `FAILURE sign 67108963` = GPG_ERR_CANCELED).
        let locked = status
            .failure_code
            .is_some_and(|code| code & GPG_ERR_CODE_MASK == GPG_ERR_CANCELED);
        let Some(primary_fpr) = status.key_considered.last() else {
            return Err(Error::GpgTarget(format!(
                "gpg did not identify a signing key: {}",
                message(&output.stderr, output.code)
            )));
        };
        if !locked {
            return Err(Error::GpgFailed(message(
                &output.stderr,
                output.code,
            )));
        }
        let blocks = self.list_secret_keys(key)?;
        let block = blocks
            .iter()
            .find(|b| &b.primary.fingerprint == primary_fpr)
            .ok_or_else(|| {
                Error::GpgTarget(format!(
                    "key considered by gpg ({primary_fpr}) was not found \
                     in the secret-key listing"
                ))
            })?;
        let record = default_signing_key(block, key).ok_or_else(|| {
            Error::GpgTarget(format!(
                "no usable signing key found for {primary_fpr}"
            ))
        })?;
        record.keygrip.is_some().then_some(()).ok_or_else(|| {
            Error::GpgTarget(format!(
                "no keygrip reported for signing key {}",
                record.fingerprint
            ))
        })?;
        Ok(SigningTarget {
            fingerprint: record.fingerprint.clone(),
            keygrip: record.keygrip.clone(),
        })
    }

    /// List secret keys (optionally restricted to a selector) as parsed
    /// key blocks with fingerprints and keygrips.
    pub fn list_secret_keys(
        &self,
        key: Option<&str>,
    ) -> Result<Vec<KeyBlock>> {
        let mut cmd = Command::new(&self.path);
        cmd.args([
            "--batch",
            "--with-colons",
            "--with-keygrip",
            "--fingerprint",
            "--fingerprint",
            "--list-secret-keys",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
        if let Some(key) = key {
            cmd.arg(key);
        }
        let output = run_with_timeout(
            &mut cmd,
            self.unattended_timeout,
            "gpg --list-secret-keys",
        )?;
        if !output.success {
            return Err(Error::GpgFailed(message(
                &output.stderr,
                output.code,
            )));
        }
        Ok(parse_key_blocks(&String::from_utf8_lossy(&output.stdout)))
    }

    /// Read GnuPG's effective `default-cache-ttl` and `max-cache-ttl` via
    /// `gpgconf --list-options gpg-agent`.
    ///
    /// The explicitly configured value wins over the advertised default.
    /// Missing, malformed or zero values are rejected.
    pub fn cache_policy(&self) -> Result<CachePolicy> {
        let path = self.gpgconf.clone().ok_or_else(|| {
            Error::GpgToolNotFound("gpgconf (not located)".into())
        })?;
        let mut cmd = Command::new(&path);
        cmd.args(["--list-options", "gpg-agent"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output =
            run_with_timeout(&mut cmd, self.unattended_timeout, "gpgconf")?;
        if !output.success {
            return Err(Error::CachePolicy(message(
                &output.stderr,
                output.code,
            )));
        }
        parse_cache_policy(&String::from_utf8_lossy(&output.stdout))
    }

    /// Query the agent's cache/protection state for exactly one keygrip.
    ///
    /// An unknown keygrip is a known answer, not a failure: the agent
    /// rejects `KEYINFO` with `ERR ... Not found` (GPG_ERR_NOT_FOUND)
    /// and the key is simply not cached. Any other rejection, or a
    /// response without a usable `S KEYINFO` record, is an error — a
    /// state is never fabricated.
    pub fn key_state(&self, keygrip: &str) -> Result<AgentKeyState> {
        let reply = self.connect_agent(&format!("KEYINFO {keygrip}"))?;
        if reply.has_code(GPG_ERR_NOT_FOUND) {
            return Ok(AgentKeyState {
                cached: false,
                protection: KeyProtection::Unknown,
            });
        }
        let lines = reply.into_result("KEYINFO")?;
        parse_keyinfo(&lines.join("\n")).ok_or_else(|| {
            Error::AgentCommand(
                "KEYINFO: the agent accepted the command but sent no \
                 usable KEYINFO record"
                    .into(),
            )
        })
    }

    /// Clear only the given keygrip's normal passphrase cache entry
    /// (`CLEAR_PASSPHRASE --mode=normal`). Succeeds only when the agent
    /// accepted the clear with a terminal `OK` (clearing an uncached
    /// keygrip is documented success). The agent is never restarted and
    /// no other key is affected.
    pub fn clear_passphrase(&self, keygrip: &str) -> Result<()> {
        self.connect_agent(&format!(
            "CLEAR_PASSPHRASE --mode=normal {keygrip}"
        ))?
        .into_result("CLEAR_PASSPHRASE")?;
        Ok(())
    }

    /// Unlock and perform the harmless sign with exactly `target`, feeding
    /// the passphrase through the child's stdin (`--passphrase-fd 0`,
    /// loopback pinentry). The caller must already have cleared the
    /// target's cache entry when it needs a deterministic cache epoch:
    /// a hot cache entry would satisfy the sign without validating.
    pub fn use_key_with_passphrase(
        &self,
        target: &SigningTarget,
        passphrase: &[u8],
    ) -> Result<()> {
        if passphrase.is_empty() {
            return Err(Error::Message(
                "the passphrase is empty; gpg must validate it \
                 (an empty passphrase is only meaningful for an \
                 unprotected key, which needs no stored credential)"
                    .into(),
            ));
        }
        if passphrase.contains(&b'\n') || passphrase.contains(&b'\r') {
            return Err(Error::Message(
                "the passphrase contains a newline; keyhold feeds it to \
                 gpg as a single line via --passphrase-fd 0"
                    .into(),
            ));
        }
        let mut cmd = self.sign_command(None, PingMode::Foreground);
        cmd.arg("--local-user")
            .arg(format!("{}!", target.fingerprint));
        cmd.arg("--pinentry-mode").arg("loopback");
        cmd.arg("--passphrase-fd").arg("0");
        cmd.stdin(Stdio::piped());
        let mut child = cmd.spawn().map_err(Error::GpgSpawn)?;
        {
            use std::io::Write;
            let mut stdin = child.stdin.take().expect("piped stdin");
            // A single trailing newline terminates the line; it is not
            // part of the passphrase. A write error here is ignored:
            // gpg may have exited early (for example after rejecting
            // the passphrase) before reading all input, and the wait
            // below reports the real error.
            let _ = stdin.write_all(passphrase);
            let _ = stdin.write_all(b"\n");
        }
        // Loopback pinentry never prompts a user, so this is an
        // unattended operation even in the activation flow: bound it
        // so a wedged child cannot hang the caller.
        let output = wait_with_timeout(
            &mut child,
            self.unattended_timeout,
            "gpg loopback sign",
        )?;
        if output.success {
            return Ok(());
        }
        // Distinguish a rejected passphrase from an unrelated signing
        // failure via the machine-readable FAILURE code (verified
        // against GnuPG 2.4: a rejected loopback passphrase → `FAILURE
        // sign 67108875` = GPG_ERR_BAD_PASSPHRASE), never localized
        // stderr. Neither path includes secret material.
        let status = parse_status(&String::from_utf8_lossy(&output.stdout));
        if status.failure_code.is_some_and(|code| {
            code & GPG_ERR_CODE_MASK == GPG_ERR_BAD_PASSPHRASE
        }) {
            return Err(Error::BadPassphrase);
        }
        Err(Error::GpgFailed(message(&output.stderr, output.code)))
    }

    /// Run one `gpg-connect-agent` command (with `/bye`) and parse its
    /// response into an [`AgentReply`].
    ///
    /// A non-zero exit status (for example an unreachable agent) is an
    /// error, but the exit status alone can never indicate success:
    /// GnuPG exits 0 even when the agent rejects the command with an
    /// Assuan `ERR` line (verified against GnuPG 2.4: an unknown
    /// command produces `ERR 67109139 Unknown IPC command` with exit
    /// status 0). The parsed terminal line therefore decides.
    fn connect_agent(&self, command: &str) -> Result<AgentReply> {
        let path = self.connect_agent.clone().ok_or_else(|| {
            Error::GpgToolNotFound("gpg-connect-agent (not located)".into())
        })?;
        let mut cmd = Command::new(&path);
        cmd.arg(command)
            .arg("/bye")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let output = run_with_timeout(
            &mut cmd,
            self.unattended_timeout,
            "gpg-connect-agent",
        )?;
        if !output.success {
            return Err(Error::GpgFailed(message(
                &output.stderr,
                output.code,
            )));
        }
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        let word = command.split_whitespace().next().unwrap_or(command);
        match parse_agent_reply(&text) {
            // An unusable reply must never pass as success.
            AgentReply::Malformed => {
                let shown = text
                    .lines()
                    .map(str::trim)
                    .find(|l| !l.is_empty())
                    .map(|l| l.chars().take(120).collect::<String>())
                    .unwrap_or_else(|| "(no output)".into());
                Err(Error::AgentCommand(format!(
                    "{word}: malformed agent response ({shown})"
                )))
            }
            reply => Ok(reply),
        }
    }

    /// The harmless detached-sign command, stdout reserved for
    /// `--status-fd=1` (the signature itself goes to `/dev/null`).
    fn sign_command(&self, key: Option<&str>, mode: PingMode) -> Command {
        let mut cmd = Command::new(&self.path);
        cmd.arg("--batch")
            .arg("--yes")
            .arg("--detach-sign")
            .arg("--output")
            .arg("/dev/null")
            .arg("--status-fd")
            .arg("1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if mode == PingMode::Background {
            // Prompt-free failure when the key is no longer cached.
            cmd.arg("--pinentry-mode").arg("cancel");
        }
        if let Some(key) = key {
            cmd.arg("--local-user").arg(key);
        }
        cmd
    }

    /// Map a signing fingerprint to a full target (fingerprint + keygrip)
    /// via the secret-key listing. `Ok(None)` means the listing does not
    /// know the fingerprint.
    fn target_for_fingerprint(
        &self,
        fingerprint: &str,
    ) -> Result<Option<SigningTarget>> {
        let blocks = self.list_secret_keys(None)?;
        Ok(
            find_by_id(&blocks, fingerprint).map(|record| SigningTarget {
                fingerprint: record.fingerprint.clone(),
                keygrip: record.keygrip.clone(),
            }),
        )
    }
}

/// Outcome of one gpg invocation.
struct RunOutput {
    success: bool,
    code: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_blocking(cmd: &mut Command) -> Result<RunOutput> {
    let output = cmd.output().map_err(Error::GpgSpawn)?;
    Ok(RunOutput {
        success: output.status.success(),
        code: output.status.code(),
        stdout: output.stdout,
        stderr: output.stderr,
    })
}

fn run_with_timeout(
    cmd: &mut Command,
    timeout: Duration,
    what: &str,
) -> Result<RunOutput> {
    let mut child = cmd.spawn().map_err(Error::GpgSpawn)?;
    wait_with_timeout(&mut child, timeout, what)
}

/// Wait for an already-spawned child, killing and reaping it if the
/// deadline passes first. `what` names the operation in the timeout
/// error; it never includes secret material.
fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Duration,
    what: &str,
) -> Result<RunOutput> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait().map_err(Error::GpgSpawn)? {
            Some(status) => {
                let stdout =
                    child.stdout.take().map(drain).unwrap_or_default();
                let stderr =
                    child.stderr.take().map(drain).unwrap_or_default();
                return Ok(RunOutput {
                    success: status.success(),
                    code: status.code(),
                    stdout,
                    stderr,
                });
            }
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(Error::GpgTimeout(format!(
                    "{what} (after {timeout:?})"
                )));
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }
}

fn drain<R: Read>(mut reader: R) -> Vec<u8> {
    let mut buf = Vec::new();
    let _ = reader.read_to_end(&mut buf);
    buf
}

/// Distil gpg stderr (last non-empty line) into a short human-readable message.
fn message(stderr: &[u8], code: Option<i32>) -> String {
    let text = String::from_utf8_lossy(stderr);
    let line = text
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("unknown gpg error");
    let suffix = code
        .map(|c| format!(" (exit status {c})"))
        .unwrap_or_default();
    format!("{}{}", line.chars().take(200).collect::<String>(), suffix)
}

/// True for a hexadecimal key id / fingerprint string.
fn is_hex_id(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Parse a gpg `--status-fd` stream into the records keyhold needs.
pub fn parse_status(text: &str) -> GpgStatus {
    let mut status = GpgStatus::default();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("[GNUPG:] ") else {
            continue;
        };
        status.saw_status = true;
        let mut tokens = rest.split_whitespace();
        let Some(keyword) = tokens.next() else {
            continue;
        };
        match keyword {
            "SIG_CREATED" => {
                // fingerprint).
                if let Some(fpr) = tokens.last()
                    && fpr.len() == 40
                    && is_hex_id(fpr)
                {
                    status.sig_created = Some(fpr.to_ascii_uppercase());
                }
            }
            "PINENTRY_LAUNCHED" => status.pinentry_launched = true,
            "FAILURE" => {
                // `FAILURE <location> <error_code>`; the code is the
                // last token and may carry a `_SYMBOL` suffix. Only
                // the numeric prefix classifies the failure.
                if let Some(code) = tokens
                    .last()
                    .and_then(|t| t.split('_').next())
                    .and_then(|c| c.parse::<u64>().ok())
                {
                    status.failure_code = Some(code);
                }
            }
            "KEY_CONSIDERED" => {
                if let Some(fpr) = tokens.next()
                    && fpr.len() == 40
                    && is_hex_id(fpr)
                    && !status.key_considered.iter().any(|k| k == fpr)
                {
                    status.key_considered.push(fpr.to_ascii_uppercase());
                }
            }
            _ => {}
        }
    }
    status
}

/// Parse a `--with-colons --with-keygrip --list-secret-keys` listing into
/// key blocks. `fpr:`/`grp:` records attach to the preceding key record.
pub fn parse_key_blocks(text: &str) -> Vec<KeyBlock> {
    let mut blocks: Vec<KeyBlock> = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        // Attach to the record most recently seen: the primary while no
        // subkey has followed, otherwise the newest subkey.
        fn last(b: &mut KeyBlock) -> &mut SecretKeyRecord {
            b.subkeys.last_mut().unwrap_or(&mut b.primary)
        }
        match fields.first().copied().unwrap_or_default() {
            "sec" => {
                blocks.push(KeyBlock {
                    primary: key_record(&fields, true),
                    subkeys: Vec::new(),
                });
            }
            "ssb" => {
                if let Some(block) = blocks.last_mut() {
                    block.subkeys.push(key_record(&fields, false));
                }
            }
            "fpr" => {
                if let Some(fpr) = field_id(fields.get(9))
                    && let Some(block) = blocks.last_mut()
                {
                    last(block).fingerprint = fpr;
                }
            }
            "grp" => {
                if let Some(grip) = field_id(fields.get(9))
                    && let Some(block) = blocks.last_mut()
                {
                    last(block).keygrip = Some(grip);
                }
            }
            _ => {}
        }
    }
    blocks
}

/// One `sec`/`ssb` row of the colon listing. `fields` is the split line;
/// `primary` distinguishes `sec` from `ssb`.
fn key_record(fields: &[&str], primary: bool) -> SecretKeyRecord {
    SecretKeyRecord {
        primary,
        keyid: fields.get(4).unwrap_or(&"").to_string(),
        fingerprint: String::new(),
        keygrip: None,
        created: fields.get(5).and_then(|t| t.parse::<u64>().ok()),
        capabilities: fields.get(11).unwrap_or(&"").to_string(),
        // disabled (d) and invalid (i) records are unusable.
        usable: !matches!(
            fields.get(1),
            Some(&"r") | Some(&"e") | Some(&"n") | Some(&"d") | Some(&"i")
        ),
    }
}

/// A 40-hex-char uppercase id from an `fpr:`/`grp:` field, if usable.
fn field_id(value: Option<&&str>) -> Option<String> {
    let id = value.unwrap_or(&"").trim();
    (id.len() == 40 && is_hex_id(id)).then(|| id.to_ascii_uppercase())
}

/// Find the record matching an id: full fingerprint, keygrip, long key
/// id, short key id (last 8 hex chars), each case-insensitive and with
/// an optional `0x` prefix — every selector form GnuPG accepts.
pub fn find_by_id<'a>(
    blocks: &'a [KeyBlock],
    id: &str,
) -> Option<&'a SecretKeyRecord> {
    let (needle, _) = normalize_selector(id);
    blocks
        .iter()
        .flat_map(|b| std::iter::once(&b.primary).chain(b.subkeys.iter()))
        .find(|r| matches_key_id(r, &needle))
}

/// Normalize a user key selector to its comparable form: trim, drop a
/// trailing exact-match marker (`!`), drop an optional `0x`/`0X`
/// prefix (accepted by GnuPG for every id form; verified against
/// 2.4), and uppercase. Returns the normalized id and whether the `!`
/// marker was present.
fn normalize_selector(selector: &str) -> (String, bool) {
    let trimmed = selector.trim();
    let forced = trimmed.ends_with('!');
    let body = trimmed.trim_end_matches('!').trim();
    let body = body
        .strip_prefix("0x")
        .or_else(|| body.strip_prefix("0X"))
        .unwrap_or(body);
    (body.to_ascii_uppercase(), forced)
}

/// Whether `record` is named by an already-normalized selector id:
/// full fingerprint, keygrip, long key id, or the last 8 hex chars of
/// the key id (GnuPG's short key id).
fn matches_key_id(record: &SecretKeyRecord, needle: &str) -> bool {
    record.fingerprint == needle
        || record.keygrip.as_deref() == Some(needle)
        || record.keyid == needle
        || (needle.len() == 8 && record.keyid.ends_with(needle))
}

/// The key GPG's default selection would use to sign within `block`:
/// a selector naming a specific subkey wins (in any id form —
/// fingerprint, long id, short id, `0x`-prefixed — exactly like
/// [`find_by_id`], so all selector forms behave consistently);
/// otherwise the newest usable signing-capable key (primary or
/// subkey — GPG prefers the newest signing subkey, verified against
/// GnuPG 2.4).
pub fn default_signing_key<'a>(
    block: &'a KeyBlock,
    selector: Option<&str>,
) -> Option<&'a SecretKeyRecord> {
    if let Some(selector) = selector {
        let (needle, forced) = normalize_selector(selector);
        if is_hex_id(&needle) {
            // A selector naming a subkey of this block is exact-key
            // semantics: gpg signs with exactly that subkey. A
            // selector naming the primary selects the key *block*
            // (verified: `--local-user <primary>` still signs with
            // the newest signing subkey), so it falls through to the
            // default rule below unless it carries the force (`!`)
            // suffix.
            if let Some(sub) =
                block.subkeys.iter().find(|r| matches_key_id(r, &needle))
            {
                return Some(sub);
            }
            if forced && matches_key_id(&block.primary, &needle) {
                return Some(&block.primary);
            }
        }
    }
    let candidates = std::iter::once(&block.primary)
        .chain(block.subkeys.iter())
        .filter(|r| r.usable && r.can_sign());
    candidates.max_by_key(|r| (r.created.unwrap_or(0), r.primary))
}

/// Parse `gpgconf --list-options gpg-agent` output for the effective
/// cache TTLs. An explicitly configured value (trailing field) wins over
/// the advertised default.
pub fn parse_cache_policy(text: &str) -> Result<CachePolicy> {
    let mut default_ttl = None;
    let mut max_ttl = None;
    for line in text.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        let name = fields.first().copied().unwrap_or_default();
        if name != "default-cache-ttl" && name != "max-cache-ttl" {
            continue;
        }
        // Fields: name:argcount:level:desc:type:alttype:format:default:...:explicit
        let value = if fields.len() > 9 && !fields[9].is_empty() {
            Some(fields[9])
        } else {
            fields.get(7).copied()
        };
        let ttl = value
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|secs| *secs > 0)
            .ok_or_else(|| {
                Error::CachePolicy(format!(
                    "option '{name}' has no usable value"
                ))
            })?;
        let ttl = Duration::from_secs(ttl);
        match name {
            "default-cache-ttl" => default_ttl = Some(ttl),
            "max-cache-ttl" => max_ttl = Some(ttl),
            _ => {}
        }
    }
    match (default_ttl, max_ttl) {
        (Some(default_ttl), Some(max_ttl)) => Ok(CachePolicy {
            default_ttl,
            max_ttl,
        }),
        _ => Err(Error::CachePolicy(
            "gpgconf did not report both cache TTLs".into(),
        )),
    }
}

/// Parse one `gpg-connect-agent` response into its terminal result.
///
/// The last non-empty line decides (Assuan protocol: information lines
/// precede the terminal status): `OK [info]` succeeds, `ERR <code>
/// [<text>]` fails, and anything else — or no lines at all — is
/// malformed and must not be treated as success.
pub fn parse_agent_reply(text: &str) -> AgentReply {
    let Some(terminal) =
        text.lines().rev().map(str::trim).find(|l| !l.is_empty())
    else {
        return AgentReply::Malformed;
    };
    if terminal == "OK" || terminal.starts_with("OK ") {
        return AgentReply::Ok(
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(str::to_owned)
                .collect(),
        );
    }
    if let Some(rest) = terminal.strip_prefix("ERR ") {
        // `ERR <code> [<text>]`: the code is required and numeric; the
        // text is optional.
        let mut parts = rest.splitn(2, char::is_whitespace);
        if let Some(code) = parts.next().and_then(|c| c.parse::<u64>().ok()) {
            return AgentReply::Err {
                code,
                text: parts.next().unwrap_or_default().trim().to_owned(),
            };
        }
    }
    AgentReply::Malformed
}

/// Parse a `KEYINFO` response. `None` means the agent reported no usable
/// information (e.g. an unknown keygrip errors with `ERR ... Not found`).
///
/// Format (verified against GnuPG 2.4):
/// `S KEYINFO <keygrip> <D|T|-> <serial> <idstr> <cached 1|-> <P|C|-> ...`
pub fn parse_keyinfo(text: &str) -> Option<AgentKeyState> {
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 8 || fields[0] != "S" || fields[1] != "KEYINFO" {
            continue;
        }
        let cached = fields[6] == "1";
        let protection = match fields[7] {
            "P" => KeyProtection::Passphrase,
            "C" => KeyProtection::Clear,
            _ => KeyProtection::Unknown,
        };
        return Some(AgentKeyState { cached, protection });
    }
    None
}

/// Resolve a tool executable: `$override` if set (made absolute, since
/// the daemon runs with cwd `/`), else the first executable `name` on
/// `$PATH`. `required` turns a missing tool into an error.
fn detect_tool(
    override_env: &str,
    name: &str,
    required: bool,
) -> Result<Option<PathBuf>> {
    if let Some(spec) = std::env::var_os(override_env) {
        let mut path = PathBuf::from(&spec);
        if !path.is_absolute() {
            let cwd =
                std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
            path = cwd.join(path);
        }
        if !is_executable(&path) {
            let detail = spec.to_string_lossy().into_owned();
            return Err(if required {
                Error::GpgNotFound(detail)
            } else {
                Error::GpgToolNotFound(format!(
                    "{name} (${override_env}={detail})"
                ))
            });
        }
        return Ok(Some(path));
    }
    if let Some(search) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&search) {
            let candidate = dir.join(name);
            if is_executable(&candidate) {
                return Ok(Some(candidate));
            }
        }
    }
    if required {
        return Err(Error::GpgNotFound(format!(
            "{name} (not found on $PATH)"
        )));
    }
    Ok(None)
}

fn is_executable(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    meta.is_file() && meta.permissions().mode() & 0o111 != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY_FPR: &str = "C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48";
    const PRIMARY_ID: &str = "8FACE96FA6D9DB48";
    const PRIMARY_GRIP: &str = "554FB2F0C3F74666FEE23A13A628C32C2310EBAF";
    const SUB_FPR: &str = "54BD088B3AC62D6BC6E4F888212181504E7D2CD7";
    const SUB_ID: &str = "212181504E7D2CD7";
    const SUB_GRIP: &str = "4B88DD924C36F6085738E95FB112B482E33A3220";
    const SUB2_FPR: &str = "97CF31DBA5F6012341995ED8F3C83A12ADCE45A1";
    const SUB2_GRIP: &str = "F097020B875D80D64C742456496ECA8F47CED17F";

    /// Real listing shape: primary + two signing subkeys (GnuPG 2.4.8).
    fn listing() -> String {
        format!(
            "sec:u:255:22:{PRIMARY_ID}:1789136976:::u:::scSC:::+::ed25519:::0:\n\
             fpr:::::::::{PRIMARY_FPR}:\n\
             grp:::::::::{PRIMARY_GRIP}:\n\
             uid:u::::1789136976::78F8::keyhold-test::::::::::0:\n\
             ssb:u:255:22:{SUB_ID}:1789136986::::::s:::+::ed25519::\n\
             fpr:::::::::{SUB_FPR}:\n\
             grp:::::::::{SUB_GRIP}:\n\
             ssb:u:255:22:F3C83A12ADCE45A1:1789137207::::::s:::+::ed25519::\n\
             fpr:::::::::{SUB2_FPR}:\n\
             grp:::::::::{SUB2_GRIP}:\n"
        )
    }

    #[test]
    fn status_parser_extracts_sig_created_fingerprint() {
        let status = parse_status(
            "[GNUPG:] KEY_CONSIDERED C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48 0\n\
             [GNUPG:] BEGIN_SIGNING H10\n\
             [GNUPG:] SIG_CREATED D 22 10 00 1789136997 54bd088b3ac62d6bc6e4f888212181504e7d2cd7\n",
        );
        assert_eq!(
            status.sig_created.as_deref(),
            Some("54BD088B3AC62D6BC6E4F888212181504E7D2CD7")
        );
        assert!(!status.pinentry_launched);
        assert_eq!(
            status.key_considered,
            vec!["C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48"]
        );
    }

    #[test]
    fn status_parser_handles_pinentry_launched_and_dedupes_key_considered() {
        let status = parse_status(
            "[GNUPG:] KEY_CONSIDERED C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48 0\n\
             [GNUPG:] KEY_CONSIDERED C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48 0\n\
             [GNUPG:] PINENTRY_LAUNCHED 2503588 gnome3 1.3.2 not a tty dumb :0 ? 1000/1000 -\n",
        );
        assert!(status.pinentry_launched);
        assert_eq!(status.key_considered.len(), 1);
        assert!(status.sig_created.is_none());
    }

    #[test]
    fn status_parser_extracts_failure_codes_without_stderr() {
        // The last FAILURE record wins; a `_SYMBOL` suffix is stripped.
        let status = parse_status(
            "[GNUPG:] FAILURE sign 67108875\n\
             [GNUPG:] FAILURE - 151011327_EOF\n",
        );
        assert_eq!(status.failure_code, Some(151_011_327));
        assert_eq!(
            parse_status("[GNUPG:] FAILURE sign 67108963\n").failure_code,
            Some(67108963)
        );
        // Malformed/incomplete FAILURE records contribute nothing.
        assert_eq!(parse_status("[GNUPG:] FAILURE sign\n").failure_code, None);
        assert_eq!(
            parse_status("[GNUPG:] FAILURE sign not-a-number\n").failure_code,
            None
        );
        assert_eq!(parse_status("[GNUPG:] FAILURE\n").failure_code, None);
    }

    #[test]
    fn status_parser_ignores_unrelated_and_malformed_records() {
        let status = parse_status(
            "[GNUPG:] BEGIN_SIGNING H10\n\
             [GNUPG:] INV_SGNR 9 <no-key>\n\
             [GNUPG:] SIG_CREATED D 22 10 00\n\
             [GNUPG:] SIG_CREATED truncated\n\
             [GNUPG:] KEY_CONSIDERED not-a-fpr 0\n\
             [GNUPG:] KEY_CONSIDERED\n\
             plain stderr-ish noise\n\
             [GNUPG:] NEED_PASSPHRASE this that more\n",
        );
        // Malformed records contribute nothing, but their presence is
        // still evidence that gpg emits status on this stream.
        assert_eq!(
            status,
            GpgStatus {
                saw_status: true,
                ..GpgStatus::default()
            }
        );
        // A stream with no status records at all leaves no evidence.
        assert_eq!(parse_status("plain noise only\n"), GpgStatus::default());
    }

    #[test]
    fn status_parser_takes_the_last_field_of_sig_created() {
        // Standard (non-detached) prefixes must not confuse the parser.
        let status = parse_status(
            "[GNUPG:] SIG_CREATED S 22 10 00 1789136997 54BD088B3AC62D6BC6E4F888212181504E7D2CD7\n",
        );
        assert_eq!(status.sig_created.as_deref(), Some(SUB_FPR));
    }

    #[test]
    fn key_blocks_parse_primary_and_subkeys_with_grips() {
        let blocks = parse_key_blocks(&listing());
        assert_eq!(blocks.len(), 1);
        let block = &blocks[0];
        assert_eq!(block.primary.fingerprint, PRIMARY_FPR);
        assert_eq!(block.primary.keygrip.as_deref(), Some(PRIMARY_GRIP));
        assert_eq!(block.subkeys.len(), 2);
        assert_eq!(block.subkeys[0].fingerprint, SUB_FPR);
        assert_eq!(block.subkeys[0].keygrip.as_deref(), Some(SUB_GRIP));
        assert_eq!(block.subkeys[1].fingerprint, SUB2_FPR);
        assert!(block.primary.can_sign());
        assert!(block.subkeys[0].can_sign());
    }

    #[test]
    fn find_by_id_matches_fingerprint_keygrip_and_key_ids() {
        let blocks = parse_key_blocks(&listing());
        assert_eq!(
            find_by_id(&blocks, PRIMARY_FPR).map(|r| &r.fingerprint),
            Some(&PRIMARY_FPR.to_string())
        );
        assert_eq!(
            find_by_id(&blocks, SUB_GRIP).map(|r| &r.fingerprint),
            Some(&SUB_FPR.to_string())
        );
        assert_eq!(
            find_by_id(&blocks, PRIMARY_ID).map(|r| &r.fingerprint),
            Some(&PRIMARY_FPR.to_string())
        );
        // Short (8-hex) key id.
        assert_eq!(
            find_by_id(&blocks, "4E7D2CD7").map(|r| &r.fingerprint),
            Some(&SUB_FPR.to_string())
        );
        // Case-insensitive, and unknown ids find nothing.
        assert!(
            find_by_id(&blocks, "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
                .is_none()
        );
        assert!(find_by_id(&blocks, "not-an-id").is_none());
    }

    #[test]
    fn default_signing_key_prefers_newest_signing_subkey() {
        let blocks = parse_key_blocks(&listing());
        let target = default_signing_key(&blocks[0], None).expect("a signer");
        // The second subkey was created later; GPG signs with it.
        assert_eq!(target.fingerprint, SUB2_FPR);
    }

    #[test]
    fn default_signing_key_honours_exact_subkey_selector() {
        let blocks = parse_key_blocks(&listing());
        let target =
            default_signing_key(&blocks[0], Some(SUB_FPR)).expect("a signer");
        assert_eq!(target.fingerprint, SUB_FPR);
        // An `!`-suffixed primary forces the primary itself.
        let forced =
            default_signing_key(&blocks[0], Some(&format!("{PRIMARY_FPR}!")))
                .expect("a signer");
        assert_eq!(forced.fingerprint, PRIMARY_FPR);
    }

    #[test]
    fn default_signing_key_resolves_the_older_subkey_by_short_id() {
        let blocks = parse_key_blocks(&listing());
        // The 8-char short id names the older signing subkey; without
        // short-id matching this used to fall through to the newer
        // subkey — silently operating on the wrong keygrip.
        let target = default_signing_key(&blocks[0], Some("4E7D2CD7"))
            .expect("a signer");
        assert_eq!(target.fingerprint, SUB_FPR);
        assert_eq!(target.keygrip.as_deref(), Some(SUB_GRIP));
    }

    #[test]
    fn default_signing_key_selector_forms_agree() {
        let blocks = parse_key_blocks(&listing());
        // Every id form GnuPG accepts (verified against 2.4: `0x`
        // prefixes and short ids are valid --local-user selectors)
        // must resolve the same subkey, case-insensitively, with and
        // without the exact (`!`) marker.
        let forms = [
            SUB_FPR.to_string(),
            format!("{}!", SUB_FPR),
            SUB_FPR.to_lowercase(),
            SUB_ID.to_string(),
            format!("0x{SUB_ID}"),
            format!("0x{}", SUB_ID.to_lowercase()),
            "4E7D2CD7".to_string(),
            "4e7d2cd7".to_string(),
            "0x4E7D2CD7".to_string(),
            "0x4e7d2cd7".to_string(),
            format!("{}!", SUB_ID),
        ];
        for form in &forms {
            let target =
                default_signing_key(&blocks[0], Some(form)).expect(form);
            assert_eq!(target.fingerprint, SUB_FPR, "selector {form}");
            assert_eq!(target.keygrip.as_deref(), Some(SUB_GRIP));
        }
    }

    #[test]
    fn default_signing_key_primary_selector_still_prefers_subkeys() {
        let blocks = parse_key_blocks(&listing());
        // A primary named in any form selects the key block: GPG signs
        // with the newest signing subkey unless `!` forces the primary.
        for primary in [PRIMARY_FPR, PRIMARY_ID, "A6D9DB48"] {
            let target =
                default_signing_key(&blocks[0], Some(primary)).unwrap();
            assert_eq!(target.fingerprint, SUB2_FPR, "selector {primary}");
            let forced =
                default_signing_key(&blocks[0], Some(&format!("{primary}!")))
                    .unwrap();
            assert_eq!(forced.fingerprint, PRIMARY_FPR, "selector {primary}!");
        }
    }

    #[test]
    fn find_by_id_accepts_0x_prefixed_and_case_insensitive_ids() {
        let blocks = parse_key_blocks(&listing());
        assert_eq!(
            find_by_id(&blocks, &format!("0x{SUB_ID}"))
                .map(|r| &r.fingerprint),
            Some(&SUB_FPR.to_string())
        );
        assert_eq!(
            find_by_id(&blocks, "0x4e7d2cd7").map(|r| &r.fingerprint),
            Some(&SUB_FPR.to_string())
        );
        // An `!` marker is tolerated by the shared normalization.
        assert_eq!(
            find_by_id(&blocks, &format!("{SUB_FPR}!"))
                .map(|r| &r.fingerprint),
            Some(&SUB_FPR.to_string())
        );
    }

    #[test]
    fn default_signing_key_falls_back_to_primary_without_subkeys() {
        let text = format!(
            "sec:u:255:22:{PRIMARY_ID}:1789136976:::u:::scSC:::+::ed25519:::0:\n\
             fpr:::::::::{PRIMARY_FPR}:\n\
             grp:::::::::{PRIMARY_GRIP}:\n\
             ssb:u:255:22:{SUB_ID}:1789136986::::::e:::+::cv25519::\n\
             fpr:::::::::{SUB_FPR}:\n"
        );
        let blocks = parse_key_blocks(&text);
        // The only subkey encrypts (`e`), so the primary signs.
        assert_eq!(
            default_signing_key(&blocks[0], None)
                .expect("a signer")
                .fingerprint,
            PRIMARY_FPR
        );
    }

    #[test]
    fn default_signing_key_skips_revoked_subkeys() {
        let text = format!(
            "sec:u:255:22:{PRIMARY_ID}:1789136976:::u:::scSC:::+::ed25519:::0:\n\
             fpr:::::::::{PRIMARY_FPR}:\n\
             grp:::::::::{PRIMARY_GRIP}:\n\
             ssb:r:255:22:{SUB_ID}:1789136986::::::s:::+::ed25519::\n\
             fpr:::::::::{SUB_FPR}:\n"
        );
        let blocks = parse_key_blocks(&text);
        assert_eq!(
            default_signing_key(&blocks[0], None)
                .expect("a signer")
                .fingerprint,
            PRIMARY_FPR
        );
    }

    #[test]
    fn cache_policy_prefers_explicit_values_over_defaults() {
        // Real gpgconf 2.4.8 shape (explicit max, default-only default).
        let text = "\
default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:600::\n\
max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:7200::999\n\
max-cache-ttl-ssh:24:2:set maximum SSH key lifetime to N seconds:3:3:N:7200::\n";
        let policy = parse_cache_policy(text).unwrap();
        assert_eq!(policy.default_ttl, Duration::from_secs(600));
        assert_eq!(policy.max_ttl, Duration::from_secs(999));
    }

    #[test]
    fn cache_policy_uses_advertised_defaults_when_unset() {
        let text = "\
default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:600::\n\
max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:7200::\n";
        let policy = parse_cache_policy(text).unwrap();
        assert_eq!(policy.max_ttl, Duration::from_secs(7200));
    }

    #[test]
    fn cache_policy_rejects_missing_zero_and_malformed_values() {
        let missing = "unrelated:1:0:x:0:0:N:5::\n";
        assert!(parse_cache_policy(missing).is_err());
        let zero = "default-cache-ttl:24:0:d:3:3:N:0::\nmax-cache-ttl:24:2:d:3:3:N:10::\n";
        assert!(parse_cache_policy(zero).is_err());
        let malformed = "default-cache-ttl:24:0:d:3:3:N:banana::\nmax-cache-ttl:24:2:d:3:3:N:10::\n";
        assert!(parse_cache_policy(malformed).is_err());
        // -ssh twins must not satisfy the non-ssh lookups.
        let ssh_only = "\
max-cache-ttl-ssh:24:2:d:3:3:N:10::\ndefault-cache-ttl-ssh:24:0:d:3:3:N:10::\n";
        assert!(parse_cache_policy(ssh_only).is_err());
    }

    #[test]
    fn keyinfo_parses_cached_protected_locked_and_clear_states() {
        let cached = parse_keyinfo(&format!(
            "S KEYINFO {SUB_GRIP} D - - 1 P - - -\nOK\n"
        ));
        assert_eq!(
            cached,
            Some(AgentKeyState {
                cached: true,
                protection: KeyProtection::Passphrase,
            })
        );
        let locked = parse_keyinfo(&format!(
            "S KEYINFO {SUB_GRIP} D - - - P - - -\nOK\n"
        ));
        assert_eq!(
            locked,
            Some(AgentKeyState {
                cached: false,
                protection: KeyProtection::Passphrase,
            })
        );
        let clear = parse_keyinfo(&format!(
            "S KEYINFO {SUB_GRIP} D - - - C - - -\nOK\n"
        ));
        assert_eq!(
            clear,
            Some(AgentKeyState {
                cached: false,
                protection: KeyProtection::Clear,
            })
        );
        let unknown = parse_keyinfo(&format!(
            "S KEYINFO {SUB_GRIP} D - - - - - - -\nOK\n"
        ));
        assert_eq!(
            unknown,
            Some(AgentKeyState {
                cached: false,
                protection: KeyProtection::Unknown,
            })
        );
    }

    #[test]
    fn keyinfo_agent_error_or_malformed_yields_none() {
        assert!(
            parse_keyinfo("ERR 67108891 Not found <GPG Agent>\nOK\n")
                .is_none()
        );
        assert!(parse_keyinfo("OK\n").is_none());
        assert!(parse_keyinfo("S KEYINFO grip\nOK\n").is_none());
        assert!(parse_keyinfo("").is_none());
    }

    #[test]
    fn agent_reply_recognises_terminal_ok_and_err() {
        assert_eq!(parse_agent_reply(""), AgentReply::Malformed);
        assert_eq!(parse_agent_reply("OK"), AgentReply::Ok(vec!["OK".into()]));
        // `OK` may carry info text (Assuan allows it; our commands
        // never produce it).
        assert_eq!(
            parse_agent_reply("OK Getinfo\n"),
            AgentReply::Ok(vec!["OK Getinfo".into()])
        );
        // Information lines precede the terminal status.
        assert_eq!(
            parse_agent_reply("S KEYINFO GRIP D - - 1 P - - -\nOK\n"),
            AgentReply::Ok(vec![
                "S KEYINFO GRIP D - - 1 P - - -".into(),
                "OK".into()
            ])
        );
        assert_eq!(
            parse_agent_reply("ERR 67108891 Not found <GPG Agent>\n"),
            AgentReply::Err {
                code: 67108891,
                text: "Not found <GPG Agent>".into()
            }
        );
        // An ERR line may carry no text.
        assert_eq!(
            parse_agent_reply("ERR 67108891"),
            AgentReply::Err {
                code: 67108891,
                text: String::new(),
            }
        );
    }

    #[test]
    fn agent_reply_rejects_malformed_and_misplaced_lines() {
        // A bare data line, a non-numeric code, a keyword that is
        // neither OK nor ERR, and a terminal line that is not last.
        assert_eq!(parse_agent_reply("D abcdef"), AgentReply::Malformed);
        assert_eq!(
            parse_agent_reply("ERR not-a-code nope\n"),
            AgentReply::Malformed
        );
        assert_eq!(parse_agent_reply("junk\n"), AgentReply::Malformed);
        assert_eq!(
            parse_agent_reply("OK\nS KEYINFO trailing\n"),
            AgentReply::Malformed
        );
        // Blank noise and CRLF endings do not confuse the parser.
        assert_eq!(
            parse_agent_reply("\r\nS KEYINFO G D - - 1 P - - -\r\nOK\r\n"),
            AgentReply::Ok(vec![
                "S KEYINFO G D - - 1 P - - -".into(),
                "OK".into()
            ])
        );
    }

    #[test]
    fn agent_err_code_matching_uses_the_libgpg_error_bits() {
        // GPG_ERR_NOT_FOUND (27) rides in the low 15 bits; the high
        // bits are the error source and must not disturb the match.
        let not_found = parse_agent_reply("ERR 67108891 Not found\n");
        assert!(not_found.has_code(GPG_ERR_NOT_FOUND));
        let other = parse_agent_reply("ERR 67109139 Unknown IPC command\n");
        assert!(!other.has_code(GPG_ERR_NOT_FOUND));
        assert!(!parse_agent_reply("OK\n").has_code(GPG_ERR_NOT_FOUND));
    }
}
