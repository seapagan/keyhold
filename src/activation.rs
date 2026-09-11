//! Activation flows for `keyhold on`, in both operating modes.
//!
//! The ordinary flow is passphrase-blind: one foreground key use with
//! normal pinentry, plus truthfulness warnings about GnuPG's absolute
//! `max-cache-ttl`. The stored flow (`--store-passphrase`) additionally
//! establishes a deterministic cache epoch: probe the exact signing key,
//! obtain the session credential **before** touching the GPG cache, clear
//! only that keygrip's normal cache entry, unlock with an exact loopback
//! sign, and only then store/replace the credential and hand the daemon
//! non-secret metadata.
//!
//! The passphrase never appears in argv, environment, files, daemon IPC
//! or errors; it exists only in [`zeroize::Zeroizing`] owners for the
//! duration of one validation.

use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use crate::{
    credential::CredentialStore,
    error::{Error, Result},
    gpg::{Gpg, GpgUse, KeyProtection, PingMode, SigningTarget},
    state::{CachePlan, CredentialMode, KeySource},
};

/// What a successful activation hands to the caller: exact IPC metadata
/// plus any warnings to show the user. No secret material.
#[derive(Debug)]
pub struct Prepared {
    /// The resolved exact signing key, when identifiable.
    pub target: Option<SigningTarget>,
    /// GPG cache tracking metadata for the daemon.
    pub cache: Option<CachePlan>,
    /// Truthfulness warnings for the user (ordinary-mode limitations).
    pub warnings: Vec<String>,
}

/// The prompt the foreground stored-mode flow may use (once, or twice
/// across a stale-credential replacement). The daemon never sees it.
pub type Prompt<'a> = dyn Fn() -> Result<Zeroizing<Vec<u8>>> + 'a;

/// Run the activation flow. `store_enabled` selects the mode; `key` and
/// `interval` are the resolved CLI/config values. GPG is used (and, in
/// stored mode, the Secret Service store) but the daemon is not
/// contacted — that is the caller's job.
pub fn activate(
    gpg: &Gpg,
    store_enabled: bool,
    key: Option<&str>,
    key_source: KeySource,
    interval: Duration,
    hold_for: Option<Duration>,
    store: &dyn CredentialStore,
    prompt: &Prompt<'_>,
) -> Result<Prepared> {
    let _ = key_source;
    if store_enabled {
        stored(gpg, key, interval, store, prompt)
    } else {
        ordinary(gpg, key, interval, hold_for)
    }
}

/// The default, passphrase-blind activation.
fn ordinary(
    gpg: &Gpg,
    key: Option<&str>,
    interval: Duration,
    hold_for: Option<Duration>,
) -> Result<Prepared> {
    // Best-effort: a missing/unreadable TTL policy only means keyhold
    // cannot warn truthfully; the hold itself is unaffected.
    let policy = gpg.cache_policy().ok();
    let used = use_foreground(gpg, key)?;
    let mut warnings = Vec::new();
    let mut started_wall = None;
    if let Some(policy) = &policy {
        if interval >= policy.default_ttl {
            warnings.push(interval_warning(interval, policy.default_ttl));
        }
        if let Some(hold) = hold_for
            && hold >= policy.max_ttl
        {
            warnings.push(format!(
                "GnuPG's max-cache-ttl is {}; an ordinary hold cannot be \
                 guaranteed for {}; use --store-passphrase for automatic \
                 session recovery",
                humantime::format_duration(policy.max_ttl),
                humantime::format_duration(hold),
            ));
        }
        if hold_for.is_none() {
            warnings.push(format!(
                "GnuPG's hard max-cache-ttl ({}) will eventually end an \
                 ordinary hold unless the cache entry is recreated \
                 externally",
                humantime::format_duration(policy.max_ttl),
            ));
        }
        match used.pinentry_launched {
            Some(false) => warnings.push(
                "the key was already cached before this activation, so \
                 its remaining hard-max lifetime is unknown and may be \
                 shorter than the requested hold"
                    .into(),
            ),
            Some(true) => {
                // A fresh unlock just created the cache entry: keyhold
                // knows the epoch and can display an honest countdown.
                started_wall = Some(SystemTime::now());
            }
            // No status stream: no evidence either way, no warning.
            None => {}
        }
    }
    Ok(Prepared {
        target: used.target,
        cache: policy.map(|policy| CachePlan {
            mode: CredentialMode::None,
            default_ttl: policy.default_ttl,
            max_ttl: policy.max_ttl,
            started_wall,
        }),
        warnings,
    })
}

/// The opt-in stored-passphrase activation. See the module docs for the
/// safety ordering; every invariant is deliberate.
fn stored(
    gpg: &Gpg,
    key: Option<&str>,
    interval: Duration,
    store: &dyn CredentialStore,
    prompt: &Prompt<'_>,
) -> Result<Prepared> {
    let policy = gpg.cache_policy().map_err(|e| {
        Error::Message(format!(
            "session credential mode needs GnuPG's cache settings: {e}; \
             the hold was NOT enabled"
        ))
    })?;
    let target = gpg.probe_target(key).map_err(|e| {
        Error::Message(format!("{e}; the hold was NOT enabled"))
    })?;
    let Some(keygrip) = target.keygrip.clone() else {
        return Err(Error::Message(
            "gpg reported no keygrip for the signing key; session \
             credential mode is not available for it; the hold was NOT \
             enabled"
                .into(),
        ));
    };
    let state = gpg.key_state(&keygrip)?;
    if state.protection == KeyProtection::Unknown {
        return Err(Error::Message(
            "the agent did not report the key's protection type; \
             session credential mode is not supported for this key; \
             the hold was NOT enabled"
                .into(),
        ));
    }
    if state.protection == KeyProtection::Clear {
        // An unprotected key needs no credential: establish a normal
        // successful use and mark the mode NotNeeded. No secret is
        // stored and no cache entry is involved.
        let used = use_foreground(gpg, key)?;
        let target = used.target.unwrap_or(target);
        let mut warnings = Vec::new();
        if interval >= policy.default_ttl {
            warnings.push(interval_warning(interval, policy.default_ttl));
        }
        return Ok(Prepared {
            target: Some(target),
            cache: Some(CachePlan {
                mode: CredentialMode::NotNeeded,
                default_ttl: policy.default_ttl,
                max_ttl: policy.max_ttl,
                started_wall: None,
            }),
            warnings,
        });
    }

    // Obtain the credential BEFORE clearing anything: a Secret Service
    // outage must not lock a currently usable key.
    let stored_secret = store.load(&keygrip);
    let freshly_typed = !matches!(stored_secret, Ok(Some(_)));
    let secret = match stored_secret {
        Ok(Some(secret)) => secret,
        Ok(None) => prompt().map_err(|e| {
            Error::Message(format!("{e}; the hold was NOT enabled"))
        })?,
        Err(e) => {
            return Err(Error::Message(format!(
                "could not read the session credential: {e}; the GPG \
                 cache entry was left untouched; the hold was NOT enabled"
            )));
        }
    };
    // A freshly typed credential that is rejected simply fails; a stored
    // one may be stale and gets one replacement round.
    let replace = (!freshly_typed).then_some((store, prompt));
    unlock_epoch(gpg, &target, &keygrip, &secret, replace)?;
    if freshly_typed {
        store.store(&target, &secret).map_err(|e| {
            Error::Message(format!(
                "the key unlocked but storing the session credential \
                 failed: {e}; the hold was NOT enabled"
            ))
        })?;
    }
    let mut warnings = Vec::new();
    if interval >= policy.default_ttl {
        warnings.push(interval_warning(interval, policy.default_ttl));
    }
    Ok(Prepared {
        target: Some(target),
        cache: Some(CachePlan {
            mode: CredentialMode::Session,
            default_ttl: policy.default_ttl,
            max_ttl: policy.max_ttl,
            started_wall: Some(SystemTime::now()),
        }),
        warnings,
    })
}

/// Clear the keygrip's normal cache entry and unlock it with the
/// supplied credential, establishing a fresh epoch. A stored credential
/// GPG conclusively rejects is deleted and replaced after one fresh
/// prompt (when `replace` is given); a freshly typed one that is
/// rejected simply fails. Nothing is enabled on failure.
fn unlock_epoch(
    gpg: &Gpg,
    target: &SigningTarget,
    keygrip: &str,
    secret: &Zeroizing<Vec<u8>>,
    replace: Option<(&dyn CredentialStore, &Prompt)>,
) -> Result<()> {
    let not_enabled =
        |e: Error| Error::Message(format!("{e}; the hold was NOT enabled"));
    gpg.clear_passphrase(keygrip).map_err(|e| {
        Error::Message(format!(
            "clearing the GPG cache entry failed: {e}; the hold was \
                 NOT enabled"
        ))
    })?;
    match gpg.use_key_with_passphrase(target, secret) {
        Ok(()) => Ok(()),
        Err(Error::BadPassphrase) if replace.is_some() => {
            let (store, prompt) = replace.expect("checked");
            // Remove the stale item; the replacement store below
            // overwrites anyway, so a delete failure is not fatal here.
            let _ = store.delete(keygrip);
            let fresh = prompt().map_err(|e| {
                Error::Message(format!("{e}; the hold was NOT enabled"))
            })?;
            // The failed attempt left nothing cached, but clear again so
            // the validation (and the epoch) is deterministic.
            gpg.clear_passphrase(keygrip).map_err(not_enabled)?;
            gpg.use_key_with_passphrase(target, &fresh)
                .map_err(not_enabled)?;
            store.store(target, &fresh).map_err(|e| {
                Error::Message(format!(
                    "the key unlocked but storing the session credential \
                     failed: {e}; the hold was NOT enabled"
                ))
            })
        }
        Err(e) => Err(not_enabled(e)),
    }
}

fn interval_warning(interval: Duration, default_ttl: Duration) -> String {
    format!(
        "the {} keepalive interval is not shorter than GnuPG's \
         default-cache-ttl ({}); the idle cache may expire between pings",
        humantime::format_duration(interval),
        humantime::format_duration(default_ttl),
    )
}

fn use_foreground(gpg: &Gpg, key: Option<&str>) -> Result<GpgUse> {
    gpg.use_key(key, PingMode::Foreground)
        .map_err(|e| Error::Message(format!("{e}; the hold was NOT enabled")))
}

#[cfg(test)]
mod tests {
    // The flows above are integration-tested end-to-end (and
    // in-process) against fake gpg tooling; the state-machine
    // arithmetic they produce is unit-tested in `state`.
}
