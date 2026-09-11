//! Session credential storage for the opt-in stored-passphrase mode.
//!
//! The GPG passphrase is stored only in the Linux Secret Service
//! collection aliased **`session`** — the collection the desktop
//! session destroys at logout. There is deliberately no fallback to the
//! `default`/`login` collection, no on-disk store, and no plaintext
//! cache: if the session collection is unavailable, storing fails.
//!
//! Secret hygiene:
//!
//! * secrets exist in keyhold memory only inside [`zeroize::Zeroizing`]
//!   owners, and only for the duration of one operation;
//! * secret bytes never appear in labels, attributes, error messages or
//!   `Debug` output (this module never derives `Debug` for values that
//!   saw a secret);
//! * the passphrase reaches `gpg` only through child stdin
//!   (see [`crate::gpg::Gpg::use_key_with_passphrase`]).
//!
//! The narrow [`CredentialStore`] trait keeps daemon/state logic testable
//! with an in-process fake instead of a live desktop keyring.

use std::collections::HashMap;

use secret_service::{
    EncryptionType,
    blocking::{Collection, SecretService as SsService},
};
use zeroize::Zeroizing;

use crate::{
    error::{Error, Result},
    gpg::SigningTarget,
};

/// Attribute marking every item keyhold creates.
pub const APPLICATION_ATTRIBUTE: &str = "keyhold";
/// Attribute distinguishing GPG passphrases from future item kinds.
pub const KIND_ATTRIBUTE: &str = "gpg-passphrase";

/// Minimal storage contract for the session credential, so daemon and
/// activation logic can run against a fake in tests.
///
/// All operations are keyed by the agent keygrip of the signing key.
pub trait CredentialStore: Send + Sync {
    /// Load the stored passphrase for `keygrip`. `Ok(None)` means no
    /// credential is stored.
    fn load(&self, keygrip: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;

    /// Whether a credential exists for `keygrip`.
    fn contains(&self, keygrip: &str) -> Result<bool>;

    /// Store (replacing any existing) the passphrase for `target`.
    fn store(&self, target: &SigningTarget, secret: &[u8]) -> Result<()>;

    /// Delete the credential for `keygrip`. Returns whether one existed.
    fn delete(&self, keygrip: &str) -> Result<bool>;

    /// Delete every keyhold credential in the session collection.
    /// Returns how many were removed.
    fn clear_all(&self) -> Result<usize>;
}

/// Secret Service storage restricted to the `session` collection.
///
/// Each operation opens its own (encrypted, DH-negotiated) connection;
/// no D-Bus object graph is retained in daemon state.
#[derive(Debug, Clone, Copy, Default)]
pub struct SessionCredentialStore;

impl SessionCredentialStore {
    /// Connect to the unlocked `session` collection and run `f` on it.
    ///
    /// A missing session collection, a locked one (keyhold never drives
    /// a Secret Service unlock prompt from unattended code) or an
    /// unavailable Secret Service are clear operational errors — never a
    /// silent fallback to persistent storage.
    fn with_session_collection<T>(
        f: impl FnOnce(&Collection<'_>) -> Result<T>,
    ) -> Result<T> {
        let service = SsService::connect(EncryptionType::Dh).map_err(|e| {
            Error::SecretService(format!(
                "could not connect to the Secret Service \
                     (is a desktop keyring session available?): {e}"
            ))
        })?;
        let collection =
            service.get_collection_by_alias("session").map_err(|e| {
                Error::SecretService(format!(
                    "the Secret Service has no 'session' collection: {e}"
                ))
            })?;
        if collection.is_locked().map_err(|e| {
            Error::SecretService(format!(
                "could not check the session collection state: {e}"
            ))
        })? {
            return Err(Error::SecretService(
                "the Secret Service session collection is locked; \
                 unlock the keyring and try again"
                    .into(),
            ));
        }
        f(&collection)
    }

    /// Find keyhold's items for exactly `keygrip`.
    fn find<'a>(
        collection: &'a Collection<'_>,
        keygrip: &str,
    ) -> Result<Vec<secret_service::blocking::Item<'a>>> {
        let attributes = HashMap::from([
            ("application", APPLICATION_ATTRIBUTE),
            ("kind", KIND_ATTRIBUTE),
            ("keygrip", keygrip),
        ]);
        collection
            .search_items(attributes)
            .map_err(|e| ss_error("searching the session collection", e))
    }
}

/// Attributes identifying keyhold's item for `keygrip` (the empty
/// fingerprint placeholder is replaced by the real one at store time).
fn item_attributes<'a>(
    keygrip: &'a str,
    fingerprint: &'a str,
) -> HashMap<&'a str, &'a str> {
    HashMap::from([
        ("application", APPLICATION_ATTRIBUTE),
        ("kind", KIND_ATTRIBUTE),
        ("keygrip", keygrip),
        ("fingerprint", fingerprint),
    ])
}

/// The subset used to find keyhold's items without knowing the keygrip.
fn owner_attributes() -> HashMap<&'static str, &'static str> {
    HashMap::from([
        ("application", APPLICATION_ATTRIBUTE),
        ("kind", KIND_ATTRIBUTE),
    ])
}

/// Uniform Secret Service error context; never includes secret bytes.
fn ss_error(context: &str, e: secret_service::Error) -> Error {
    Error::SecretService(format!("{context} failed: {e}"))
}

impl CredentialStore for SessionCredentialStore {
    fn load(&self, keygrip: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Self::with_session_collection(|collection| {
            let items = Self::find(collection, keygrip)?;
            let Some(item) = items.first() else {
                return Ok(None);
            };
            let secret = item
                .get_secret()
                .map_err(|e| ss_error("reading the session credential", e))?;
            Ok(Some(Zeroizing::new(secret)))
        })
    }

    fn contains(&self, keygrip: &str) -> Result<bool> {
        Self::with_session_collection(|collection| {
            Ok(!Self::find(collection, keygrip)?.is_empty())
        })
    }

    fn store(&self, target: &SigningTarget, secret: &[u8]) -> Result<()> {
        let Some(keygrip) = target.keygrip.as_deref() else {
            return Err(Error::SecretService(
                "cannot store a credential without a keygrip".into(),
            ));
        };
        Self::with_session_collection(|collection| {
            collection
                .create_item(
                    &item_label(&target.fingerprint),
                    item_attributes(keygrip, &target.fingerprint),
                    secret,
                    true,
                    "application/octet-stream",
                )
                .map_err(|e| ss_error("storing the session credential", e))?;
            Ok(())
        })
    }

    fn delete(&self, keygrip: &str) -> Result<bool> {
        Self::with_session_collection(|collection| {
            let items = Self::find(collection, keygrip)?;
            let existed = !items.is_empty();
            for item in items {
                item.delete().map_err(|e| {
                    ss_error("deleting the session credential", e)
                })?;
            }
            Ok(existed)
        })
    }

    fn clear_all(&self) -> Result<usize> {
        Self::with_session_collection(|collection| {
            let items =
                collection.search_items(owner_attributes()).map_err(|e| {
                    ss_error("searching the session collection", e)
                })?;
            let count = items.len();
            for item in items {
                item.delete().map_err(|e| {
                    ss_error("deleting the session credential", e)
                })?;
            }
            Ok(count)
        })
    }
}

/// Human label showing only a short fingerprint prefix.
fn item_label(fingerprint: &str) -> String {
    let short: String = fingerprint.chars().take(8).collect();
    format!("Keyhold GPG session credential {short}")
}

/// Prompt once for the GPG passphrase in the foreground opt-in flow.
///
/// Only the CLI activation path may call this; the daemon never prompts.
/// The returned buffer is zeroized on drop. CR/LF is rejected up front
/// because the gpg stdin transport is line-based.
pub fn prompt_passphrase() -> Result<Zeroizing<Vec<u8>>> {
    let answer = rpassword::prompt_password(
        "GPG passphrase (store for this login session): ",
    )
    .map_err(|e| {
        Error::Message(format!("could not read the passphrase: {e}"))
    })?;
    let secret = Zeroizing::new(answer.into_bytes());
    if secret.contains(&b'\n') || secret.contains(&b'\r') {
        return Err(Error::Message(
            "the passphrase contains a newline; keyhold feeds it to gpg \
             as a single line via --passphrase-fd 0"
                .into(),
        ));
    }
    Ok(secret)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn item_attributes_carry_owner_kind_and_target() {
        let attrs = item_attributes("GRIP", "FPR");
        assert_eq!(attrs.get("application"), Some(&"keyhold"));
        assert_eq!(attrs.get("kind"), Some(&"gpg-passphrase"));
        assert_eq!(attrs.get("keygrip"), Some(&"GRIP"));
        assert_eq!(attrs.get("fingerprint"), Some(&"FPR"));
        // Owner-only search must not pin any single key.
        let owner = owner_attributes();
        assert!(!owner.contains_key("keygrip"));
        assert!(!owner.contains_key("fingerprint"));
    }

    #[test]
    fn item_label_shows_only_a_short_prefix() {
        assert_eq!(
            item_label("54BD088B3AC62D6BC6E4F888212181504E7D2CD7"),
            "Keyhold GPG session credential 54BD088B"
        );
        // Short inputs degrade gracefully without panicking.
        assert_eq!(item_label("AB"), "Keyhold GPG session credential AB");
    }
}
