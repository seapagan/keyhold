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

use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    path::Path,
};

use secret_service::{
    EncryptionType,
    blocking::{Collection, SecretService as SsService},
};
use zeroize::Zeroizing;

use crate::{
    daemon,
    error::{Error, Result},
    gpg::SigningTarget,
};

/// Attribute marking every item keyhold creates.
pub const APPLICATION_ATTRIBUTE: &str = "keyhold";
/// Attribute distinguishing GPG passphrases from future item kinds.
pub const KIND_ATTRIBUTE: &str = "gpg-passphrase";

/// Owned key-scoped credential transaction. Dropping it releases both locks.
pub trait CredentialTransactionGuard: Send {}

impl<T: Send> CredentialTransactionGuard for T {}

/// Minimal storage contract for the session credential, so daemon and
/// activation logic can run against a fake in tests.
///
/// All operations are keyed by the agent keygrip of the signing key.
pub trait CredentialStore: Send + Sync {
    /// Serialize credential use and mutation for one resolved keygrip.
    fn lock_transaction(
        &self,
        keygrip: &str,
    ) -> Result<Box<dyn CredentialTransactionGuard>>;

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

const STORE_LOCK_FILE: &str = "credential-store.lock";

struct CredentialTransactionLock {
    _global: File,
    _key: File,
}

impl CredentialTransactionLock {
    fn acquire(keygrip: &str) -> Result<Self> {
        let paths = daemon::paths()?;
        daemon::ensure_private_dir(&paths.dir)?;
        Self::acquire_in(&paths.dir, keygrip)
    }

    fn acquire_in(dir: &Path, keygrip: &str) -> Result<Self> {
        if keygrip.len() != 40
            || !keygrip.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(Error::GpgTarget(
                "resolved signing key has an invalid keygrip".into(),
            ));
        }
        let global = open_lock(dir, STORE_LOCK_FILE)?;
        fs4::FileExt::lock_shared(&global)?;
        let key = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(dir.join(format!("credential-{keygrip}.lock")))?;
        fs4::FileExt::lock(&key)?;
        // Keep both files: unlinking a lock file can split contenders across
        // different inodes. Closing it releases kernel ownership on every
        // return path and after process termination.
        Ok(Self {
            _global: global,
            _key: key,
        })
    }
}

struct CredentialStoreBarrier {
    _global: File,
}

impl CredentialStoreBarrier {
    fn acquire() -> Result<Self> {
        let paths = daemon::paths()?;
        daemon::ensure_private_dir(&paths.dir)?;
        Self::acquire_in(&paths.dir)
    }

    fn acquire_in(dir: &Path) -> Result<Self> {
        let global = open_lock(dir, STORE_LOCK_FILE)?;
        fs4::FileExt::lock(&global)?;
        Ok(Self { _global: global })
    }
}

fn open_lock(dir: &Path, name: &str) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(name))?)
}

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

/// Attributes identifying keyhold's session item by owner, kind and keygrip.
fn item_attributes(keygrip: &str) -> HashMap<&str, &str> {
    HashMap::from([
        ("application", APPLICATION_ATTRIBUTE),
        ("kind", KIND_ATTRIBUTE),
        ("keygrip", keygrip),
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
    fn lock_transaction(
        &self,
        keygrip: &str,
    ) -> Result<Box<dyn CredentialTransactionGuard>> {
        Ok(Box::new(CredentialTransactionLock::acquire(keygrip)?))
    }

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
                    item_attributes(keygrip),
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
        let _barrier = CredentialStoreBarrier::acquire()?;
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
    use std::{
        io::{BufRead as _, BufReader, Read as _, Write as _},
        process::{Command, Stdio},
    };

    use super::*;

    const LOCK_TEST_ENV: &str = "KEYHOLD_CREDENTIAL_LOCK_CHILD_DIR";
    const TEST_KEYGRIP: &str = "0123456789ABCDEF0123456789ABCDEF01234567";
    const OTHER_KEYGRIP: &str = "89ABCDEF0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn credential_transaction_process_child() {
        let Some(dir) = std::env::var_os(LOCK_TEST_ENV) else {
            return;
        };
        let _guard = CredentialTransactionLock::acquire_in(
            Path::new(&dir),
            TEST_KEYGRIP,
        )
        .expect("child acquires credential transaction");
        println!("KEYHOLD_CREDENTIAL_LOCKED");
        std::io::stdout().flush().unwrap();
        let _ = std::io::stdin().read(&mut [0_u8; 1]);
    }

    #[test]
    fn process_exit_releases_transaction_without_removing_lockfiles() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "credential::tests::credential_transaction_process_child",
                "--nocapture",
            ])
            .env(LOCK_TEST_ENV, dir.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let mut lines = BufReader::new(stdout).lines();
        assert!(
            lines.any(|line| line
                .unwrap()
                .contains("KEYHOLD_CREDENTIAL_LOCKED")),
            "child exited before acquiring the lock"
        );

        let path = dir.path().join(format!("credential-{TEST_KEYGRIP}.lock"));
        let global_path = dir.path().join("credential-store.lock");
        let global = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&global_path)
            .unwrap();
        let contender = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        assert!(
            fs4::FileExt::try_lock(&contender).is_err(),
            "child did not hold the lock"
        );
        assert!(
            fs4::FileExt::try_lock(&global).is_err(),
            "child did not hold the global shared lock"
        );
        child.kill().unwrap();
        assert!(!child.wait().unwrap().success(), "child was not terminated");
        fs4::FileExt::try_lock(&contender)
            .expect("process exit left stale lock ownership");
        fs4::FileExt::try_lock(&global)
            .expect("process exit left stale global lock ownership");
        assert!(path.exists(), "lock file was unexpectedly removed");
        assert!(
            global_path.exists(),
            "global lock file was unexpectedly removed"
        );
    }

    #[test]
    fn transaction_holds_shared_global_then_exclusive_key_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let transaction =
            CredentialTransactionLock::acquire_in(dir.path(), TEST_KEYGRIP)
                .unwrap();
        let global = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("credential-store.lock"))
            .unwrap();
        let key = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join(format!("credential-{TEST_KEYGRIP}.lock")))
            .unwrap();
        let other_global = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("credential-store.lock"))
            .unwrap();
        let other_key =
            open_lock(dir.path(), &format!("credential-{OTHER_KEYGRIP}.lock"))
                .unwrap();

        assert!(fs4::FileExt::try_lock(&global).is_err());
        assert!(fs4::FileExt::try_lock(&key).is_err());
        fs4::FileExt::try_lock_shared(&other_global).unwrap();
        fs4::FileExt::try_lock(&other_key).unwrap();
        drop(transaction);
    }

    #[test]
    fn exclusive_store_barrier_blocks_new_transactions() {
        let dir = tempfile::TempDir::new().unwrap();
        let barrier = CredentialStoreBarrier::acquire_in(dir.path()).unwrap();
        let global = OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join("credential-store.lock"))
            .unwrap();

        assert!(fs4::FileExt::try_lock_shared(&global).is_err());
        drop(barrier);
        fs4::FileExt::try_lock_shared(&global).unwrap();
    }

    #[test]
    fn item_attributes_use_keygrip_as_the_canonical_identity() {
        let attrs = item_attributes("GRIP");
        assert_eq!(attrs.get("application"), Some(&"keyhold"));
        assert_eq!(attrs.get("kind"), Some(&"gpg-passphrase"));
        assert_eq!(attrs.get("keygrip"), Some(&"GRIP"));
        assert!(!attrs.contains_key("fingerprint"));
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
