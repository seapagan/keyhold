//! Subprocess-level integration tests for the GPG tool layer, using
//! self-contained fake `gpg`/`gpgconf`/`gpg-connect-agent` scripts with
//! their scratch directory baked in (no environment mutation, so the
//! tests are parallel-safe even under plain `cargo test`).

use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf, process::Command};

use keyhold::gpg::{
    AgentKeyState, Gpg, KeyProtection, PingMode, SigningTarget,
};
use tempfile::TempDir;

const PRIMARY_FPR: &str = "C1D6F8E1B1E8D5FBFF34ACE08FACE96FA6D9DB48";
const PRIMARY_GRIP: &str = "554FB2F0C3F74666FEE23A13A628C32C2310EBAF";
const SUB_FPR: &str = "54BD088B3AC62D6BC6E4F888212181504E7D2CD7";
const SUB_GRIP: &str = "4B88DD924C36F6085738E95FB112B482E33A3220";
const SUB2_FPR: &str = "97CF31DBA5F6012341995ED8F3C83A12ADCE45A1";
const SUB2_GRIP: &str = "F097020B875D80D64C742456496ECA8F47CED17F";

/// Scratch directory with fake tools whose paths are baked into the
/// scripts themselves.
struct Tools {
    _dir: TempDir,
    gpg: Gpg,
    gpg_log: PathBuf,
    ca_log: PathBuf,
    root: PathBuf,
}

impl Tools {
    fn new() -> Self {
        let dir = TempDir::new().expect("scratch dir");
        let root = dir.path().to_path_buf();
        let gpg_path = root.join("fake-gpg");
        let gpgconf_path = root.join("fake-gpgconf");
        let ca_path = root.join("fake-connect-agent");
        let gpg_log = root.join("gpg.log");
        let ca_log = root.join("ca.log");

        fs::write(
            &gpg_path,
            format!(
                "#!/bin/sh\n\
                 list=0; loopback=0; background=0\n\
                 for a in \"$@\"; do\n\
                   [ \"$a\" = --list-secret-keys ] && list=1\n\
                   [ \"$a\" = --passphrase-fd ] && loopback=1\n\
                   [ \"$a\" = cancel ] && background=1\n\
                 done\n\
                 echo \"$*\" >> {log}\n\
                 if [ \"$list\" = 1 ]; then cat {root}/keys.txt; exit 0; fi\n\
                 if [ \"$background\" = 1 ] && [ -e {root}/lock ]; then\n\
                   echo '[GNUPG:] KEY_CONSIDERED {PRIMARY_FPR} 0'\n\
                   echo 'gpg: signing failed: Operation cancelled' >&2\n\
                   exit 2\n\
                 fi\n\
                 if [ \"$loopback\" = 1 ]; then\n\
                   IFS= read -r supplied\n\
                   expected=$(cat {root}/passphrase)\n\
                   if [ \"$supplied\" != \"$expected\" ]; then\n\
                     echo 'gpg: signing failed: Bad passphrase' >&2\n\
                     exit 2\n\
                   fi\n\
                 fi\n\
                 if [ -e {root}/fail-all ]; then exit 2; fi\n\
                 echo '[GNUPG:] KEY_CONSIDERED {PRIMARY_FPR} 0'\n\
                 if [ \"$background\" != 1 ] && [ \"$loopback\" != 1 ] && \
                    [ ! -e {root}/cached ]; then\n\
                   echo '[GNUPG:] PINENTRY_LAUNCHED 2718 gnome3 1.3.2 x'\n\
                 fi\n\
                 echo '[GNUPG:] SIG_CREATED D 22 10 00 1789136997 {SUB2_FPR}'\n\
                 exit 0\n",
                log = gpg_log.display(),
                root = root.display(),
            ),
        )
        .expect("write fake gpg");
        fs::set_permissions(&gpg_path, fs::Permissions::from_mode(0o755))
            .expect("chmod fake gpg");

        fs::write(
            &gpgconf_path,
            format!(
                "#!/bin/sh\n\
                 if [ -e {root}/gpgconf-fail ]; then exit 1; fi\n\
                 read def max < {root}/ttls\n\
                 printf '%s\\n' \
                 \"default-cache-ttl:24:0:expire cached PINs after N seconds:3:3:N:$def::\" \
                 \"max-cache-ttl:24:2:set maximum PIN cache lifetime to N seconds:3:3:N:$max::\"\n",
                root = root.display(),
            ),
        )
        .expect("write fake gpgconf");
        fs::set_permissions(&gpgconf_path, fs::Permissions::from_mode(0o755))
            .expect("chmod fake gpgconf");

        fs::write(
            &ca_path,
            format!(
                "#!/bin/sh\n\
                 echo \"$*\" >> {ca_log}\n\
                 cmd=$1\n\
                 if [ -e {root}/malformed-ca ]; then echo 'gibberish, not assuan'; exit 0; fi\n\
                 if [ -e {root}/bare-ok ]; then echo OK; exit 0; fi\n\
                 case \"$cmd\" in\n\
                   'CLEAR_PASSPHRASE '*)\n\
                     if [ -e {root}/fail-clear ]; then\n\
                       echo 'ERR 67109139 Unknown IPC command <GPG Agent>'; exit 0; fi\n\
                     echo OK; exit 0;;\n\
                   KEYINFO\\ *)\n\
                     if [ -e {root}/fail-keyinfo ]; then\n\
                       echo 'ERR 67109139 Unknown IPC command <GPG Agent>'; exit 0; fi\n\
                     grip=$(echo \"$cmd\" | cut -d' ' -f2)\n\
                     case \"$grip\" in\n\
                       0000000000000000000000000000000000000000)\n\
                         echo 'ERR 67108891 Not found <GPG Agent>'; exit 0;;\n\
                     esac\n\
                     prot=P\n\
                     [ -f {root}/prot ] && prot=$(cat {root}/prot)\n\
                     cached=-\n\
                     [ -e {root}/key-cached ] && cached=1\n\
                     echo \"S KEYINFO $grip D - - $cached $prot - - -\"\n\
                     echo OK\n\
                     exit 0;;\n\
                 esac\n\
                 echo OK\n",
                ca_log = ca_log.display(),
                root = root.display(),
            ),
        )
        .expect("write fake connect-agent");
        fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o755))
            .expect("chmod fake connect-agent");

        let tools = Self {
            gpg: Gpg::with_tools(gpg_path, Some(gpgconf_path), Some(ca_path)),
            _dir: dir,
            gpg_log,
            ca_log,
            root,
        };
        tools.set_keys(&default_keys());
        tools.set_ttls("600 7200");
        tools.set_passphrase("seekrit");
        tools
    }

    fn set_keys(&self, fixture: &str) {
        fs::write(self.root.join("keys.txt"), fixture).unwrap();
    }

    fn set_ttls(&self, value: &str) {
        fs::write(self.root.join("ttls"), value).unwrap();
    }

    fn set_passphrase(&self, value: &str) {
        fs::write(self.root.join("passphrase"), value).unwrap();
    }

    fn marker(&self, name: &str) {
        fs::write(self.root.join(name), b"1").unwrap();
    }

    fn gpg_log(&self) -> String {
        fs::read_to_string(&self.gpg_log).unwrap_or_default()
    }

    fn ca_log(&self) -> String {
        fs::read_to_string(&self.ca_log).unwrap_or_default()
    }
}

/// Primary with two signing subkeys; the newest signs by default.
fn default_keys() -> String {
    format!(
        "sec:u:255:22:8FACE96FA6D9DB48:1789136976:::u:::scSC:::+::ed25519:::0:\n\
         fpr:::::::::{PRIMARY_FPR}:\n\
         grp:::::::::{PRIMARY_GRIP}:\n\
         uid:u::::1789136976::78F8::keyhold-test::::::::::0:\n\
         ssb:u:255:22:212181504E7D2CD7:1789136986::::::s:::+::ed25519::\n\
         fpr:::::::::{SUB_FPR}:\n\
         grp:::::::::{SUB_GRIP}:\n\
         ssb:u:255:22:F3C83A12ADCE45A1:1789137207::::::s:::+::ed25519::\n\
         fpr:::::::::{SUB2_FPR}:\n\
         grp:::::::::{SUB2_GRIP}:\n"
    )
}

fn target(fpr: &str, grip: &str) -> SigningTarget {
    SigningTarget {
        fingerprint: fpr.to_string(),
        keygrip: Some(grip.to_string()),
    }
}

#[test]
fn foreground_use_resolves_the_actual_signing_subkey() {
    let tools = Tools::new();
    let used = tools.gpg.use_key(None, PingMode::Foreground).unwrap();
    // The fake's SIG_CREATED names the newest signing subkey, and the
    // fingerprint must map to that subkey's own keygrip — never the
    // primary's.
    assert_eq!(
        used.target,
        Some(target(SUB2_FPR, SUB2_GRIP)),
        "target mismatch: {:?}",
        used.target
    );
    assert_eq!(used.pinentry_launched, Some(true));
}

#[test]
fn cached_key_reports_no_pinentry() {
    let tools = Tools::new();
    tools.marker("cached");
    let used = tools.gpg.use_key(None, PingMode::Foreground).unwrap();
    assert_eq!(used.pinentry_launched, Some(false));
    assert!(used.target.is_some());
}

#[test]
fn background_use_works_when_unlocked() {
    let tools = Tools::new();
    let used = tools.gpg.use_key(None, PingMode::Background).unwrap();
    assert_eq!(used.target, Some(target(SUB2_FPR, SUB2_GRIP)));
}

#[test]
fn background_use_on_locked_key_fails_like_today() {
    let tools = Tools::new();
    tools.marker("lock");
    let err = tools
        .gpg
        .use_key(None, PingMode::Background)
        .unwrap_err()
        .to_string();
    assert!(err.contains("cancelled"), "{err}");
}

#[test]
fn probe_target_resolves_locked_key_via_listing() {
    let tools = Tools::new();
    tools.marker("lock");
    // Locked: no SIG_CREATED, but KEY_CONSIDERED + listing resolve the
    // key GPG's default selection would use (newest signing subkey).
    let probed = tools.gpg.probe_target(None).unwrap();
    assert_eq!(probed, target(SUB2_FPR, SUB2_GRIP));
}

#[test]
fn probe_target_honours_explicit_subkey_selector() {
    let tools = Tools::new();
    tools.marker("lock");
    let probed = tools.gpg.probe_target(Some(SUB_FPR)).unwrap();
    assert_eq!(probed, target(SUB_FPR, SUB_GRIP));
    let probed = tools
        .gpg
        .probe_target(Some(&format!("{PRIMARY_FPR}!")))
        .unwrap();
    assert_eq!(probed, target(PRIMARY_FPR, PRIMARY_GRIP));
}

#[test]
fn probe_target_on_unlocked_key_uses_sig_created() {
    let tools = Tools::new();
    let probed = tools.gpg.probe_target(None).unwrap();
    assert_eq!(probed, target(SUB2_FPR, SUB2_GRIP));
}

#[test]
fn probe_target_skips_expired_subkeys() {
    let tools = Tools::new();
    tools.marker("lock");
    tools.set_keys(&format!(
        "sec:u:255:22:8FACE96FA6D9DB48:1789136976:::u:::scSC:::+::ed25519:::0:\n\
         fpr:::::::::{PRIMARY_FPR}:\n\
         grp:::::::::{PRIMARY_GRIP}:\n\
         ssb:e:255:22:212181504E7D2CD7:1789136986::::::s:::+::ed25519::\n\
         fpr:::::::::{SUB_FPR}:\n\
         grp:::::::::{SUB_GRIP}:\n"
    ));
    // The only subkey is expired: the primary signs.
    let probed = tools.gpg.probe_target(None).unwrap();
    assert_eq!(probed, target(PRIMARY_FPR, PRIMARY_GRIP));
}

#[test]
fn probe_target_fails_when_gpg_reports_no_key() {
    let tools = Tools::new();
    tools.marker("fail-all");
    let err = tools.gpg.probe_target(None).unwrap_err().to_string();
    // A hard failure with no KEY_CONSIDERED record is an error, not a
    // guess.
    assert!(
        err.contains("could not resolve the GPG signing key"),
        "{err}"
    );
}

#[test]
fn cache_policy_reads_effective_ttls() {
    let tools = Tools::new();
    tools.set_ttls("600 7200");
    let policy = tools.gpg.cache_policy().unwrap();
    assert_eq!(
        policy,
        keyhold::gpg::CachePolicy {
            default_ttl: std::time::Duration::from_secs(600),
            max_ttl: std::time::Duration::from_secs(7200),
        }
    );
}

#[test]
fn cache_policy_reports_gpgconf_failure() {
    let tools = Tools::new();
    tools.marker("gpgconf-fail");
    let err = tools.gpg.cache_policy().unwrap_err().to_string();
    assert!(err.contains("cache TTL"), "{err}");
}

#[test]
fn cache_policy_requires_the_tool() {
    let tools = Tools::new();
    let gpg = Gpg::with_tools(
        tools.root.join("fake-gpg"),
        None,
        Some(tools.root.join("fake-connect-agent")),
    );
    let err = gpg.cache_policy().unwrap_err().to_string();
    assert!(err.contains("gpgconf"), "{err}");
}

#[test]
fn key_state_reads_cached_locked_and_clear_entries() {
    let tools = Tools::new();
    let state = tools.gpg.key_state(SUB2_GRIP).unwrap();
    assert_eq!(
        state,
        AgentKeyState {
            cached: false,
            protection: KeyProtection::Passphrase
        }
    );
    tools.marker("key-cached");
    let state = tools.gpg.key_state(SUB2_GRIP).unwrap();
    assert_eq!(
        state,
        AgentKeyState {
            cached: true,
            protection: KeyProtection::Passphrase
        }
    );
    fs::write(tools.root.join("prot"), "C").unwrap();
    let state = tools.gpg.key_state(SUB2_GRIP).unwrap();
    assert_eq!(
        state,
        AgentKeyState {
            cached: true,
            protection: KeyProtection::Clear
        }
    );
}

#[test]
fn key_state_of_unknown_grip_is_locked_and_unknown() {
    let tools = Tools::new();
    let state = tools
        .gpg
        .key_state("0000000000000000000000000000000000000000")
        .unwrap();
    assert_eq!(
        state,
        AgentKeyState {
            cached: false,
            protection: KeyProtection::Unknown
        }
    );
}

#[test]
fn clear_passphrase_clears_only_the_given_keygrip() {
    let tools = Tools::new();
    tools.gpg.clear_passphrase(SUB2_GRIP).unwrap();
    let log = tools.ca_log();
    assert!(
        log.contains(&format!("CLEAR_PASSPHRASE --mode=normal {SUB2_GRIP}")),
        "{log}"
    );
    // Keygrip-specific only: no agent restart or global flush commands.
    assert!(!log.contains("RELOADAGENT"), "{log}");
    assert!(!log.contains("KILLAGENT"), "{log}");
    assert_eq!(log.lines().count(), 1, "{log}");
}

/// Regression: `gpg-connect-agent` exits 0 even when the agent rejects
/// the command with an Assuan `ERR` line. A rejected clear must be an
/// error, never success: stored mode relies on the clear establishing
/// a deterministic cache epoch.
#[test]
fn clear_passphrase_fails_when_the_agent_returns_err_despite_exit_zero() {
    let tools = Tools::new();
    tools.marker("fail-clear");
    let err = tools.gpg.clear_passphrase(SUB2_GRIP).unwrap_err();
    assert!(
        matches!(err, keyhold::error::Error::AgentCommand(_)),
        "{err}"
    );
    assert!(
        err.to_string().contains("ERR 67109139"),
        "error lacks the agent's answer: {err}"
    );
    // The fake tool really ran and really exited 0.
    let log = tools.ca_log();
    assert!(
        log.contains(&format!("CLEAR_PASSPHRASE --mode=normal {SUB2_GRIP}")),
        "{log}"
    );
}

/// A response with no terminal `OK`/`ERR` line is malformed and must
/// not silently pass as success.
#[test]
fn clear_passphrase_rejects_a_malformed_agent_response() {
    let tools = Tools::new();
    tools.marker("malformed-ca");
    let err = tools.gpg.clear_passphrase(SUB2_GRIP).unwrap_err();
    assert!(
        matches!(err, keyhold::error::Error::AgentCommand(_)),
        "{err}"
    );
    assert!(err.to_string().contains("malformed"), "{err}");
}

#[test]
fn key_state_reports_an_agent_rejection_despite_exit_zero() {
    let tools = Tools::new();
    tools.marker("fail-keyinfo");
    assert!(
        tools.gpg.key_state(SUB2_GRIP).is_err(),
        "a rejected KEYINFO became a state"
    );
}

#[test]
fn key_state_rejects_a_malformed_agent_response() {
    let tools = Tools::new();
    tools.marker("malformed-ca");
    assert!(
        tools.gpg.key_state(SUB2_GRIP).is_err(),
        "a malformed reply became a state"
    );
}

/// `OK` without a `S KEYINFO` record is an ambiguous answer, not a
/// usable state.
#[test]
fn key_state_rejects_ok_without_a_keyinfo_record() {
    let tools = Tools::new();
    tools.marker("bare-ok");
    assert!(
        tools.gpg.key_state(SUB2_GRIP).is_err(),
        "a record-less OK became a state"
    );
}

#[test]
fn loopback_sign_unlocks_the_exact_key_without_leaking_the_secret() {
    let tools = Tools::new();
    let t = target(SUB2_FPR, SUB2_GRIP);
    tools
        .gpg
        .use_key_with_passphrase(&t, b"seekrit")
        .expect("valid passphrase unlocks");
    let log = tools.gpg_log();
    // Exact-key semantics and stdin transport only.
    assert!(log.contains(&format!("--local-user {SUB2_FPR}!")), "{log}");
    assert!(log.contains("--passphrase-fd 0"), "{log}");
    assert!(log.contains("--pinentry-mode loopback"), "{log}");
    // The secret never reaches the command line (or any log).
    assert!(!log.contains("seekrit"), "passphrase leaked: {log}");
}

#[test]
fn loopback_sign_rejects_a_bad_passphrase() {
    let tools = Tools::new();
    let t = target(SUB2_FPR, SUB2_GRIP);
    let err = tools.gpg.use_key_with_passphrase(&t, b"wrong").unwrap_err();
    assert!(matches!(err, keyhold::error::Error::BadPassphrase), "{err}");
    assert!(!tools.gpg_log().contains("wrong"));
}

#[test]
fn loopback_sign_rejects_newlines_before_spawning_gpg() {
    let tools = Tools::new();
    let t = target(SUB2_FPR, SUB2_GRIP);
    for bad in ["with\nnewline".as_bytes(), "with\rnewline".as_bytes()] {
        let err = tools.gpg.use_key_with_passphrase(&t, bad).unwrap_err();
        assert!(err.to_string().contains("newline"), "{err}");
    }
    // Rejected before any subprocess ran.
    assert_eq!(tools.gpg_log(), "");
}

#[test]
fn loopback_sign_rejects_empty_passphrase() {
    let tools = Tools::new();
    let t = target(SUB2_FPR, SUB2_GRIP);
    let err = tools.gpg.use_key_with_passphrase(&t, b"").unwrap_err();
    assert!(err.to_string().contains("empty"), "{err}");
    assert_eq!(tools.gpg_log(), "");
}

/// Sanity: the fake tooling itself must be executable (guards against
/// script-generation drift breaking every other test confusingly).
#[test]
fn fake_tools_are_executable() {
    let tools = Tools::new();
    let ok = Command::new(tools.root.join("fake-gpg"))
        .arg("--batch")
        .output()
        .expect("run fake gpg");
    assert!(ok.status.success());
}
