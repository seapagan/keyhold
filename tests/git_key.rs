//! `--git-key` / `git_key = true` integration tests: Git resolution,
//! key-selection precedence, side-effect ordering and status display.
//!
//! Every test uses fully isolated Git configuration (temporary `HOME`,
//! no system/global config inheritance) so the developer's real
//! `~/.gitconfig` is never read.

mod common;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use common::TestEnv;
use tempfile::TempDir;

/// A keyhold command with Git fully isolated: temporary `HOME`, system
/// config disabled, `GIT_CONFIG_GLOBAL` cleared, run from `workdir`.
fn git_isolated(env: &TestEnv, args: &[&str], workdir: &Path) -> Command {
    let mut cmd = env.keyhold(args);
    cmd.env("HOME", workdir)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_GLOBAL")
        .current_dir(workdir);
    cmd
}

/// Write the global Git config verbatim (under the isolated `HOME`).
fn global_config(home: &Path, body: &str) {
    fs::write(home.join(".gitconfig"), body).expect("write .gitconfig");
}

/// Write a global Git config with `user.signingkey = <key>`.
fn global_signing_key(home: &Path, key: &str) {
    global_config(home, &format!("[user]\n\tsigningkey = {key}\n"));
}

/// Set a repository-local Git config value.
fn local_config(repo: &Path, name: &str, value: &str) {
    let status = Command::new("git")
        .args(["config", name, value])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_GLOBAL")
        .current_dir(repo)
        .status()
        .expect("run git config");
    assert!(status.success(), "git config failed");
}

/// Create a Git repository (no signing key unless `key` is given).
fn init_repo(key: Option<&str>) -> TempDir {
    let dir = tempfile::TempDir::new().expect("temp repo");
    let status = Command::new("git")
        .args(["init", "--quiet"])
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env_remove("GIT_CONFIG_GLOBAL")
        .current_dir(dir.path())
        .status()
        .expect("run git init");
    assert!(status.success(), "git init failed");
    if let Some(key) = key {
        let status = Command::new("git")
            .args(["config", "user.signingkey", key])
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env_remove("GIT_CONFIG_GLOBAL")
            .current_dir(dir.path())
            .status()
            .expect("run git config");
        assert!(status.success(), "git config failed");
    }
    dir
}

/// Neutral working directory with no Git repository.
fn neutral_dir() -> TempDir {
    tempfile::TempDir::new().expect("neutral dir")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

#[test]
fn global_signing_key_is_used() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "DEADBEEF");

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));

    // The resolved key is used for the foreground sign and shown tagged.
    assert!(
        env.gpg_log().contains("--local-user DEADBEEF"),
        "{}",
        env.gpg_log()
    );
    assert!(env.status().contains("Key        DEADBEEF (git)"));
}

#[test]
fn local_repo_signing_key_overrides_global() {
    let env = TestEnv::new();
    let repo = init_repo(Some("LOCALKEY"));
    global_signing_key(repo.path(), "GLOBALKEY");

    let out = git_isolated(&env, &["on", "--git-key"], repo.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = env.status();
    assert!(text.contains("Key        LOCALKEY (git)"), "{text}");
    assert!(env.gpg_log().contains("--local-user LOCALKEY"));
}

#[test]
fn repo_without_local_key_uses_global() {
    let env = TestEnv::new();
    let repo = init_repo(None);
    global_signing_key(repo.path(), "GLOBALKEY");

    let out = git_isolated(&env, &["on", "--git-key"], repo.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(env.status().contains("Key        GLOBALKEY (git)"));
}

#[test]
fn git_output_whitespace_is_trimmed() {
    let env = TestEnv::new();
    let home = neutral_dir();
    // A trailing newline comes back from `git config --get`; the value
    // itself must reach GPG trimmed.
    global_signing_key(home.path(), "PADDEDKEY");

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    // The newline from `git config --get` output must not leak into the
    // selector: the fake gpg log would then contain two lines.
    let log = env.gpg_log();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 1, "newline leaked into key: {log:?}");
    assert!(lines[0].ends_with("--local-user PADDEDKEY"), "{log}");
    assert!(env.status().contains("Key        PADDEDKEY (git)"));
}

#[test]
fn unset_format_defaults_to_openpgp() {
    // Already implied by every other test (no [gpg] section), but pin the
    // default explicitly: gpg.format unset + valid signingkey succeeds.
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "DEFAULTKEY");

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(env.status().contains("Key        DEFAULTKEY (git)"));
}

#[test]
fn explicit_openpgp_format_succeeds() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_config(
        home.path(),
        "[gpg]\n\tformat = openpgp\n[user]\n\tsigningkey = OPENPGPKEY\n",
    );

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(env.gpg_log().contains("--local-user OPENPGPKEY"));
    assert!(env.status().contains("Key        OPENPGPKEY (git)"));
}

#[test]
fn ssh_format_is_rejected_without_side_effects() {
    let env = TestEnv::new();
    // A healthy default hold first: the rejection must not disturb it.
    env.succeed(&["on"]);
    assert!(env.status().contains("Key        default"));

    let home = neutral_dir();
    global_config(
        home.path(),
        "[gpg]\n\tformat = ssh\n[user]\n\tsigningkey = /home/x/.ssh/id_ed25519\n",
    );

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = stderr(&out);
    assert!(stderr.contains("Git signing format is 'ssh'"), "{stderr}");
    assert!(stderr.contains("requires OpenPGP"), "{stderr}");

    // No new foreground GPG call, no On request: the existing hold and
    // daemon state are unchanged.
    let text = env.status();
    assert!(text.contains("Hold       on"), "{text}");
    assert!(text.contains("Key        default"), "{text}");
    assert!(!env.gpg_log().contains("id_ed25519"), "{}", env.gpg_log());
}

#[test]
fn x509_format_is_rejected() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_config(
        home.path(),
        "[gpg]\n\tformat = x509\n[user]\n\tsigningkey = /cn=Someone\n",
    );

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("Git signing format is 'x509'"),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.gpg_log(), "");
    assert!(env.status().contains("Daemon     stopped"));
}

#[test]
fn unknown_format_is_rejected() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_config(
        home.path(),
        "[gpg]\n\tformat = smime9\n[user]\n\tsigningkey = WHATEVER\n",
    );

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("Git signing format is 'smime9'"),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.gpg_log(), "");
}

#[test]
fn local_format_overrides_global() {
    let env = TestEnv::new();
    let repo = init_repo(Some("LOCALKEY"));
    // Global says ssh, the repository overrides back to openpgp: Git's
    // own effective config wins, so Git-key mode succeeds.
    global_config(repo.path(), "[gpg]\n\tformat = ssh\n");
    local_config(repo.path(), "gpg.format", "openpgp");

    let out = git_isolated(&env, &["on", "--git-key"], repo.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(env.status().contains("Key        LOCALKEY (git)"));
}

#[test]
fn local_ssh_format_overrides_global_openpgp() {
    let env = TestEnv::new();
    let repo = init_repo(Some("LOCALKEY"));
    global_config(repo.path(), "[gpg]\n\tformat = openpgp\n");
    local_config(repo.path(), "gpg.format", "ssh");

    let out = git_isolated(&env, &["on", "--git-key"], repo.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("Git signing format is 'ssh'"),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.gpg_log(), "");
}

#[test]
fn missing_signing_key_fails_without_side_effects() {
    let env = TestEnv::new();
    let home = neutral_dir();

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = stderr(&out);
    assert!(
        stderr.contains("no Git signing key is configured"),
        "{stderr}"
    );

    // No daemon was started, no GPG call was made.
    assert_eq!(
        env.status(),
        "Keyhold status\n\nDaemon     stopped\nHold       off\n"
    );
    assert_eq!(env.gpg_log(), "");
}

#[test]
fn failed_git_resolution_leaves_existing_hold_untouched() {
    let env = TestEnv::new();
    // A healthy default hold first (with normal keyhold env, no git env).
    env.succeed(&["on"]);
    assert!(env.status().contains("Key        default"));

    let nowhere = neutral_dir();
    let out = git_isolated(&env, &["on", "--git-key"], nowhere.path())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(stderr(&out).contains("no Git signing key is configured"));

    // The existing hold is unchanged.
    let text = env.status();
    assert!(text.contains("Hold       on"), "{text}");
    assert!(text.contains("Key        default"), "{text}");
}

#[test]
fn missing_git_executable_is_reported() {
    let env = TestEnv::new();
    let home = neutral_dir();
    // An empty PATH directory: git cannot be found (KEYHOLD_GPG is
    // absolute, so keyhold's own GPG detection is unaffected).
    let empty_path = tempfile::TempDir::new().unwrap();

    let mut cmd = git_isolated(&env, &["on", "--git-key"], home.path());
    cmd.env("PATH", empty_path.path());
    let out = cmd.output().unwrap();
    assert!(!out.status.success());
    assert!(
        stderr(&out).contains("could not execute git"),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.gpg_log(), "");
    assert!(env.status().contains("Daemon     stopped"));
}

#[test]
fn key_and_git_key_flags_conflict() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "DEADBEEF");

    let out =
        git_isolated(&env, &["on", "--key", "ABCD", "--git-key"], home.path())
            .output()
            .unwrap();
    assert_eq!(out.status.code(), Some(2), "{}", stderr(&out));
    assert!(
        stderr(&out).contains("cannot be used with"),
        "{}",
        stderr(&out)
    );
    assert_eq!(env.gpg_log(), "");
}

#[test]
fn config_git_key_acts_like_the_flag() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "CFGKEY");
    fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "git_key = true\n",
    )
    .unwrap();

    let out = git_isolated(&env, &["on"], home.path()).output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    assert!(env.status().contains("Key        CFGKEY (git)"));
}

#[test]
fn cli_key_overrides_config_git_key() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "CFGKEY");
    fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "git_key = true\n",
    )
    .unwrap();

    let out = git_isolated(&env, &["on", "--key", "OVERRIDE"], home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = env.status();
    assert!(text.contains("Key        OVERRIDE"), "{text}");
    assert!(!text.contains("(git)"), "{text}");
    assert!(env.gpg_log().contains("--local-user OVERRIDE"));
}

#[test]
fn cli_git_key_overrides_configured_static_key() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "GITKEY");
    fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "key = \"CONFKEY\"\n",
    )
    .unwrap();

    let out = git_isolated(&env, &["on", "--git-key"], home.path())
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", stderr(&out));
    let text = env.status();
    assert!(text.contains("Key        GITKEY (git)"), "{text}");
    assert!(env.gpg_log().contains("--local-user GITKEY"));
}

#[test]
fn config_key_plus_git_key_is_rejected() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "DEADBEEF");
    fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "key = \"ABCD\"\ngit_key = true\n",
    )
    .unwrap();

    let out = git_isolated(&env, &["on"], home.path()).output().unwrap();
    assert!(!out.status.success());
    let stderr = stderr(&out);
    assert!(
        stderr.contains("invalid configuration")
            && stderr.contains("key-selection strategy"),
        "{stderr}"
    );
    // Failed before any side effect.
    assert_eq!(env.gpg_log(), "");
    assert!(env.status().contains("Daemon     stopped"));
}

#[test]
fn git_tag_is_styled_and_aligned() {
    let env = TestEnv::new();
    let home = neutral_dir();
    global_signing_key(home.path(), "DEADBEEF");

    let mut cmd = git_isolated(&env, &["on", "--git-key"], home.path());
    cmd.env_remove("NO_COLOR").env("FORCE_COLOR", "1");
    let out = cmd.output().unwrap();
    assert!(out.status.success(), "{}", stderr(&out));

    let mut cmd = git_isolated(&env, &["status"], home.path());
    cmd.env_remove("NO_COLOR").env("FORCE_COLOR", "1");
    let out = cmd.output().unwrap();
    let styled = stdout(&out);
    assert!(styled.contains('\x1b'), "not styled: {styled:?}");

    let plain = strip_ansi(&styled);
    let key_row = plain
        .lines()
        .find(|l| l.starts_with("Key        "))
        .expect("key row");
    assert_eq!(key_row, "Key        DEADBEEF (git)", "{plain}");
}

/// Remove ANSI SGR sequences for visible-layout assertions.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' && chars.next() == Some('[') {
            for c in chars.by_ref() {
                if c == 'm' {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Config `key` alone still selects an explicit (untagged) key.
#[test]
fn config_static_key_is_not_tagged_git() {
    let env = TestEnv::new();
    fs::create_dir_all(env.config.path().join("keyhold")).unwrap();
    fs::write(
        env.config.path().join("keyhold").join("config.toml"),
        "key = \"CONFONLY\"\n",
    )
    .unwrap();

    env.succeed(&["on"]);
    let text = env.status();
    assert!(text.contains("Key        CONFONLY"), "{text}");
    assert!(!text.contains("(git)"), "{text}");
}
