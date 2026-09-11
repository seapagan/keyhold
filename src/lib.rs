//! `keyhold` — keep a GPG private key cached in `gpg-agent` while you
//! explicitly allow it.
//!
//! # Model
//!
//! * `keyhold on` runs one foreground GPG signing ping with normal pinentry
//!   behaviour (so the key can be unlocked if needed), then tells the
//!   resident daemon to keep pinging periodically.
//! * The daemon pings with `--pinentry-mode cancel`: if the GPG cache has
//!   expired, the ping fails promptly instead of opening an unattended
//!   pinentry, and the hold turns itself off (visible via `keyhold status`).
//! * `keyhold off` stops the pings and leaves the cache to expire naturally
//!   according to `gpg-agent`'s normal idle TTL.
//!
//! keyhold has two operating modes. In the default mode it never handles
//! the passphrase, never uses loopback pinentry, and never edits GnuPG
//! configuration: it only refreshes `gpg-agent`'s normal idle cache
//! timeout by genuinely using the key. The explicitly opted-in session
//! credential mode (`keyhold on --store-passphrase`) additionally stores
//! the passphrase in the Linux Secret Service **session** collection so
//! keyhold can recreate the selected key's cache entry before GnuPG's
//! absolute `max-cache-ttl` expires; see [`credential`] for that mode's
//! contract.

pub mod cli;
pub mod config;
pub mod credential;
pub mod daemon;
pub mod error;
pub mod git;
pub mod gpg;
pub mod ipc;
pub mod presentation;
pub mod state;
