//! `network-orchestrator-helper`: the privileged macOS service that will own
//! routes, interfaces and DNS on behalf of the native client
//! (`docs/plans/2026-09-30-14-macos-privileged-helper.md`).
//!
//! It speaks the shared `daemon_protocol` over a Unix socket. This crate holds
//! the transport, peer verification and request dispatch; tunnel executors are
//! added behind [`server::Handler`] and are never reachable by an
//! unverified peer.

pub mod peer;
pub mod server;
pub mod service;

/// Directory of the helper socket; created root-owned and world-searchable.
pub const SOCKET_DIR: &str = "/var/run/network-orchestrator";
/// Socket the native client connects to.
pub const SOCKET_PATH: &str = "/var/run/network-orchestrator/helper.sock";
/// Root-owned persistent state (ownership journal).
pub const STATE_DIR: &str = "/var/db/network-orchestrator";
