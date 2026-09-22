//! `network-orchestrator-daemon`: the privileged Linux service that owns
//! routes and links on behalf of the app. Platform-neutral modules compile
//! (and are tested) everywhere; kernel/D-Bus glue is Linux-only.

pub mod auth;
pub mod core;
pub mod journal;
#[cfg(target_os = "linux")]
pub mod netlink;
#[cfg(target_os = "linux")]
pub mod peer;
pub mod validate;
