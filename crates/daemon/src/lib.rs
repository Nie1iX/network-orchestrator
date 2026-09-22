//! `network-orchestrator-daemon`: the privileged Linux service that owns
//! routes and links on behalf of the app. Platform-neutral modules compile
//! (and are tested) everywhere; kernel/D-Bus glue is Linux-only.

pub mod core;
pub mod journal;
pub mod validate;
