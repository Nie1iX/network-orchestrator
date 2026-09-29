//! `network-orchestrator-daemon`: the privileged Linux service that owns
//! routes and links on behalf of the app. Platform-neutral modules compile
//! (and are tested) everywhere; kernel/D-Bus glue is Linux-only.

#[cfg(target_os = "linux")]
pub mod always_on;
pub mod auth;
#[cfg(target_os = "linux")]
pub mod cond_rules;
pub mod core;
#[cfg(target_os = "linux")]
pub mod dns;
pub mod journal;
#[cfg(target_os = "linux")]
pub mod netlink;
pub mod openvpn;
pub mod openvpn_process;
#[cfg(target_os = "linux")]
pub mod peer;
pub mod server;
pub mod settings;
pub mod validate;
pub mod wireguard;
pub mod xray;
pub mod xray_process;
