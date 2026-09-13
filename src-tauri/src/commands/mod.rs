pub(crate) mod diagnostics;
pub(crate) mod explorer;
pub(crate) mod profiles;
pub(crate) mod recovery;
pub(crate) mod system;
pub(crate) mod tunnels;

pub(crate) use diagnostics::{diagnose_profile, inspect_profile_by_id, inspect_profiles};
pub(crate) use explorer::{get_interfaces, get_routes, lookup_destination, set_interface_state};
pub(crate) use profiles::{delete_profile, get_profiles, save_profile, save_vless_profile};
pub(crate) use recovery::{cleanup_recovery, get_recovery_report};
pub(crate) use system::{is_elevated, restart_elevated};
pub(crate) use tunnels::{connect_profile, disconnect_profile, get_tunnel_statuses};
