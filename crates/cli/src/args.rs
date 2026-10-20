//! Command line of `netorch`.
use clap::{Args, Parser, Subcommand, ValueEnum};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "netorch",
    version,
    about = "One command for VPN profiles, tunnels and routing",
    long_about = "Import a link, subscription or config and connect with one command.\n\
                  Profiles and settings are shared with the Network Orchestrator app."
)]
pub struct Cli {
    /// Print machine-readable JSON instead of text
    #[arg(long, global = true)]
    pub json: bool,
    /// App data directory (default: the Network Orchestrator app's)
    #[arg(
        long,
        global = true,
        env = "NETORCH_MACOS_DATA_DIR",
        value_name = "DIR"
    )]
    pub data_dir: Option<PathBuf>,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// List saved profiles
    Ls,
    /// Show which connections are running
    Status { target: Option<String> },
    /// Save a profile from a share link, subscription URL or config file
    Add(AddArgs),
    /// Delete a saved profile
    Rm { target: String },
    /// Rename a saved profile
    Rename { target: String, name: String },
    /// Connect (importing first when given a link, URL or file)
    Up(UpArgs),
    /// Disconnect
    Down {
        target: Option<String>,
        /// Disconnect every running connection
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// Show the tail of a connection's log
    Logs { target: String },
    /// Measure subscription endpoint delays, or check the exit IP
    Test(TestArgs),
    /// Routing rules and route lookups
    #[command(subcommand)]
    Route(RouteCommand),
    /// Check that everything netorch needs is in place
    Doctor,
    /// Manage the backends netorch runs
    #[command(subcommand)]
    Backend(BackendCommand),
    /// The privileged helper that owns routes, interfaces and DNS
    #[command(subcommand)]
    Service(ServiceCommand),
    /// Print shell completions
    Completions { shell: Shell },
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// vless:// / hysteria2:// link, https:// subscription URL, or .conf/.ovpn file
    pub input: String,
    /// Display name (default: taken from the link or file name)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Mode {
    Socks,
    Tun,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum Role {
    Primary,
    Secondary,
}

#[derive(Args, Debug)]
pub struct UpArgs {
    /// Saved profile (id or name), or a link / URL / file to import first
    pub target: String,
    /// Name for a profile imported by this command
    #[arg(long)]
    pub name: Option<String>,
    /// Xray mode: a local proxy (socks) or a system-wide tunnel (tun)
    #[arg(long, value_enum)]
    pub mode: Option<Mode>,
    /// Primary tunnels carry all traffic; secondary ones only --networks
    #[arg(long, value_enum)]
    pub role: Option<Role>,
    /// Networks a secondary tunnel carries (CIDR, comma separated)
    #[arg(long, value_name = "CIDR,...")]
    pub networks: Option<String>,
    /// Domains resolved through a secondary tunnel's DNS (comma separated)
    #[arg(long, value_name = "DOMAIN,...")]
    pub dns_domains: Option<String>,
    /// Point the macOS system proxy at the local proxy while connected
    #[arg(long)]
    pub system_proxy: bool,
    /// Read OpenVPN username and password (two lines) from stdin
    #[arg(long)]
    pub auth_stdin: bool,
    /// Read the OpenVPN private key passphrase (one line) from stdin
    #[arg(long)]
    pub passphrase_stdin: bool,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Subscription to measure (default: check the exit IP)
    pub target: Option<String>,
    /// Check the exit IP, through the connection when a profile is given
    #[arg(long)]
    pub ip: bool,
}

#[derive(Subcommand, Debug)]
pub enum RouteCommand {
    /// Which interface the system would use for an address
    Lookup { address: String },
    /// Which rule of a profile decides a host or address
    Check {
        target: String,
        /// Profile whose rules are replayed
        #[arg(long)]
        profile: String,
    },
    /// Show a profile's routing rules
    Show { profile: String },
    /// Replace a profile's routing rules (one selector per argument)
    Set {
        profile: String,
        #[arg(long, value_name = "SELECTOR")]
        block: Vec<String>,
        #[arg(long, value_name = "SELECTOR")]
        proxy: Vec<String>,
        #[arg(long, value_name = "SELECTOR")]
        direct: Vec<String>,
        /// Send private LAN ranges direct
        #[arg(long)]
        lan_direct: bool,
    },
}

#[derive(Subcommand, Debug)]
pub enum BackendCommand {
    /// Download (hash-checked) or unpack the pinned Xray
    Install {
        /// Use this copy of the official Xray zip instead of downloading
        #[arg(long, value_name = "ZIP")]
        archive: Option<PathBuf>,
    },
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommand {
    /// Is the helper installed, running and willing to talk to netorch
    Status,
    /// Install the helper without the app (needs sudo, run from the app bundle)
    Install,
    /// Remove a helper installed by `service install` (needs sudo)
    Remove,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_line_definition_is_consistent() {
        Cli::command().debug_assert();
    }

    #[test]
    fn up_takes_a_link_and_flags() {
        let cli = Cli::try_parse_from([
            "netorch",
            "--json",
            "up",
            "vless://x@h:1#n",
            "--mode",
            "tun",
            "--role",
            "secondary",
            "--networks",
            "10.0.0.0/8",
        ])
        .unwrap();
        assert!(cli.json);
        let Command::Up(up) = cli.command else {
            panic!("not up")
        };
        assert_eq!(up.mode, Some(Mode::Tun));
        assert_eq!(up.role, Some(Role::Secondary));
        assert_eq!(up.networks.as_deref(), Some("10.0.0.0/8"));
    }

    #[test]
    fn down_all_and_a_target_exclude_each_other() {
        assert!(Cli::try_parse_from(["netorch", "down", "--all", "x"]).is_err());
        assert!(Cli::try_parse_from(["netorch", "down", "--all"]).is_ok());
    }
}
