//! Command line of `netorch` on Linux.
use clap::{Args, Parser, Subcommand};
use clap_complete::Shell;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "netorch",
    version = env!("NETORCH_VERSION"),
    about = "One command for VPN profiles and tunnels",
    long_about = "Connect the profiles saved in the Network Orchestrator app through its \
                  network daemon.\nProfiles are shared with the app."
)]
pub struct Cli {
    /// Print machine-readable JSON instead of text
    #[arg(long, global = true)]
    pub json: bool,
    /// App data directory (default: ~/.local/share/com.netmanager.app)
    #[arg(long, global = true, env = "NETORCH_DATA_DIR", value_name = "DIR")]
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
    /// List the servers of a subscription
    Endpoints { target: String },
    /// Choose a subscription's server (asks on a terminal when none is given)
    Use {
        target: String,
        /// Server number or part of its name
        server: Option<String>,
    },
    /// Change a subscription's server, reconnecting if it is connected
    Switch {
        target: String,
        /// Server number or part of its name
        server: Option<String>,
    },
    /// Fetch the subscription again for its current list of servers
    Refresh { target: String },
    /// Measure the delay of a subscription's servers, fastest first
    Test(TestArgs),
    /// Connect a saved profile (importing first when given a link, URL or file)
    Up(UpArgs),
    /// Disconnect
    Down {
        target: Option<String>,
        /// Disconnect every running connection
        #[arg(long, conflicts_with = "target")]
        all: bool,
    },
    /// Show the netorch and daemon versions and whether they work together
    Version,
    /// Print shell completions
    Completions { shell: Shell },
    /// Background process that keeps a connection up (started by `up`)
    #[command(hide = true)]
    Hold { target: String },
}

#[derive(Args, Debug)]
pub struct AddArgs {
    /// vless:// / hysteria2:// link, https:// subscription URL, or .conf/.ovpn file
    pub input: String,
    /// Display name (default: taken from the link or file name)
    #[arg(long)]
    pub name: Option<String>,
}

#[derive(Args, Debug)]
pub struct TestArgs {
    /// Subscription profile
    pub target: String,
    /// Measure only the servers whose name contains this text
    pub server: Option<String>,
    /// Show every server, not just the fastest
    #[arg(long)]
    pub all: bool,
    /// How many of the fastest servers to show
    #[arg(long, default_value_t = super::endpoints::DEFAULT_TOP, value_name = "N")]
    pub top: usize,
}

#[derive(Args, Debug)]
pub struct UpArgs {
    /// Saved profile (id or name), or a link / URL / file to import first
    pub target: String,
    /// Name for a profile imported by this command
    #[arg(long)]
    pub name: Option<String>,
    /// Subscription server to use: its number or part of its name
    #[arg(long, value_name = "SERVER")]
    pub endpoint: Option<String>,
    /// Stay in this terminal and disconnect on Ctrl+C, instead of leaving a
    /// background process that keeps the connection up
    #[arg(long, short = 'f')]
    pub foreground: bool,
    /// Read OpenVPN username and password (two lines) from stdin
    #[arg(long)]
    pub auth_stdin: bool,
    /// Read the OpenVPN private key passphrase (one line) from stdin
    #[arg(long)]
    pub passphrase_stdin: bool,
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
    fn down_all_and_a_target_exclude_each_other() {
        assert!(Cli::try_parse_from(["netorch", "down", "--all", "x"]).is_err());
        assert!(Cli::try_parse_from(["netorch", "down", "--all"]).is_ok());
    }
}
