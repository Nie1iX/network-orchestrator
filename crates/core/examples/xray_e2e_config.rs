//! Test-only bridge from synthetic share links to the production Xray generator.
//! Reads the URI on stdin so it never appears in a process command line.

use net_manager_core::xray::generate_share_link_config_with_http;
use serde::Deserialize;
use std::io::{self, Read};
use std::path::Path;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Input {
    uri: String,
    socks_port: u16,
    http_port: u16,
}

fn generate(path: &Path) -> io::Result<()> {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input)?;
    let input: Input = serde_json::from_str(&input).map_err(io::Error::other)?;
    let config =
        generate_share_link_config_with_http(&input.uri, input.socks_port, input.http_port)?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    serde_json::to_writer(file, &config).map_err(io::Error::other)
}

fn main() {
    let Some(path) = std::env::args_os().nth(1) else {
        std::process::exit(2);
    };
    if generate(Path::new(&path)).is_err() {
        eprintln!("failed to generate synthetic Xray config");
        std::process::exit(1);
    }
}
