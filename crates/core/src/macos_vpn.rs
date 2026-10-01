//! VPN services configured by other apps on macOS (Network Extension and
//! built-in VPNs), listed and toggled through `scutil --nc` as the logged-in
//! user — the same operation as the VPN menu in System Settings.
use serde::Serialize;
use std::io;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalVpn {
    /// Service identifier (UUID) passed back to start/stop.
    pub id: String,
    pub name: String,
    /// `connected`, `connecting`, `disconnecting`, `disconnected` or `invalid`.
    pub state: String,
    /// Provider bundle id such as `llc.itdev.incy`, when reported.
    pub provider: Option<String>,
    pub enabled: bool,
}

/// Parse `scutil --nc list`. Lines look like
/// `* (Connected)  <UUID> VPN (bundle.id) "Name"  [VPN:bundle.id]`; the
/// leading `*` marks an enabled service.
pub fn parse_nc_list(output: &str) -> Vec<ExternalVpn> {
    output
        .lines()
        .filter_map(|line| {
            let line = line.trim_end();
            let enabled = line.trim_start().starts_with('*');
            let rest = line.trim_start().trim_start_matches('*').trim_start();
            let rest = rest.strip_prefix('(')?;
            let (state, rest) = rest.split_once(')')?;
            let mut rest = rest.trim_start();
            let (id, after) = rest.split_once(char::is_whitespace)?;
            if !is_service_id(id) {
                return None;
            }
            rest = after.trim_start();
            let quote = rest.find('"')?;
            let head = &rest[..quote];
            let provider = head
                .split_once('(')
                .and_then(|(_, tail)| tail.split_once(')'))
                .map(|(provider, _)| provider.trim().to_string())
                .filter(|provider| !provider.is_empty());
            let mut name = String::new();
            let mut escaped = false;
            for c in rest[quote + 1..].chars() {
                match (escaped, c) {
                    (true, c) => {
                        name.push(c);
                        escaped = false;
                    }
                    (false, '\\') => escaped = true,
                    (false, '"') => break,
                    (false, c) => name.push(c),
                }
            }
            Some(ExternalVpn {
                id: id.to_string(),
                name,
                state: state.trim().to_ascii_lowercase(),
                provider,
                enabled,
            })
        })
        .collect()
}

fn is_service_id(id: &str) -> bool {
    id.len() == 36
        && id.chars().enumerate().all(|(i, c)| {
            if [8, 13, 18, 23].contains(&i) {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        })
}

/// Arguments for `scutil` to start or stop one service; only a well-formed
/// service UUID is accepted.
pub fn nc_command(id: &str, connect: bool) -> io::Result<Vec<String>> {
    if !is_service_id(id) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid VPN service",
        ));
    }
    let verb = if connect { "start" } else { "stop" };
    Ok(vec!["--nc".into(), verb.into(), id.to_string()])
}

pub trait ScutilRunner {
    fn run(&mut self, args: &[&str]) -> io::Result<String>;
}

pub struct SystemScutil;

impl ScutilRunner for SystemScutil {
    fn run(&mut self, args: &[&str]) -> io::Result<String> {
        let output = std::process::Command::new("/usr/sbin/scutil")
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("scutil failed"));
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }
}

pub fn list(runner: &mut impl ScutilRunner) -> io::Result<Vec<ExternalVpn>> {
    Ok(parse_nc_list(&runner.run(&["--nc", "list"])?))
}

pub fn set_connected(runner: &mut impl ScutilRunner, id: &str, connect: bool) -> io::Result<()> {
    let args = nc_command(id, connect)?;
    let args: Vec<&str> = args.iter().map(String::as_str).collect();
    runner.run(&args).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = "Available network connection services in the current set (*=enabled):\n\
* (Connected)      392D9AF2-DA71-4726-B590-5EDE32714C7C VPN (llc.itdev.incy) \"incy\"                           [VPN:llc.itdev.incy]\n\
* (Disconnected)   09A8A986-D242-43CD-B1AD-DDDA9FF97929 VPN (hossin.asaadi.V2Box) \"V2BOX\"                          [VPN:hossin.asaadi.V2Box]\n\
  (Disconnected)   11111111-2222-3333-4444-555555555555 IPSec \"Office \\\"HQ\\\"\"            [IPSec]\n";

    #[test]
    fn parses_services_states_and_providers() {
        let services = parse_nc_list(LIST);
        assert_eq!(services.len(), 3);
        assert_eq!(
            services[0],
            ExternalVpn {
                id: "392D9AF2-DA71-4726-B590-5EDE32714C7C".into(),
                name: "incy".into(),
                state: "connected".into(),
                provider: Some("llc.itdev.incy".into()),
                enabled: true,
            }
        );
        assert_eq!(services[1].state, "disconnected");
        assert_eq!(services[2].name, "Office \"HQ\"");
        assert_eq!(services[2].provider, None);
        assert!(!services[2].enabled);
    }

    #[test]
    fn toggling_validates_the_service_id() {
        assert!(nc_command("392D9AF2-DA71-4726-B590-5EDE32714C7C", true).is_ok());
        assert_eq!(
            nc_command("392D9AF2-DA71-4726-B590-5EDE32714C7C", false).unwrap(),
            vec!["--nc", "stop", "392D9AF2-DA71-4726-B590-5EDE32714C7C"]
        );
        assert!(nc_command("incy; rm -rf /", true).is_err());
        assert!(nc_command("", false).is_err());
    }
}
