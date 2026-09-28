use crate::daemon_protocol::OpenVpnCredentials;
use ipnet::{IpNet, Ipv4Net};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

pub const MAX_MANAGEMENT_LINE_BYTES: usize = 16 * 1024;
const MAX_PUSH_BYTES: usize = 8 * 1024;
const MAX_PUSH_DIRECTIVES: usize = 128;
const MAX_ROUTES: usize = 64;
const MAX_DNS_ADDRESSES: usize = 16;
const MAX_DNS_DOMAINS: usize = 16;
const MAX_USERNAME_BYTES: usize = 256;
const MAX_SECRET_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementParseError {
    Malformed,
    Unsupported,
    TooLarge,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenVpnState {
    Connecting,
    Wait,
    Auth,
    GetConfig,
    AssignIp,
    AddRoutes,
    Connected,
    Reconnecting,
    Exiting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordPrompt {
    Auth,
    PrivateKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManagementCredentialError {
    Missing,
    Invalid,
}

/// Reject control characters before a value can reach the line-based socket.
pub fn validate_openvpn_credentials(
    credentials: &OpenVpnCredentials,
) -> Result<(), ManagementCredentialError> {
    if credentials.auth_user_pass.is_none() && credentials.private_key_passphrase.is_none() {
        return Err(ManagementCredentialError::Invalid);
    }
    if let Some(auth) = &credentials.auth_user_pass {
        if !safe_credential(&auth.username, MAX_USERNAME_BYTES, false)
            || !safe_credential(&auth.password, MAX_SECRET_BYTES, true)
        {
            return Err(ManagementCredentialError::Invalid);
        }
    }
    if let Some(passphrase) = &credentials.private_key_passphrase {
        if !safe_credential(passphrase, MAX_SECRET_BYTES, false) {
            return Err(ManagementCredentialError::Invalid);
        }
    }
    Ok(())
}

/// OpenVPN management command syntax, with every secret kept on the Unix socket.
pub fn management_password_reply(
    prompt: PasswordPrompt,
    credentials: Option<&OpenVpnCredentials>,
) -> Result<String, ManagementCredentialError> {
    let credentials = credentials.ok_or(ManagementCredentialError::Missing)?;
    validate_openvpn_credentials(credentials)?;
    match prompt {
        PasswordPrompt::Auth => {
            let auth = credentials
                .auth_user_pass
                .as_ref()
                .ok_or(ManagementCredentialError::Missing)?;
            Ok(format!(
                "username \"Auth\" {}\npassword \"Auth\" {}\n",
                quote_management_value(&auth.username),
                quote_management_value(&auth.password)
            ))
        }
        PasswordPrompt::PrivateKey => {
            let passphrase = credentials
                .private_key_passphrase
                .as_deref()
                .ok_or(ManagementCredentialError::Missing)?;
            Ok(format!(
                "password \"Private Key\" {}\n",
                quote_management_value(passphrase)
            ))
        }
    }
}

fn safe_credential(value: &str, max_bytes: usize, allow_empty: bool) -> bool {
    (allow_empty || !value.is_empty())
        && value.len() <= max_bytes
        && !value.chars().any(char::is_control)
}

fn quote_management_value(value: &str) -> String {
    let mut result = String::with_capacity(value.len() + 2);
    result.push('"');
    for character in value.chars() {
        if matches!(character, '"' | '\\') {
            result.push('\\');
        }
        result.push(character);
    }
    result.push('"');
    result
}

pub struct PushedDnsServer {
    pub id: u8,
    pub addresses: Vec<IpAddr>,
    pub resolve_domains: Vec<String>,
}

pub struct PushedNetworkConfig {
    pub routes: Vec<IpNet>,
    pub redirect_gateway_def1: bool,
    pub legacy_dns_servers: Vec<IpAddr>,
    pub search_domains: Vec<String>,
    pub dns_servers: Vec<PushedDnsServer>,
    /// `push-continuation 2`: more PUSH_REPLY fragments follow.
    pub more_follows: bool,
}

impl PushedNetworkConfig {
    /// Append a later `push-continuation` fragment; caps are re-checked by
    /// the daemon when it builds the network plan.
    fn merge(&mut self, next: PushedNetworkConfig) {
        fn extend<T: PartialEq>(into: &mut Vec<T>, from: Vec<T>) {
            for item in from {
                if !into.contains(&item) {
                    into.push(item);
                }
            }
        }
        extend(&mut self.routes, next.routes);
        extend(&mut self.legacy_dns_servers, next.legacy_dns_servers);
        extend(&mut self.search_domains, next.search_domains);
        self.dns_servers.extend(next.dns_servers);
        self.redirect_gateway_def1 |= next.redirect_gateway_def1;
        self.more_follows = next.more_follows;
    }
}

impl fmt::Debug for PushedNetworkConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushedNetworkConfig")
            .field("routes_len", &self.routes.len())
            .field("dns_servers_len", &self.dns_servers.len())
            .finish_non_exhaustive()
    }
}

pub enum ManagementEvent {
    State(OpenVpnState),
    ByteCount { received: u64, sent: u64 },
    PasswordPrompt(PasswordPrompt),
    AuthenticationFailed,
    PushReply(PushedNetworkConfig),
}

impl fmt::Debug for ManagementEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::State(state) => f.debug_tuple("State").field(state).finish(),
            Self::ByteCount { received, sent } => f
                .debug_struct("ByteCount")
                .field("received", received)
                .field("sent", sent)
                .finish(),
            Self::PasswordPrompt(kind) => f.debug_tuple("PasswordPrompt").field(kind).finish(),
            Self::AuthenticationFailed => f.write_str("AuthenticationFailed"),
            Self::PushReply(push) => f.debug_tuple("PushReply").field(push).finish(),
        }
    }
}

#[derive(Default)]
pub struct ManagementSnapshot {
    pub state: Option<OpenVpnState>,
    pub received: u64,
    pub sent: u64,
    pub active_push: Option<PushedNetworkConfig>,
    pending_push: Option<PushedNetworkConfig>,
}

impl ManagementSnapshot {
    pub fn apply(&mut self, event: ManagementEvent) {
        match event {
            ManagementEvent::State(state) => {
                self.state = Some(state);
                match state {
                    OpenVpnState::Connected => self.active_push = self.pending_push.take(),
                    OpenVpnState::Reconnecting | OpenVpnState::Exiting => {
                        self.active_push = None;
                        self.pending_push = None;
                    }
                    _ => {}
                }
            }
            ManagementEvent::ByteCount { received, sent } => {
                self.received = received;
                self.sent = sent;
            }
            ManagementEvent::PushReply(push) => {
                self.pending_push = match self.pending_push.take() {
                    Some(mut pending) if pending.more_follows => {
                        pending.merge(push);
                        Some(pending)
                    }
                    _ => Some(push),
                };
            }
            ManagementEvent::AuthenticationFailed => {
                self.state = Some(OpenVpnState::Exiting);
                self.active_push = None;
                self.pending_push = None;
            }
            ManagementEvent::PasswordPrompt(_) => {}
        }
    }
}

/// Parses one complete management socket line. Raw log/reason text is never returned.
pub fn parse_management_line(line: &str) -> Result<Option<ManagementEvent>, ManagementParseError> {
    if line.len() > MAX_MANAGEMENT_LINE_BYTES {
        return Err(ManagementParseError::TooLarge);
    }
    let line = line.strip_suffix('\r').unwrap_or(line);
    if line.contains(['\r', '\n', '\0']) {
        return Err(ManagementParseError::Malformed);
    }
    let numeric = line.as_bytes().first().is_some_and(u8::is_ascii_digit);
    let numeric_log = numeric
        && line
            .split_once(',')
            .and_then(|(_, rest)| rest.split(',').next())
            .is_some_and(|flags| flags.bytes().all(|b| b"IFNWD".contains(&b)));
    if let Some(data) = line
        .strip_prefix(">STATE:")
        .or_else(|| line.strip_prefix("STATE:"))
        .or_else(|| (numeric && !numeric_log).then_some(line))
    {
        let mut fields = data.split(',');
        parse_timestamp(fields.next())?;
        let state = match fields.next() {
            Some("CONNECTING") => OpenVpnState::Connecting,
            Some("WAIT") => OpenVpnState::Wait,
            Some("AUTH") => OpenVpnState::Auth,
            Some("GET_CONFIG") => OpenVpnState::GetConfig,
            Some("ASSIGN_IP") => OpenVpnState::AssignIp,
            Some("ADD_ROUTES") => OpenVpnState::AddRoutes,
            Some("CONNECTED") => OpenVpnState::Connected,
            Some("RECONNECTING") => OpenVpnState::Reconnecting,
            Some("EXITING") => OpenVpnState::Exiting,
            _ => return Err(ManagementParseError::Malformed),
        };
        return Ok(Some(ManagementEvent::State(state)));
    }
    if let Some(data) = line.strip_prefix(">BYTECOUNT:") {
        let (received, sent) = data
            .split_once(',')
            .ok_or(ManagementParseError::Malformed)?;
        return Ok(Some(ManagementEvent::ByteCount {
            received: received
                .parse()
                .map_err(|_| ManagementParseError::Malformed)?,
            sent: sent.parse().map_err(|_| ManagementParseError::Malformed)?,
        }));
    }
    if let Some(data) = line.strip_prefix(">PASSWORD:") {
        if data.starts_with("Verification Failed:") {
            return Ok(Some(ManagementEvent::AuthenticationFailed));
        }
        // Sent after a server-issued auth-token; a notification, not a prompt.
        if data.starts_with("Auth-Token:") {
            return Ok(None);
        }
        let prompt = match data {
            "Need 'Auth' username/password" => PasswordPrompt::Auth,
            "Need 'Private Key' password" => PasswordPrompt::PrivateKey,
            _ => return Err(ManagementParseError::Unsupported),
        };
        return Ok(Some(ManagementEvent::PasswordPrompt(prompt)));
    }
    if let Some(data) = line
        .strip_prefix(">LOG:")
        .or_else(|| numeric_log.then_some(line))
    {
        let mut fields = data.splitn(3, ',');
        parse_timestamp(fields.next())?;
        let flags = fields.next().ok_or(ManagementParseError::Malformed)?;
        if !flags.bytes().all(|b| b"IFNWD".contains(&b)) {
            return Err(ManagementParseError::Malformed);
        }
        let message = fields.next().ok_or(ManagementParseError::Malformed)?;
        const PREFIX: &str = "PUSH: Received control message: '";
        if let Some(rest) = message.strip_prefix(PREFIX) {
            let payload = rest
                .strip_suffix('\'')
                .ok_or(ManagementParseError::Malformed)?;
            if payload.starts_with("PUSH_REPLY") {
                return parse_push_reply(payload)
                    .map(|push| Some(ManagementEvent::PushReply(push)));
            }
        }
    }
    Ok(None)
}

/// Parses only network metadata from a PUSH_REPLY; all other pushed options are ignored.
pub fn parse_push_reply(payload: &str) -> Result<PushedNetworkConfig, ManagementParseError> {
    if payload.len() > MAX_PUSH_BYTES {
        return Err(ManagementParseError::TooLarge);
    }
    if payload.contains(['\r', '\n', '\0']) {
        return Err(ManagementParseError::Malformed);
    }
    let mut directives = payload.split(',');
    if directives.next() != Some("PUSH_REPLY") {
        return Err(ManagementParseError::Malformed);
    }
    let mut config = PushedNetworkConfig {
        routes: Vec::new(),
        redirect_gateway_def1: false,
        legacy_dns_servers: Vec::new(),
        search_domains: Vec::new(),
        dns_servers: Vec::new(),
        more_follows: false,
    };
    let mut servers = BTreeMap::<u8, PushedDnsServer>::new();
    for (index, directive) in directives.enumerate() {
        if index >= MAX_PUSH_DIRECTIVES {
            return Err(ManagementParseError::TooLarge);
        }
        let tokens: Vec<_> = directive.split_whitespace().collect();
        match tokens.as_slice() {
            ["route", rest @ ..] => {
                if let Some(route) = parse_ipv4_route(rest)? {
                    add_route(&mut config.routes, route)?;
                }
            }
            ["route-ipv6", network] => {
                let route = network
                    .parse::<IpNet>()
                    .map_err(|_| ManagementParseError::Malformed)?;
                if !matches!(route, IpNet::V6(_)) {
                    return Err(ManagementParseError::Malformed);
                }
                add_route(&mut config.routes, route.trunc())?;
            }
            ["route-ipv6", ..] => return Err(ManagementParseError::Malformed),
            ["redirect-gateway", flags @ ..] => {
                if !flags.iter().all(|flag| {
                    matches!(
                        *flag,
                        "def1"
                            | "local"
                            | "autolocal"
                            | "bypass-dhcp"
                            | "bypass-dns"
                            | "block-local"
                            | "ipv6"
                            | "!ipv4"
                    )
                }) {
                    return Err(ManagementParseError::Unsupported);
                }
                // Installed as halves either way: the daemon owns the routes.
                if !flags.contains(&"!ipv4") {
                    config.redirect_gateway_def1 = true;
                    add_route(&mut config.routes, "0.0.0.0/1".parse().unwrap())?;
                    add_route(&mut config.routes, "128.0.0.0/1".parse().unwrap())?;
                }
                if flags.contains(&"ipv6") {
                    add_route(&mut config.routes, "::/1".parse().unwrap())?;
                    add_route(&mut config.routes, "8000::/1".parse().unwrap())?;
                }
            }
            ["push-continuation", "2"] => config.more_follows = true,
            ["dhcp-option", "DNS", address] => {
                let address = address
                    .parse()
                    .map_err(|_| ManagementParseError::Malformed)?;
                push_unique(&mut config.legacy_dns_servers, address, MAX_DNS_ADDRESSES)?;
            }
            ["dhcp-option", "DOMAIN" | "DOMAIN-SEARCH", domain] => {
                validate_domain(domain)?;
                push_unique(
                    &mut config.search_domains,
                    (*domain).to_owned(),
                    MAX_DNS_DOMAINS,
                )?;
            }
            ["dhcp-option", "DNS" | "DOMAIN" | "DOMAIN-SEARCH", ..] => {
                return Err(ManagementParseError::Malformed);
            }
            ["dns", "search-domains", domains @ ..] if !domains.is_empty() => {
                for domain in domains {
                    validate_domain(domain)?;
                    push_unique(
                        &mut config.search_domains,
                        (*domain).to_owned(),
                        MAX_DNS_DOMAINS,
                    )?;
                }
            }
            ["dns", "server", id, "address", addresses @ ..] if !addresses.is_empty() => {
                let server = dns_server(&mut servers, id)?;
                for address in addresses {
                    let address = address
                        .parse()
                        .map_err(|_| ManagementParseError::Malformed)?;
                    push_unique(&mut server.addresses, address, 8)?;
                }
            }
            ["dns", "server", id, "resolve-domains", domains @ ..] if !domains.is_empty() => {
                let server = dns_server(&mut servers, id)?;
                for domain in domains {
                    validate_domain(domain)?;
                    push_unique(
                        &mut server.resolve_domains,
                        (*domain).to_owned(),
                        MAX_DNS_DOMAINS,
                    )?;
                }
            }
            // priority, dnssec, transport, sni, exclude-domains: not applied.
            ["dns", ..] => {}
            _ => {}
        }
    }
    let address_count = config.legacy_dns_servers.len()
        + servers.values().map(|s| s.addresses.len()).sum::<usize>();
    if address_count > MAX_DNS_ADDRESSES
        || servers
            .values()
            .map(|s| s.resolve_domains.len())
            .sum::<usize>()
            + config.search_domains.len()
            > MAX_DNS_DOMAINS
    {
        return Err(ManagementParseError::TooLarge);
    }
    config.dns_servers = servers.into_values().collect();
    Ok(config)
}

fn parse_timestamp(field: Option<&str>) -> Result<(), ManagementParseError> {
    field
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<u64>().ok())
        .map(|_| ())
        .ok_or(ManagementParseError::Malformed)
}

/// `None` for routes that must bypass the tunnel (`net_gateway`,
/// `remote_host`); gateway and metric of tunnel routes are ignored because the
/// daemon installs them on the tunnel link itself.
fn parse_ipv4_route(tokens: &[&str]) -> Result<Option<IpNet>, ManagementParseError> {
    match tokens {
        [_, _, "net_gateway" | "remote_host", ..] => Ok(None),
        [address, mask, gateway] | [address, mask, gateway, _] => {
            let valid_gateway = *gateway == "vpn_gateway" || gateway.parse::<Ipv4Addr>().is_ok();
            let valid_metric = tokens.get(3).is_none_or(|m| m.parse::<u32>().is_ok());
            if !valid_gateway || !valid_metric {
                return Err(ManagementParseError::Malformed);
            }
            parse_ipv4_route(&[*address, *mask])
        }
        [cidr] if cidr.contains('/') => {
            let route = cidr
                .parse::<IpNet>()
                .map_err(|_| ManagementParseError::Malformed)?;
            if !matches!(route, IpNet::V4(_)) {
                return Err(ManagementParseError::Malformed);
            }
            Ok(Some(route.trunc()))
        }
        [address] => Ok(Some(IpNet::V4(
            Ipv4Net::new(
                address
                    .parse()
                    .map_err(|_| ManagementParseError::Malformed)?,
                32,
            )
            .unwrap(),
        ))),
        [address, mask] => {
            let address = address
                .parse::<Ipv4Addr>()
                .map_err(|_| ManagementParseError::Malformed)?;
            let mask = mask
                .parse::<Ipv4Addr>()
                .map_err(|_| ManagementParseError::Malformed)?;
            Ok(Some(IpNet::V4(
                Ipv4Net::with_netmask(address, mask)
                    .map_err(|_| ManagementParseError::Malformed)?
                    .trunc(),
            )))
        }
        _ => Err(ManagementParseError::Malformed),
    }
}

fn add_route(routes: &mut Vec<IpNet>, route: IpNet) -> Result<(), ManagementParseError> {
    push_unique(routes, route, MAX_ROUTES)
}

fn push_unique<T: PartialEq>(
    items: &mut Vec<T>,
    item: T,
    max: usize,
) -> Result<(), ManagementParseError> {
    if !items.contains(&item) {
        if items.len() >= max {
            return Err(ManagementParseError::TooLarge);
        }
        items.push(item);
    }
    Ok(())
}

fn dns_server<'a>(
    servers: &'a mut BTreeMap<u8, PushedDnsServer>,
    id: &str,
) -> Result<&'a mut PushedDnsServer, ManagementParseError> {
    let id = id
        .parse::<u8>()
        .map_err(|_| ManagementParseError::Malformed)?;
    if id > 127 {
        return Err(ManagementParseError::Malformed);
    }
    Ok(servers.entry(id).or_insert_with(|| PushedDnsServer {
        id,
        addresses: Vec::new(),
        resolve_domains: Vec::new(),
    }))
}

fn validate_domain(domain: &str) -> Result<(), ManagementParseError> {
    if domain.len() > 253
        || domain.is_empty()
        || !domain.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(ManagementParseError::Malformed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_protocol::OpenVpnUserPass;

    #[test]
    fn management_replies_escape_credentials_and_can_answer_repeated_prompts() {
        let credentials = OpenVpnCredentials {
            auth_user_pass: Some(OpenVpnUserPass {
                username: "alice bob".into(),
                password: "p\\\\\"word".into(),
            }),
            private_key_passphrase: Some("key\\\\\" pass".into()),
        };
        let auth = management_password_reply(PasswordPrompt::Auth, Some(&credentials)).unwrap();
        assert_eq!(
            auth,
            "username \"Auth\" \"alice bob\"\npassword \"Auth\" \"p\\\\\\\\\\\"word\"\n"
        );
        assert_eq!(
            management_password_reply(PasswordPrompt::Auth, Some(&credentials)).unwrap(),
            auth
        );
        assert_eq!(
            management_password_reply(PasswordPrompt::PrivateKey, Some(&credentials)).unwrap(),
            "password \"Private Key\" \"key\\\\\\\\\\\" pass\"\n"
        );
    }

    #[test]
    fn management_replies_reject_missing_or_line_breaking_secrets() {
        assert_eq!(
            management_password_reply(PasswordPrompt::Auth, None),
            Err(ManagementCredentialError::Missing)
        );
        for value in [
            "bad\nline".to_string(),
            "bad\0value".to_string(),
            "x".repeat(4097),
        ] {
            let credentials = OpenVpnCredentials {
                auth_user_pass: Some(OpenVpnUserPass {
                    username: "alice".into(),
                    password: value,
                }),
                private_key_passphrase: None,
            };
            assert_eq!(
                management_password_reply(PasswordPrompt::Auth, Some(&credentials)),
                Err(ManagementCredentialError::Invalid)
            );
        }
    }

    #[test]
    fn parses_state_bytecount_and_password_events_without_reason_text() {
        assert!(matches!(
            parse_management_line(">STATE:1720000000,CONNECTED,SUCCESS,10.8.0.2,198.51.100.1")
                .unwrap(),
            Some(ManagementEvent::State(OpenVpnState::Connected))
        ));
        assert!(matches!(
            parse_management_line(">BYTECOUNT:123,456").unwrap(),
            Some(ManagementEvent::ByteCount {
                received: 123,
                sent: 456
            })
        ));
        assert!(matches!(
            parse_management_line(">PASSWORD:Need 'Auth' username/password").unwrap(),
            Some(ManagementEvent::PasswordPrompt(PasswordPrompt::Auth))
        ));
        assert!(matches!(
            parse_management_line(">PASSWORD:Need 'Private Key' password").unwrap(),
            Some(ManagementEvent::PasswordPrompt(PasswordPrompt::PrivateKey))
        ));
        assert!(matches!(
            parse_management_line(">PASSWORD:Verification Failed: 'private-secret'").unwrap(),
            Some(ManagementEvent::AuthenticationFailed)
        ));
        assert!(matches!(
            parse_management_line("1720000001,RECONNECTING,connection-reset").unwrap(),
            Some(ManagementEvent::State(OpenVpnState::Reconnecting))
        ));
    }

    #[test]
    fn parses_split_def1_legacy_dns_and_modern_dns() {
        let push = parse_push_reply("PUSH_REPLY,route 10.20.0.0 255.255.0.0,route-ipv6 fd00:1::/64,redirect-gateway def1,dhcp-option DNS 10.8.0.1,dhcp-option DOMAIN corp.example,dns search-domains branch.example,dns server 0 address 10.8.0.2 fd00::53,dns server 0 resolve-domains internal.example,auth-token PRIVATE-SECRET").unwrap();
        assert!(push.routes.contains(&"10.20.0.0/16".parse().unwrap()));
        assert!(push.routes.contains(&"fd00:1::/64".parse().unwrap()));
        assert!(push.routes.contains(&"0.0.0.0/1".parse().unwrap()));
        assert!(push.routes.contains(&"128.0.0.0/1".parse().unwrap()));
        assert!(push.redirect_gateway_def1);
        assert_eq!(
            push.legacy_dns_servers,
            vec!["10.8.0.1".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(push.search_domains, ["corp.example", "branch.example"]);
        assert_eq!(push.dns_servers[0].id, 0);
        assert_eq!(push.dns_servers[0].addresses.len(), 2);
        assert_eq!(push.dns_servers[0].resolve_domains, ["internal.example"]);
        assert!(!format!("{push:?}").contains("PRIVATE-SECRET"));
    }

    #[test]
    fn routes_via_the_tunnel_are_installed_and_bypass_routes_are_skipped() {
        let push = parse_push_reply(
            "PUSH_REPLY,route 10.30.0.0 255.255.0.0 vpn_gateway,route 10.31.0.0 255.255.0.0 vpn_gateway 10,route 10.32.0.0 255.255.0.0 10.8.0.1 5,route 198.51.100.0 255.255.255.0 net_gateway",
        )
        .unwrap();
        assert_eq!(
            push.routes,
            [
                "10.30.0.0/16".parse().unwrap(),
                "10.31.0.0/16".parse().unwrap(),
                "10.32.0.0/16".parse().unwrap()
            ]
        );
    }

    #[test]
    fn accepts_redirect_gateway_flags_and_unknown_dns_keys() {
        let push = parse_push_reply(
            "PUSH_REPLY,redirect-gateway def1 bypass-dhcp,dns server 0 priority 10,dns server 0 address 10.8.0.53,dns server 0 dnssec no",
        )
        .unwrap();
        assert!(push.redirect_gateway_def1);
        assert!(push.routes.contains(&"0.0.0.0/1".parse().unwrap()));
        assert!(push.routes.contains(&"128.0.0.0/1".parse().unwrap()));
        assert_eq!(
            push.dns_servers[0].addresses,
            ["10.8.0.53".parse::<IpAddr>().unwrap()]
        );
        assert!(
            parse_push_reply("PUSH_REPLY,redirect-gateway")
                .unwrap()
                .redirect_gateway_def1
        );
        let v6_only = parse_push_reply("PUSH_REPLY,redirect-gateway ipv6 !ipv4").unwrap();
        assert!(!v6_only.redirect_gateway_def1);
        assert_eq!(
            v6_only.routes,
            ["::/1".parse().unwrap(), "8000::/1".parse().unwrap()]
        );
    }

    #[test]
    fn auth_token_notification_is_ignored_without_keeping_the_token() {
        assert!(parse_management_line(">PASSWORD:Auth-Token:PRIVATE-SECRET")
            .unwrap()
            .is_none());
    }

    #[test]
    fn push_continuation_fragments_are_merged() {
        let mut state = ManagementSnapshot::default();
        for payload in [
            "PUSH_REPLY,route 10.1.0.0 255.255.0.0,dhcp-option DNS 10.8.0.1,push-continuation 2",
            "PUSH_REPLY,redirect-gateway def1,push-continuation 1",
        ] {
            state.apply(ManagementEvent::PushReply(
                parse_push_reply(payload).unwrap(),
            ));
        }
        state.apply(ManagementEvent::State(OpenVpnState::Connected));
        let active = state.active_push.as_ref().unwrap();
        assert!(active.routes.contains(&"10.1.0.0/16".parse().unwrap()));
        assert!(active.redirect_gateway_def1);
        assert_eq!(
            active.legacy_dns_servers,
            ["10.8.0.1".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn extracts_push_only_from_well_formed_log_event() {
        let event = parse_management_line(">LOG:1720000000,I,PUSH: Received control message: 'PUSH_REPLY,route 192.0.2.0 255.255.255.0,auth-token PRIVATE-SECRET'").unwrap();
        let Some(ManagementEvent::PushReply(push)) = event else {
            panic!("expected push")
        };
        assert_eq!(push.routes, ["192.0.2.0/24".parse().unwrap()]);
        assert!(!format!("{push:?}").contains("PRIVATE-SECRET"));
        assert!(
            parse_management_line(">LOG:1720000000,I,ordinary log with PRIVATE-SECRET")
                .unwrap()
                .is_none()
        );
        let history = parse_management_line("1720000000,I,PUSH: Received control message: 'PUSH_REPLY,route 10.89.0.0 255.255.255.0'").unwrap();
        assert!(matches!(history, Some(ManagementEvent::PushReply(_))));
        assert!(
            parse_management_line("1720000001,W,ordinary historical warning")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn rejects_malformed_known_events_and_unsupported_auth_challenges() {
        for line in [
            ">STATE:bad,CONNECTED",
            ">STATE:1,UNKNOWN",
            ">BYTECOUNT:1",
            ">BYTECOUNT:1,-2",
            ">PASSWORD:Need 'Auth' username/password SC:1,secret",
            ">LOG:1,I,PUSH: Received control message: 'PUSH_REPLY,route not-an-ip'",
            ">STATE:1,CONNECTED\n>BYTECOUNT:1,2",
        ] {
            assert!(parse_management_line(line).is_err(), "{line}");
        }
    }

    #[test]
    fn rejects_hostile_push_values_and_caps() {
        for payload in [
            "PUSH_REPLY,route 10.0.0.0 255.0.255.0",
            "PUSH_REPLY,route-ipv6 not-ip",
            "PUSH_REPLY,dhcp-option DNS file:///secret",
            "PUSH_REPLY,dhcp-option DOMAIN evil;script",
            "PUSH_REPLY,dns server 0 address 10.0.0.1:53",
        ] {
            let err = parse_push_reply(payload).err().unwrap();
            assert!(!format!("{err:?}").contains("secret"));
        }
        assert_eq!(
            parse_management_line(&format!(">LOG:{}", "x".repeat(MAX_MANAGEMENT_LINE_BYTES))).err(),
            Some(ManagementParseError::TooLarge)
        );
        assert_eq!(
            parse_push_reply(&format!("PUSH_REPLY,{}", "route 10.0.0.0/8,".repeat(129))).err(),
            Some(ManagementParseError::TooLarge)
        );
    }

    #[test]
    fn reconnect_replaces_routes_and_dns_only_after_connected() {
        let mut state = ManagementSnapshot::default();
        let first =
            parse_push_reply("PUSH_REPLY,route 10.1.0.0 255.255.0.0,dhcp-option DNS 10.8.0.1")
                .unwrap();
        state.apply(ManagementEvent::PushReply(first));
        assert!(state.active_push.is_none());
        state.apply(ManagementEvent::State(OpenVpnState::Connected));
        assert_eq!(
            state.active_push.as_ref().unwrap().routes,
            ["10.1.0.0/16".parse().unwrap()]
        );
        state.apply(ManagementEvent::State(OpenVpnState::Reconnecting));
        assert!(state.active_push.is_none());
        let second =
            parse_push_reply("PUSH_REPLY,route 10.2.0.0 255.255.0.0,dhcp-option DNS 10.8.0.2")
                .unwrap();
        state.apply(ManagementEvent::PushReply(second));
        state.apply(ManagementEvent::State(OpenVpnState::Connected));
        let active = state.active_push.as_ref().unwrap();
        assert_eq!(active.routes, ["10.2.0.0/16".parse().unwrap()]);
        assert_eq!(
            active.legacy_dns_servers,
            ["10.8.0.2".parse::<IpAddr>().unwrap()]
        );
    }
}
