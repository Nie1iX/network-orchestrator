//! DNS path visibility: which resolver would answer a query and which
//! interface it would leave through. `net.dns.status` mirrors
//! `resolvectl status` (per-link servers, route domains, the active
//! server); `net.dns.probe` sends one real UDP query so the user sees
//! the egress source/gateway the policy routing picks — the "from which
//! point does my DNS leave" question the orchestrator answers for.

use crate::cond_rules::NetworkObservation;
use net_manager_core::daemon_protocol::{
    DnsDomain, DnsLinkStatus, IpFamily, NetDnsProbeParams, NetDnsProbeResult, NetDnsStatusResult,
    RouteLookup,
};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use zbus::zvariant::OwnedValue;

const RESOLVE1: &str = "org.freedesktop.resolve1";
const RESOLVE1_ROOT: &str = "/org/freedesktop/resolve1";
const RESOLVE1_LINK: &str = "org.freedesktop.resolve1.Link";
const DBUS_PROPS: &str = "org.freedesktop.DBus.Properties";
const PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

fn unavailable(err: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotConnected,
        format!("systemd-resolved is not available: {err}"),
    )
}

async fn bus() -> io::Result<&'static zbus::Connection> {
    static CELL: tokio::sync::OnceCell<zbus::Connection> = tokio::sync::OnceCell::const_new();
    CELL.get_or_try_init(|| async { zbus::Connection::system().await.map_err(unavailable) })
        .await
}

async fn property(conn: &zbus::Connection, path: &str, name: &str) -> Option<OwnedValue> {
    let reply = conn
        .call_method(
            Some(RESOLVE1),
            path,
            Some(DBUS_PROPS),
            "Get",
            &(RESOLVE1_LINK, name),
        )
        .await
        .ok()?;
    reply.body().deserialize::<OwnedValue>().ok()
}

/// `a(iay)` → `IpAddr` list: each entry is (address family, packed bytes).
fn decode_addresses(value: Option<&OwnedValue>) -> Vec<IpAddr> {
    let Some(value) = value else {
        return Vec::new();
    };
    Vec::<(i32, Vec<u8>)>::try_from(value.clone())
        .map(|items| items.iter().filter_map(decode_address).collect())
        .unwrap_or_default()
}

fn decode_address((family, bytes): &(i32, Vec<u8>)) -> Option<IpAddr> {
    match (*family, bytes.as_slice()) {
        (libc::AF_INET, [a, b, c, d]) => Some(IpAddr::from([*a, *b, *c, *d])),
        (libc::AF_INET6, bytes) if bytes.len() == 16 => {
            let mut addr = [0u8; 16];
            addr.copy_from_slice(bytes);
            Some(IpAddr::from(addr))
        }
        _ => None,
    }
}

/// `nameserver` lines of /etc/resolv.conf — what applications actually
/// get from glibc, even when resolved is absent.
fn resolv_conf_nameservers() -> Vec<IpAddr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|text| {
            text.lines()
                .filter_map(|line| {
                    let mut parts = line.split_whitespace();
                    match (parts.next(), parts.next()) {
                        (Some("nameserver"), Some(addr)) => addr.parse().ok(),
                        _ => None,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// (ifindex, name) of every kernel interface — resolved link objects are
/// only addressable by ifindex and newer systemd has no `Links` list.
fn system_links() -> Vec<(u32, String)> {
    std::fs::read_dir("/sys/class/net")
        .map(|entries| {
            entries
                .filter_map(|entry| {
                    let entry = entry.ok()?;
                    let name = entry.file_name().to_str()?.to_string();
                    let index: u32 = std::fs::read_to_string(entry.path().join("ifindex"))
                        .ok()?
                        .trim()
                        .parse()
                        .ok()?;
                    Some((index, name))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// `net.dns.status`: per-link resolver inventory from systemd-resolved,
/// plus the resolv.conf stub view. `available: false` means the bus or
/// the service is gone — the stub list still carries what apps see.
pub async fn status() -> io::Result<NetDnsStatusResult> {
    let resolv_conf = resolv_conf_nameservers();
    let conn = match bus().await {
        Ok(conn) => conn,
        Err(_) => {
            return Ok(NetDnsStatusResult {
                links: Vec::new(),
                available: false,
                resolv_conf,
            })
        }
    };
    let mut result = Vec::new();
    for (index, name) in system_links() {
        // Resolved escapes the leading digit (`_3<ifindex>`) — a missing
        // object means the interface carries no DNS configuration.
        let path = format!("{RESOLVE1_ROOT}/link/_3{index}");
        let servers = decode_addresses(property(conn, &path, "DNS").await.as_ref());
        let current_server = property(conn, &path, "CurrentDNSServer")
            .await
            .as_ref()
            .and_then(|value| {
                <(i32, Vec<u8>)>::try_from((*value).clone())
                    .ok()
                    .and_then(|server| decode_address(&server))
            });
        let domains: Vec<DnsDomain> = property(conn, &path, "Domains")
            .await
            .as_ref()
            .and_then(|value| Vec::<(String, bool)>::try_from((*value).clone()).ok())
            .unwrap_or_default()
            .into_iter()
            .map(|(domain, route_only)| DnsDomain { domain, route_only })
            .collect();
        let default_route = property(conn, &path, "DefaultRoute")
            .await
            .as_ref()
            .and_then(|value| bool::try_from((*value).clone()).ok())
            .unwrap_or(false);
        if servers.is_empty() && current_server.is_none() && domains.is_empty() && !default_route {
            continue;
        }
        result.push(DnsLinkStatus {
            interface_index: index,
            interface_name: name,
            servers,
            current_server,
            domains,
            default_route,
        });
    }
    Ok(NetDnsStatusResult {
        links: result,
        available: true,
        resolv_conf,
    })
}

/// `net.dns.probe`: resolve `server` (explicit, the resolved
/// default-route link's current server, or the resolv.conf stub), look up
/// the egress route for it, then send a real UDP query and parse the
/// answer section. The result shows where the query left the box.
pub async fn probe(
    observer: Arc<dyn NetworkObservation>,
    params: NetDnsProbeParams,
) -> io::Result<NetDnsProbeResult> {
    let hostname = params.hostname.trim_end_matches('.').to_string();
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname
            .chars()
            .any(|c| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid hostname",
        ));
    }
    let server = match params.server {
        Some(server) => server,
        None => default_resolver().await.ok_or_else(|| {
            io::Error::new(io::ErrorKind::NotFound, "no DNS server is configured")
        })?,
    };
    let lookup = observer.route_lookup(server).ok();
    let answers =
        tokio::time::timeout(PROBE_TIMEOUT, query(server, &hostname, params.family)).await;
    let answers = match answers {
        Ok(inner) => inner?,
        Err(_) => {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "DNS query timed out",
            ))
        }
    };
    let lookup = lookup.unwrap_or(RouteLookup {
        source: None,
        interface_index: None,
        interface_name: None,
        gateway: None,
        table: 0,
    });
    Ok(NetDnsProbeResult {
        server,
        source: lookup.source,
        interface_index: lookup.interface_index,
        interface_name: lookup.interface_name,
        gateway: lookup.gateway,
        answers: answers.0,
        status: answers.1,
        rtt_ms: answers.2,
    })
}

/// The resolver a default DNS query would hit: resolved's current server
/// on a default-route link, else the first resolv.conf nameserver.
async fn default_resolver() -> Option<IpAddr> {
    let status = status().await.ok()?;
    status
        .links
        .iter()
        .find(|link| link.default_route && link.current_server.is_some())
        .and_then(|link| link.current_server)
        .or_else(|| {
            status
                .links
                .iter()
                .find_map(|link| link.current_server)
                .or_else(|| status.resolv_conf.first().copied())
        })
}

// --- Minimal DNS message codec -------------------------------------------

fn encode_query(id: u16, hostname: &str, qtype: u16) -> Vec<u8> {
    let mut packet = Vec::with_capacity(64);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    packet.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    packet.extend_from_slice(&[0; 6]); // ANCOUNT/NSCOUNT/ARCOUNT
    for label in hostname.split('.') {
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&1u16.to_be_bytes()); // IN
    packet
}

/// Read one compressed-or-plain domain name at `offset`; returns the
/// name and the offset right after the wire encoding.
fn read_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = offset;
    let mut next = None;
    for _ in 0..64 {
        let len = *packet.get(cursor)? as usize;
        if len & 0xC0 == 0xC0 {
            let pointer = ((len & 0x3F) << 8) | *packet.get(cursor + 1)? as usize;
            if next.is_none() {
                next = Some(cursor + 2);
            }
            cursor = pointer;
            continue;
        }
        if len == 0 {
            return Some((labels.join("."), next.unwrap_or(cursor + 1)));
        }
        cursor += 1;
        labels.push(String::from_utf8_lossy(packet.get(cursor..cursor + len)?).into_owned());
        cursor += len;
    }
    None
}

fn rtype_name(rtype: u16) -> &'static str {
    match rtype {
        1 => "A",
        2 => "NS",
        5 => "CNAME",
        12 => "PTR",
        16 => "TXT",
        28 => "AAAA",
        65 => "HTTPS",
        _ => "TYPE",
    }
}

/// Parse the answer section into dig-style `name TTL TYPE data` lines.
fn parse_answers(packet: &[u8]) -> Option<(Vec<String>, String)> {
    if packet.len() < 12 {
        return None;
    }
    let rcode = packet[3] & 0x0F;
    let status = match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        5 => "REFUSED",
        _ => "STATUS",
    }
    .to_string();
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut cursor = 12;
    for _ in 0..qdcount {
        let (_, end) = read_name(packet, cursor)?;
        cursor = end + 4; // qtype + qclass
    }
    let mut answers = Vec::new();
    for _ in 0..ancount {
        let (name, end) = read_name(packet, cursor)?;
        cursor = end;
        let rtype = u16::from_be_bytes([*packet.get(cursor)?, *packet.get(cursor + 1)?]);
        let ttl = u32::from_be_bytes([
            *packet.get(cursor + 4)?,
            *packet.get(cursor + 5)?,
            *packet.get(cursor + 6)?,
            *packet.get(cursor + 7)?,
        ]);
        let rdlen =
            u16::from_be_bytes([*packet.get(cursor + 8)?, *packet.get(cursor + 9)?]) as usize;
        cursor += 10;
        let rdata = packet.get(cursor..cursor + rdlen)?;
        let data = match (rtype, rdata.len()) {
            (1, 4) => IpAddr::from([rdata[0], rdata[1], rdata[2], rdata[3]]).to_string(),
            (28, 16) => {
                let mut bytes = [0u8; 16];
                bytes.copy_from_slice(rdata);
                IpAddr::from(bytes).to_string()
            }
            (5, _) | (2, _) | (12, _) => read_name(packet, cursor)
                .map(|(name, _)| name)
                .unwrap_or_default(),
            _ => format!("\\# {rdlen}"),
        };
        answers.push(format!("{name} {ttl} {} {data}", rtype_name(rtype)));
        cursor += rdlen;
    }
    Some((answers, status))
}

async fn query(
    server: IpAddr,
    hostname: &str,
    family: Option<IpFamily>,
) -> io::Result<(Vec<String>, String, u64)> {
    let qtype = match family {
        Some(IpFamily::Ipv6) => 28,
        _ => 1,
    };
    let id = (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.subsec_micros())
        .unwrap_or_default()
        & 0xFFFF) as u16;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = tokio::net::UdpSocket::bind(bind).await?;
    socket.connect(SocketAddr::new(server, 53)).await?;
    let started = std::time::Instant::now();
    socket.send(&encode_query(id, hostname, qtype)).await?;
    let mut buffer = [0u8; 4096];
    let len = socket.recv(&mut buffer).await?;
    let rtt_ms = started.elapsed().as_millis() as u64;
    let packet = &buffer[..len];
    if packet.len() < 4 || u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "malformed DNS response",
        ));
    }
    let (answers, status) = parse_answers(packet)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "malformed DNS response"))?;
    Ok((answers, status, rtt_ms))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_query_builds_a_valid_question() {
        let packet = encode_query(0x1234, "example.com", 1);
        assert_eq!(&packet[..4], &[0x12, 0x34, 0x01, 0x00]);
        assert_eq!(u16::from_be_bytes([packet[4], packet[5]]), 1);
        // example.com → 7 'example' 3 'com' 0 QTYPE A QCLASS IN
        assert_eq!(&packet[12..25], b"\x07example\x03com\x00");
        assert_eq!(&packet[25..], &[0, 1, 0, 1]);
    }

    #[test]
    fn read_name_follows_pointers() {
        let packet = encode_query(1, "example.com", 1);
        let (name, end) = read_name(&packet, 12).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, 25);
        // A pointer at the answer position must resolve back to the qname.
        let mut reply = packet.clone();
        reply.extend_from_slice(&[0xC0, 0x0C]);
        let (name, end) = read_name(&reply, 29).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(end, 31);
    }

    #[test]
    fn parse_answers_reads_a_records() {
        // Header: id, flags(0x8180), qd=1, an=1; question; answer with a
        // compression pointer back to the qname.
        let mut packet = encode_query(1, "example.com", 1);
        packet[2] = 0x81;
        packet[3] = 0x80;
        packet[7] = 1;
        packet.extend_from_slice(&[0xC0, 0x0C]); // name
        packet.extend_from_slice(&[0, 1, 0, 1]); // A, IN
        packet.extend_from_slice(&[0, 0, 0, 60]); // TTL
        packet.extend_from_slice(&[0, 4]); // rdlen
        packet.extend_from_slice(&[93, 184, 216, 34]); // 93.184.216.34
        let (answers, status) = parse_answers(&packet).unwrap();
        assert_eq!(status, "NOERROR");
        assert_eq!(answers, vec!["example.com 60 A 93.184.216.34"]);
    }

    #[test]
    fn parse_answers_reports_nxdomain() {
        let mut packet = encode_query(1, "missing.example", 1);
        packet[3] = 0x83;
        let (answers, status) = parse_answers(&packet).unwrap();
        assert_eq!(status, "NXDOMAIN");
        assert!(answers.is_empty());
    }

    #[test]
    fn resolv_conf_parses_nameservers() {
        // The parser reads the live file; just assert it does not panic
        // and produces parseable addresses.
        for server in resolv_conf_nameservers() {
            assert!(!server.is_unspecified());
        }
    }
}
