//! A minimal DNS client: one A query sent straight to a chosen server. The
//! system resolver can answer from another tunnel's fake-IP pool (Xray
//! `fakedns`, `198.18.0.0/15`); the OpenVPN server's real address then has to
//! come from the uplink's own resolvers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

const TIMEOUT: Duration = Duration::from_secs(2);
const QUERY_ID: u16 = 0x4e4f;
const MAX_ANSWERS: usize = 16;

/// Whether `ip` is in the benchmarking range (`198.18.0.0/15`) that fake-IP
/// DNS hands out; such an address is a placeholder, never a real host.
pub fn is_fake_pool(ip: &IpAddr) -> bool {
    matches!(ip, IpAddr::V4(v4) if v4.octets()[0] == 198 && v4.octets()[1] & 0xfe == 18)
}

fn build_query(host: &str) -> Option<Vec<u8>> {
    let mut packet = Vec::with_capacity(host.len() + 18);
    packet.extend_from_slice(&QUERY_ID.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&[0, 1, 0, 1]);
    Some(packet)
}

/// Offset just past the (possibly compressed) name at `at`.
fn skip_name(packet: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *packet.get(at)?;
        if len & 0xc0 == 0xc0 {
            return Some(at + 2);
        }
        if len == 0 {
            return Some(at + 1);
        }
        at += 1 + usize::from(len);
    }
}

fn parse_answers(packet: &[u8]) -> Vec<Ipv4Addr> {
    let parse = || -> Option<Vec<Ipv4Addr>> {
        if packet.len() < 12 || packet[..2] != QUERY_ID.to_be_bytes() || packet[2] & 0x80 == 0 {
            return None;
        }
        if packet[3] & 0x0f != 0 {
            return None;
        }
        let questions = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        let answers = usize::from(u16::from_be_bytes([packet[6], packet[7]]));
        let mut at = 12;
        for _ in 0..questions {
            at = skip_name(packet, at)? + 4;
        }
        let mut found = Vec::new();
        for _ in 0..answers.min(MAX_ANSWERS) {
            at = skip_name(packet, at)?;
            let header = packet.get(at..at + 10)?;
            let kind = u16::from_be_bytes([header[0], header[1]]);
            let len = usize::from(u16::from_be_bytes([header[8], header[9]]));
            let data = packet.get(at + 10..at + 10 + len)?;
            if kind == 1 && len == 4 {
                found.push(Ipv4Addr::new(data[0], data[1], data[2], data[3]));
            }
            at += 10 + len;
        }
        Some(found)
    };
    parse().unwrap_or_default()
}

/// The A records `server` returns for `host`; empty on any failure.
pub fn resolve_a(host: &str, server: IpAddr) -> io::Result<Vec<Ipv4Addr>> {
    let query = build_query(host).ok_or_else(|| io::Error::other("invalid host name"))?;
    let socket = UdpSocket::bind(if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })?;
    socket.set_read_timeout(Some(TIMEOUT))?;
    socket.set_write_timeout(Some(TIMEOUT))?;
    socket.connect(SocketAddr::new(server, 53))?;
    socket.send(&query)?;
    let mut buffer = [0u8; 1500];
    let read = socket.recv(&mut buffer)?;
    Ok(parse_answers(&buffer[..read]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fake_pool_is_198_18_0_0_15() {
        for ip in ["198.18.0.1", "198.19.255.254", "198.18.133.83"] {
            assert!(is_fake_pool(&ip.parse().unwrap()), "{ip}");
        }
        for ip in ["198.17.0.1", "198.20.0.1", "10.0.0.1", "::1"] {
            assert!(!is_fake_pool(&ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn a_query_has_one_question_for_the_host() {
        let query = build_query("vpn.example.").unwrap();
        assert_eq!(&query[4..6], &[0, 1]);
        assert_eq!(&query[12..], b"\x03vpn\x07example\x00\x00\x01\x00\x01");
        assert!(build_query("a..b").is_none());
        assert!(build_query(&"x".repeat(64)).is_none());
    }

    #[test]
    fn answers_with_compressed_names_are_read() {
        let mut reply = build_query("vpn.example").unwrap();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[7] = 2;
        // A CNAME first (skipped), then an A record; both name the question.
        reply.extend_from_slice(&[0xc0, 12, 0, 5, 0, 1, 0, 0, 0, 60, 0, 2, 0xc0, 12]);
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 203, 0, 113, 5]);
        assert_eq!(parse_answers(&reply), vec![Ipv4Addr::new(203, 0, 113, 5)]);
    }

    #[test]
    fn foreign_truncated_and_failed_replies_yield_nothing() {
        let mut reply = build_query("vpn.example").unwrap();
        reply[2] = 0x81;
        reply[7] = 1;
        assert!(parse_answers(&reply).is_empty(), "truncated");
        reply[3] = 0x83;
        assert!(parse_answers(&reply).is_empty(), "NXDOMAIN");
        reply[0] = 0;
        assert!(parse_answers(&reply).is_empty(), "wrong id");
        assert!(parse_answers(&[]).is_empty());
    }
}
