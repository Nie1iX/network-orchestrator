//! A small DNS client for diagnostics: one query to a chosen server, answered
//! like `dig` would show it. It exists to see which server and path a name
//! really takes (for instance a fake-IP answer from another tunnel), so it
//! speaks plain UDP, asks one question and trusts nothing in the reply.

use serde::{Deserialize, Serialize};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub const MAX_ANSWERS: usize = 16;
const MAX_PACKET: usize = 4096;
const MAX_NAME_JUMPS: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DnsFamily {
    A,
    Aaaa,
}

impl DnsFamily {
    fn qtype(self) -> u16 {
        match self {
            Self::A => 1,
            Self::Aaaa => 28,
        }
    }
}

/// What a reply said, before the caller adds the path and the timing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedResponse {
    pub status: String,
    pub answers: Vec<String>,
    pub truncated: bool,
    /// An A answer lies in `198.18.0.0/15`, where fake-IP DNS hands out
    /// placeholders that are never real hosts.
    pub fake_pool: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsProbeResult {
    pub server: IpAddr,
    pub port: u16,
    pub status: String,
    pub answers: Vec<String>,
    pub truncated: bool,
    pub fake_pool: bool,
    pub rtt_ms: u64,
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The query packet, or `None` for a name that is not a plain ASCII host name.
pub fn build_query(host: &str, family: DnsFamily, id: u16) -> Option<Vec<u8>> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() || host.len() > 253 {
        return None;
    }
    let mut packet = Vec::with_capacity(host.len() + 18);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in host.split('.') {
        if !valid_label(label) {
            return None;
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.to_ascii_lowercase().as_bytes());
    }
    packet.push(0);
    packet.extend_from_slice(&family.qtype().to_be_bytes());
    packet.extend_from_slice(&[0, 1]);
    Some(packet)
}

/// A name at `offset`, following compression pointers a bounded number of
/// times; returns it and the offset just past it in the original position.
fn read_name(packet: &[u8], offset: usize) -> Option<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut position = offset;
    let mut after = None;
    let mut jumps = 0;
    loop {
        let length = *packet.get(position)? as usize;
        if length == 0 {
            return Some((labels.join("."), after.unwrap_or(position + 1)));
        }
        if length & 0xc0 == 0xc0 {
            let low = *packet.get(position + 1)? as usize;
            after.get_or_insert(position + 2);
            jumps += 1;
            if jumps > MAX_NAME_JUMPS {
                return None;
            }
            position = ((length & 0x3f) << 8) | low;
            continue;
        }
        if length > 63 {
            return None;
        }
        let label = packet.get(position + 1..position + 1 + length)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        position += 1 + length;
        if labels.iter().map(|l| l.len() + 1).sum::<usize>() > 255 {
            return None;
        }
    }
}

fn status_name(rcode: u8) -> String {
    match rcode {
        0 => "NOERROR".into(),
        1 => "FORMERR".into(),
        2 => "SERVFAIL".into(),
        3 => "NXDOMAIN".into(),
        4 => "NOTIMP".into(),
        5 => "REFUSED".into(),
        other => format!("RCODE{other}"),
    }
}

fn is_fake_pool(ip: Ipv4Addr) -> bool {
    ip.octets()[0] == 198 && ip.octets()[1] & 0xfe == 18
}

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.to_string())
}

pub fn parse_response(packet: &[u8], id: u16) -> io::Result<ParsedResponse> {
    if packet.len() < 12 {
        return Err(bad("the DNS reply is too short"));
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != id {
        return Err(bad("the DNS reply answers another query"));
    }
    if packet[2] & 0x80 == 0 {
        return Err(bad("the DNS packet is not a reply"));
    }
    let truncated = packet[2] & 0x02 != 0;
    let status = status_name(packet[3] & 0x0f);
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answer_count = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;
    for _ in 0..questions {
        let (_, next) = read_name(packet, offset).ok_or_else(|| bad("bad question name"))?;
        offset = next + 4;
        if offset > packet.len() {
            return Err(bad("the DNS question is cut off"));
        }
    }
    let mut answers = Vec::new();
    let mut fake_pool = false;
    for _ in 0..answer_count.min(MAX_ANSWERS) {
        let (name, next) = read_name(packet, offset).ok_or_else(|| bad("bad answer name"))?;
        let fixed = packet
            .get(next..next + 10)
            .ok_or_else(|| bad("the DNS answer is cut off"))?;
        let kind = u16::from_be_bytes([fixed[0], fixed[1]]);
        let ttl = u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
        let length = u16::from_be_bytes([fixed[8], fixed[9]]) as usize;
        let data_at = next + 10;
        let data = packet
            .get(data_at..data_at + length)
            .ok_or_else(|| bad("the DNS answer data is cut off"))?;
        let rendered = match (kind, length) {
            (1, 4) => {
                let ip = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
                fake_pool |= is_fake_pool(ip);
                format!("A {ip}")
            }
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(data);
                format!("AAAA {}", Ipv6Addr::from(octets))
            }
            (5, _) => {
                let (target, _) =
                    read_name(packet, data_at).ok_or_else(|| bad("bad CNAME target"))?;
                format!("CNAME {target}")
            }
            (other, _) => format!("TYPE{other}"),
        };
        answers.push(format!("{name} {ttl} {rendered}"));
        offset = data_at + length;
    }
    Ok(ParsedResponse {
        status,
        answers,
        truncated,
        fake_pool,
    })
}

/// Sends one query to `server` and waits for the matching reply.
pub fn probe(
    hostname: &str,
    server: SocketAddr,
    family: DnsFamily,
    timeout: Duration,
) -> io::Result<DnsProbeResult> {
    let id = (std::process::id() as u16)
        ^ (Instant::now().elapsed().subsec_nanos() as u16)
        ^ std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u16)
            .unwrap_or(0x4e4f);
    let query = build_query(hostname, family, id).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "that is not a valid host name")
    })?;
    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind)?;
    socket.connect(server)?;
    let started = Instant::now();
    socket.send(&query)?;
    let mut buffer = vec![0u8; MAX_PACKET];
    loop {
        let left = timeout.saturating_sub(started.elapsed());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "the DNS server did not answer in time",
            ));
        }
        socket.set_read_timeout(Some(left))?;
        let length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the DNS server did not answer in time",
                ))
            }
            Err(error) => return Err(error),
        };
        // A reply for another query (or junk) is skipped, not trusted.
        let Ok(parsed) = parse_response(&buffer[..length], id) else {
            continue;
        };
        return Ok(DnsProbeResult {
            server: server.ip(),
            port: server.port(),
            status: parsed.status,
            answers: parsed.answers,
            truncated: parsed.truncated,
            fake_pool: parsed.fake_pool,
            rtt_ms: started.elapsed().as_millis() as u64,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;

    /// Header (id 0x4e4f, QR+RD+RA, rcode `rcode`), the question for
    /// `example.com`, then `answers` raw.
    fn response(rcode: u8, ancount: u16, qtype: u16, answers: &[u8]) -> Vec<u8> {
        let mut p = vec![
            0x4e,
            0x4f,
            0x81,
            0x80 | rcode,
            0,
            1,
            (ancount >> 8) as u8,
            ancount as u8,
            0,
            0,
            0,
            0,
        ];
        p.extend_from_slice(b"\x07example\x03com\x00");
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&[0, 1]);
        p.extend_from_slice(answers);
        p
    }

    #[test]
    fn a_query_asks_for_one_name_with_recursion_desired() {
        let query = build_query("Example.COM.", DnsFamily::A, 0x4e4f).unwrap();
        assert_eq!(&query[..4], &[0x4e, 0x4f, 0x01, 0x00]);
        assert_eq!(&query[4..6], &[0, 1]);
        assert_eq!(&query[12..], b"\x07example\x03com\x00\x00\x01\x00\x01");
        let aaaa = build_query("example.com", DnsFamily::Aaaa, 1).unwrap();
        assert_eq!(&aaaa[aaaa.len() - 4..], &[0, 28, 0, 1]);
    }

    #[test]
    fn hostnames_are_validated_before_anything_is_sent() {
        for bad in [
            "",
            ".",
            "a..b",
            "-",
            &"a".repeat(64),
            &format!("{}.com", "a.".repeat(130)),
            "sp ace.com",
            "ünï.com",
            "a/b.com",
        ] {
            assert!(build_query(bad, DnsFamily::A, 1).is_none(), "{bad:?}");
        }
        assert!(build_query("_dmarc.example.com", DnsFamily::A, 1).is_some());
        assert!(build_query("xn--80ak6aa92e.com", DnsFamily::A, 1).is_some());
    }

    #[test]
    fn an_a_answer_with_a_compressed_name_is_rendered_like_dig() {
        // name pointer to offset 12, type A, class IN, ttl 300, 4 bytes
        let answer = [
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 0x2c, 0, 4, 93, 184, 216, 34,
        ];
        let parsed = parse_response(&response(0, 1, 1, &answer), 0x4e4f).unwrap();
        assert_eq!(parsed.status, "NOERROR");
        assert_eq!(parsed.answers, ["example.com 300 A 93.184.216.34"]);
        assert!(!parsed.truncated);
    }

    #[test]
    fn aaaa_and_cname_answers_are_decoded() {
        let mut answers = vec![0xc0, 0x0c, 0, 5, 0, 1, 0, 0, 0, 60, 0, 6];
        answers.extend_from_slice(b"\x03www\xc0\x0c"); // www + pointer to example.com
        answers.extend_from_slice(&[0xc0, 0x0c, 0, 28, 0, 1, 0, 0, 0, 10, 0, 16]);
        answers.extend_from_slice(&[0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        let parsed = parse_response(&response(0, 2, 28, &answers), 0x4e4f).unwrap();
        assert_eq!(
            parsed.answers,
            [
                "example.com 60 CNAME www.example.com",
                "example.com 10 AAAA 2001:db8::1"
            ]
        );
    }

    #[test]
    fn dns_failure_codes_get_their_names() {
        let status = |rcode| {
            parse_response(&response(rcode, 0, 1, &[]), 0x4e4f)
                .unwrap()
                .status
        };
        assert_eq!(status(0), "NOERROR");
        assert_eq!(status(2), "SERVFAIL");
        assert_eq!(status(3), "NXDOMAIN");
        assert_eq!(status(5), "REFUSED");
        assert_eq!(status(9), "RCODE9");
    }

    #[test]
    fn the_truncation_bit_is_reported() {
        let mut packet = response(0, 0, 1, &[]);
        packet[2] |= 0x02;
        assert!(parse_response(&packet, 0x4e4f).unwrap().truncated);
    }

    #[test]
    fn a_fake_ip_answer_is_recognised() {
        let answer = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 198, 18, 0, 7];
        let parsed = parse_response(&response(0, 1, 1, &answer), 0x4e4f).unwrap();
        assert!(parsed.fake_pool);
        let real = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 8, 8, 8, 8];
        assert!(
            !parse_response(&response(0, 1, 1, &real), 0x4e4f)
                .unwrap()
                .fake_pool
        );
    }

    #[test]
    fn malformed_packets_are_errors_not_panics() {
        let ok = response(
            0,
            1,
            1,
            &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 2, 3, 4],
        );
        assert!(parse_response(&ok, 0x1111).is_err(), "wrong id");
        assert!(parse_response(&ok[..5], 0x4e4f).is_err(), "short header");
        assert!(
            parse_response(&ok[..ok.len() - 2], 0x4e4f).is_err(),
            "cut rdata"
        );
        let mut not_response = ok.clone();
        not_response[2] &= 0x7f;
        assert!(
            parse_response(&not_response, 0x4e4f).is_err(),
            "not a response"
        );
        // A pointer that points at itself must not loop forever.
        let mut pointer_loop = response(0, 1, 1, &[]);
        let at = pointer_loop.len();
        pointer_loop.extend_from_slice(&[0xc0, at as u8, 0, 1, 0, 1, 0, 0, 0, 1, 0, 0]);
        assert!(parse_response(&pointer_loop, 0x4e4f).is_err());
        for len in 0..ok.len() {
            let _ = parse_response(&ok[..len], 0x4e4f); // never panics
        }
    }

    #[test]
    fn at_most_sixteen_answers_are_kept() {
        let one = [0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4, 1, 1, 1, 1];
        let many: Vec<u8> = one.iter().copied().cycle().take(one.len() * 40).collect();
        let parsed = parse_response(&response(0, 40, 1, &many), 0x4e4f).unwrap();
        assert_eq!(parsed.answers.len(), MAX_ANSWERS);
    }

    #[test]
    fn a_real_exchange_over_loopback_measures_the_round_trip() {
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        let address = server.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let mut buffer = [0u8; 512];
            let (len, peer) = server.recv_from(&mut buffer).unwrap();
            let id = [buffer[0], buffer[1]];
            let mut reply = response(
                0,
                1,
                1,
                &[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 5, 0, 4, 10, 0, 0, 9],
            );
            reply[0] = id[0];
            reply[1] = id[1];
            server.send_to(&reply, peer).unwrap();
            len
        });
        let result = probe("example.com", address, DnsFamily::A, Duration::from_secs(2)).unwrap();
        assert!(handle.join().unwrap() > 12);
        assert_eq!(result.status, "NOERROR");
        assert_eq!(result.answers, ["example.com 5 A 10.0.0.9"]);
        assert_eq!(result.server, address.ip());
    }

    #[test]
    fn a_silent_server_times_out_and_a_bad_name_never_leaves_the_machine() {
        let silent = UdpSocket::bind("127.0.0.1:0").unwrap();
        let error = probe(
            "example.com",
            silent.local_addr().unwrap(),
            DnsFamily::A,
            Duration::from_millis(150),
        )
        .unwrap_err();
        assert!(matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ));
        let invalid = probe(
            "bad name",
            silent.local_addr().unwrap(),
            DnsFamily::A,
            Duration::from_millis(50),
        )
        .unwrap_err();
        assert_eq!(invalid.kind(), io::ErrorKind::InvalidInput);
    }
}
