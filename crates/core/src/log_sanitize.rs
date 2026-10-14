//! Masking of routable identifiers in log lines surfaced to the UI or
//! diagnostics.
//!
//! Public IPv4/IPv6 addresses and hostnames are masked; private, loopback,
//! link-local, multicast and unspecified addresses plus `localhost`/`.local`
//! names and obvious file names pass through — they identify the local
//! environment, not the user. The module complements
//! `vpn::redact_runtime_log`, which strips credentials: this one covers the
//! addresses and hostnames the runtime happily logs.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Whether an IPv4 address denotes the local environment rather than a
/// routable remote host.
fn keep_ipv4(ip: &Ipv4Addr) -> bool {
    ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_unspecified()
        || ip.is_broadcast()
        || ip.octets()[0] == 0
}

fn keep_ipv6(ip: &Ipv6Addr) -> bool {
    ip.is_loopback()
        || ip.is_multicast()
        || ip.is_unspecified()
        // fc00::/7 ULA
        || (ip.segments()[0] & 0xfe00) == 0xfc00
        // fe80::/10 link-local
        || (ip.segments()[0] & 0xffc0) == 0xfe80
        // IPv4-mapped ::ffff:a.b.c.d follows the IPv4 rules.
        || ip.to_ipv4_mapped().is_some_and(|v4| keep_ipv4(&v4))
}

fn mask_ipv4(ip: &Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.x.x", o[0], o[1])
}

fn mask_ipv6(ip: &Ipv6Addr) -> String {
    let s = ip.segments();
    format!("{:x}:{:x}::", s[0], s[1])
}

/// File-name suffixes that look like hostnames but are local artefacts
/// (`xray.log`, `geoip.dat`, …) — masking them makes logs unreadable.
const FILE_SUFFIXES: &[&str] = &[
    "log", "dat", "json", "conf", "txt", "exe", "dll", "so", "pid", "tmp", "md", "yaml", "yml",
    "toml", "lock", "db", "sock", "pid", "plist", "pem", "crt",
];

fn is_domain_shaped(token: &str) -> bool {
    let labels: Vec<&str> = token.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let last = labels.last().unwrap();
    // TLD must be alpha (or punycode); rejects version strings like "1.2.3".
    if !((2..=63).contains(&last.len())
        && last.bytes().all(|b| b.is_ascii_alphabetic() || b == b'-')
        && last.bytes().any(|b| b.is_ascii_alphabetic()))
    {
        return false;
    }
    if FILE_SUFFIXES.contains(&last.to_ascii_lowercase().as_str()) {
        return false;
    }
    labels[..labels.len() - 1].iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

fn mask_domain(token: &str) -> String {
    let labels: Vec<&str> = token.split('.').collect();
    // Keep at most the last two labels — for a bare `host.tld` that leaves
    // only the TLD, which is the point.
    let keep = &labels[labels.len().saturating_sub(2).max(1)..];
    format!("*.{}", keep.join("."))
}

/// Masks a single token: bare IPs, `host:port`, `[v6]:port`, CIDRs and
/// hostnames.
fn mask_token(token: &str) -> String {
    if token.is_empty() || token == "localhost" || token.ends_with(".local") {
        return token.to_string();
    }
    if let Ok(ip) = token.parse::<Ipv4Addr>() {
        return if keep_ipv4(&ip) {
            token.to_string()
        } else {
            mask_ipv4(&ip)
        };
    }
    if let Ok(ip) = token.parse::<Ipv6Addr>() {
        return if keep_ipv6(&ip) {
            token.to_string()
        } else {
            mask_ipv6(&ip)
        };
    }
    // `host:port` — only when the port part is numeric, so IPv6 literals
    // and Windows paths are not mistaken for it.
    if let Some((host, port)) = token.rsplit_once(':') {
        if !host.contains(':')
            && !port.is_empty()
            && port.bytes().all(|b| b.is_ascii_digit())
            && port.parse::<u16>().is_ok()
        {
            return format!("{}:{port}", mask_token(host));
        }
    }
    if let Some(inner) = token.strip_prefix('[') {
        if let Some((host, suffix)) = inner.split_once(']') {
            return format!("[{}]{suffix}", mask_token(host));
        }
    }
    if let Ok(net) = token.parse::<ipnet::IpNet>() {
        let masked = match net.addr() {
            IpAddr::V4(v4) if !keep_ipv4(&v4) => mask_ipv4(&v4),
            IpAddr::V6(v6) if !keep_ipv6(&v6) => mask_ipv6(&v6),
            _ => return token.to_string(),
        };
        return format!("{masked}/{}", net.prefix_len());
    }
    if is_domain_shaped(token) {
        return mask_domain(token);
    }
    token.to_string()
}

/// Masks identifiers inside one whitespace-separated token; tokens with
/// `scheme://` are handled on the authority part so URLs keep their path.
fn mask_word(word: &str) -> String {
    if let Some((scheme, rest)) = word.split_once("://") {
        if !scheme.is_empty()
            && scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            let authority = &rest[..end];
            return format!("{scheme}://{}{}", mask_token(authority), &rest[end..]);
        }
    }
    mask_token(word)
}

/// Masks public IPs and hostnames in a log line, leaving whitespace,
/// punctuation and private/local identifiers untouched.
pub fn sanitize_log_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut word_start: Option<usize> = None;
    for (index, ch) in line.char_indices() {
        if ch.is_whitespace()
            || matches!(
                ch,
                '"' | '\'' | '<' | '>' | '(' | ')' | ',' | ';' | '|' | '{' | '}'
            )
        {
            if let Some(start) = word_start.take() {
                out.push_str(&mask_word(&line[start..index]));
            }
            out.push(ch);
        } else if word_start.is_none() {
            word_start = Some(index);
        }
    }
    if let Some(start) = word_start {
        out.push_str(&mask_word(&line[start..]));
    }
    out
}

/// Whole log text: lines are sanitized independently.
pub fn sanitize_log_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        out.push_str(&sanitize_log_line(line.trim_end_matches('\n')));
        if line.ends_with('\n') {
            out.push('\n');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_ipv4_is_masked_private_kept() {
        assert_eq!(
            sanitize_log_line("dial tcp 203.0.113.7:443"),
            "dial tcp 203.0.x.x:443"
        );
        assert_eq!(
            sanitize_log_line("route 192.168.1.10 via 10.0.0.1"),
            "route 192.168.1.10 via 10.0.0.1"
        );
    }

    #[test]
    fn ipv6_masked_with_prefix_kept() {
        assert_eq!(
            sanitize_log_line("udp 2001:db8:85a3::8a2e:370:7334"),
            "udp 2001:db8::"
        );
        assert_eq!(
            sanitize_log_line("[2001:db8::1]:443 ::1 fe80::1"),
            "[2001:db8::]:443 ::1 fe80::1"
        );
    }

    #[test]
    fn domains_are_masked_but_files_kept() {
        assert_eq!(
            sanitize_log_line("dns query api.evil-tracker.example.com"),
            "dns query *.example.com"
        );
        assert_eq!(
            sanitize_log_line("open xray.log geoip.dat localhost"),
            "open xray.log geoip.dat localhost"
        );
        // Version-like tokens are not domains.
        assert_eq!(sanitize_log_line("v 1.2.3 ok"), "v 1.2.3 ok");
    }

    #[test]
    fn urls_keep_scheme_and_path() {
        assert_eq!(
            sanitize_log_line("GET https://dns.google/dns-query?q=1"),
            "GET https://*.google/dns-query?q=1"
        );
    }

    #[test]
    fn cidrs_and_plain_text_pass_through() {
        assert_eq!(sanitize_log_line("route 10.0.0.0/8"), "route 10.0.0.0/8");
        assert_eq!(
            sanitize_log_line("default via 45.67.0.0/16"),
            "default via 45.67.x.x/16"
        );
    }
}
