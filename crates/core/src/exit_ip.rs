//! Exit-IP checkers: concurrent HTTPS requests to IP-echo services, either
//! over normal OS routing or through a loopback SOCKS proxy, so a client can
//! show which outbound actually serves its traffic. A best-effort `ipwho.is`
//! lookup annotates the exit IP with a country code.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;

pub const TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BODY_BYTES: usize = 256 * 1024;

/// `(display name, fallback URLs in order)`. Endpoints return the caller IP
/// as plain text or inside a small JSON body; the parser extracts the first
/// valid IP token.
pub const CHECKERS: &[(&str, &[&str])] = &[
    ("2ip.io", &["https://2ip.io", "https://api.2ip.io"]),
    (
        "ipify",
        &["https://api64.ipify.org", "https://api.ipify.org"],
    ),
    (
        "ifconfig.io",
        &["https://ifconfig.io/ip", "https://ifconfig.me/ip"],
    ),
    ("icanhazip", &["https://icanhazip.com"]),
    ("checkip.aws", &["https://checkip.amazonaws.com"]),
    ("ipinfo.io", &["https://ipinfo.io/ip"]),
];

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ExitIpEntry {
    pub name: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub error: Option<String>,
}

/// First `IpAddr`-parseable token in the body. Tokens are maximal runs of
/// `[0-9a-fA-F:.%]`; `%zone` suffixes are stripped before parsing.
fn extract_ip(body: &str) -> Option<IpAddr> {
    body.split(|c: char| !(c.is_ascii_hexdigit() || c == '.' || c == ':' || c == '%'))
        .filter_map(|token| {
            let token = token.split('%').next().unwrap_or(token);
            token.trim_matches(|c| c == '.' || c == ':').parse().ok()
        })
        .next()
}

async fn fetch_ip(client: &reqwest::Client, url: &str) -> Result<IpAddr, String> {
    let mut response = client
        .get(url)
        .send()
        .await
        .map_err(|_| "unreachable".to_string())?;
    if !response.status().is_success() {
        return Err(format!("HTTP {}", response.status()));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "read failed".to_string())?
    {
        if body.len() + chunk.len() > MAX_BODY_BYTES {
            return Err("response too large".to_string());
        }
        body.extend_from_slice(&chunk);
    }
    let text = String::from_utf8_lossy(&body);
    extract_ip(&text).ok_or_else(|| "no IP in response".to_string())
}

#[derive(Deserialize)]
struct GeoResponse {
    country_code: Option<String>,
}

/// Best-effort ISO country code for a queried IP via `ipwho.is` (free, no
/// key). Failures just leave the entry without a country.
async fn geo_lookup(client: &reqwest::Client, ip: &str) -> Option<String> {
    let body = client
        .get(format!("https://ipwho.is/{ip}?fields=country_code"))
        .send()
        .await
        .ok()?
        .bytes()
        .await
        .ok()?;
    serde_json::from_slice::<GeoResponse>(&body)
        .ok()?
        .country_code
        .filter(|code| !code.is_empty() && code.len() <= 3)
}

pub async fn check_one(client: reqwest::Client, name: &str, urls: &[&str]) -> ExitIpEntry {
    let mut entry = ExitIpEntry {
        name: name.to_string(),
        ip: None,
        country: None,
        error: Some("unreachable".to_string()),
    };
    for url in urls {
        match fetch_ip(&client, url).await {
            Ok(ip) => {
                let ip = ip.to_string();
                entry.country = geo_lookup(&client, &ip).await;
                entry.ip = Some(ip);
                entry.error = None;
                return entry;
            }
            Err(err) => entry.error = Some(err),
        }
    }
    entry
}

/// HTTP client for the checkers; `socks_port` routes them through a local
/// SOCKS5 proxy with remote DNS (an Xray connection) instead of the OS route.
pub fn client(socks_port: Option<u16>) -> std::io::Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().timeout(TIMEOUT).no_proxy();
    if let Some(port) = socks_port {
        builder = builder.proxy(
            reqwest::Proxy::all(format!("socks5h://127.0.0.1:{port}"))
                .map_err(std::io::Error::other)?,
        );
    }
    builder.build().map_err(std::io::Error::other)
}

/// Run every checker concurrently and return their entries in list order.
pub async fn check_all(client: reqwest::Client) -> Vec<ExitIpEntry> {
    let mut tasks = tokio::task::JoinSet::new();
    for (index, &(name, urls)) in CHECKERS.iter().enumerate() {
        let client = client.clone();
        tasks.spawn(async move { (index, check_one(client, name, urls).await) });
    }
    let mut entries = Vec::new();
    while let Some(Ok(result)) = tasks.join_next().await {
        entries.push(result);
    }
    entries.sort_by_key(|(index, _)| *index);
    entries.into_iter().map(|(_, entry)| entry).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ip_parses_plain_and_json_bodies() {
        assert_eq!(extract_ip("1.2.3.4\n").unwrap().to_string(), "1.2.3.4");
        assert_eq!(
            extract_ip(" 2001:db8::5 ").unwrap().to_string(),
            "2001:db8::5"
        );
        assert_eq!(
            extract_ip(r#"{"ip":"203.0.113.7","country":"NL"}"#)
                .unwrap()
                .to_string(),
            "203.0.113.7"
        );
        assert_eq!(
            extract_ip("<html><div class=ip>198.51.100.3</div></html>")
                .unwrap()
                .to_string(),
            "198.51.100.3"
        );
        assert!(extract_ip("no address here").is_none());
        assert!(extract_ip("999.999.999.999").is_none());
    }
}
