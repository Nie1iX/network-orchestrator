//! Exit-IP checkers: concurrent HTTPS requests to IP-echo services.
//!
//! Each request traverses normal OS routing, so when a TUN profile is up the
//! tunnel's split rules classify every checker domain — the returned IP shows
//! which outbound actually served it (proxy exit vs ISP), which is the whole
//! point of the panel. Results stream to the frontend over a channel as each
//! checker resolves; a best-effort `ipwho.is` lookup annotates the exit IP
//! with a country code.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::time::Duration;
use tauri::ipc::Channel;

const TIMEOUT: Duration = Duration::from_secs(8);
const MAX_BODY_BYTES: usize = 256 * 1024;

/// `(display name, fallback URLs in order)`. Endpoints return the caller IP
/// as plain text or inside a small JSON body; the parser extracts the first
/// valid IP token.
const CHECKERS: &[(&str, &[&str])] = &[
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
pub(crate) struct ExitIpEntry {
    pub name: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub error: Option<String>,
}

/// Channel events: `Pending` lists checker names up front so rows render
/// instantly; `Result` arrives per checker as it completes.
#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub(crate) enum ExitIpEvent {
    Pending { names: Vec<String> },
    Result { entry: ExitIpEntry },
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

async fn check_one(client: reqwest::Client, name: &str, urls: &[&str]) -> ExitIpEntry {
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

#[tauri::command]
pub(crate) async fn check_exit_ips(on_event: Channel<ExitIpEvent>) {
    let Ok(client) = reqwest::Client::builder().timeout(TIMEOUT).build() else {
        for (name, _) in CHECKERS {
            let _ = on_event.send(ExitIpEvent::Result {
                entry: ExitIpEntry {
                    name: name.to_string(),
                    ip: None,
                    country: None,
                    error: Some("client unavailable".to_string()),
                },
            });
        }
        return;
    };
    let _ = on_event.send(ExitIpEvent::Pending {
        names: CHECKERS.iter().map(|(name, _)| name.to_string()).collect(),
    });
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ExitIpEntry>();
    for &(name, urls) in CHECKERS {
        let client = client.clone();
        let tx = tx.clone();
        tokio::spawn(async move {
            let _ = tx.send(check_one(client, name, urls).await);
        });
    }
    drop(tx);
    while let Some(entry) = rx.recv().await {
        let _ = on_event.send(ExitIpEvent::Result { entry });
    }
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
