//! Bounded subscription loading and managed import shared by desktop clients.
use crate::{
    config_vault::{ConfigVault, SubscriptionEndpoint},
    models::*,
    profile_import::{profile_listener_ports, select_generated_ports},
    profiles::{ProfileDocument, ProfileStore},
    xray,
};
use std::{
    io,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

pub const MAX_SUBSCRIPTION_BODY_BYTES: usize = 1024 * 1024;
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}
fn failure(message: &str) -> io::Error {
    io::Error::other(message)
}

/// Decode a v2ray-style subscription body and count unsupported nonblank lines.
pub fn parse_subscription_body(body: &str) -> (Vec<String>, usize) {
    let decoded = base64_decode(body.trim()).unwrap_or_else(|| body.to_string());
    let mut urls = Vec::new();
    let mut skipped = 0;
    for line in decoded
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if line.starts_with("vless://")
            || line.starts_with("hysteria2://")
            || line.starts_with("hy2://")
        {
            urls.push(line.to_string());
        } else {
            skipped += 1;
        }
    }
    (urls, skipped)
}

pub fn parse_subscription_userinfo(value: &str) -> Option<SubscriptionUserInfo> {
    if value.len() > 512 {
        return None;
    }
    let mut upload = None;
    let mut download = None;
    let mut total = None;
    let mut expire = None;
    for field in value.split(';').take(16) {
        let Some((key, raw)) = field.trim().split_once('=') else {
            continue;
        };
        if !matches!(key.trim(), "upload" | "download" | "total" | "expire") {
            continue;
        }
        let number = raw.trim().parse::<u64>().ok()?;
        if number > 9_007_199_254_740_991 {
            return None;
        }
        match key.trim() {
            "upload" => upload = Some(number),
            "download" => download = Some(number),
            "total" => total = Some(number),
            "expire" => expire = Some(number),
            _ => {}
        }
    }
    Some(SubscriptionUserInfo {
        upload_bytes: upload?,
        download_bytes: download?,
        total_bytes: total.filter(|total| *total > 0),
        expires_at_unix: expire.filter(|expire| *expire > 0 && *expire <= 253_402_300_799),
    })
}

/// Best-effort standard base64 decoder that tolerates missing padding and
/// whitespace. Returns `None` if the input is not valid base64.
pub fn base64_decode(input: &str) -> Option<String> {
    use base64::Engine;
    let cleaned: String = input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() {
        return None;
    }
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    [STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD]
        .iter()
        .find_map(|engine| {
            engine
                .decode(&cleaned)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
        })
}

pub fn http_client() -> io::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .user_agent("v2rayng/1.0")
        .build()
        .map_err(|_| failure("Could not create the subscription HTTP client"))
}
pub fn validate_url(value: &str) -> io::Result<reqwest::Url> {
    let url = reqwest::Url::parse(value.trim())
        .map_err(|_| invalid("Enter a valid HTTP or HTTPS subscription URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(invalid("Enter a valid HTTP or HTTPS subscription URL"));
    }
    Ok(url)
}
pub struct FetchedSubscription {
    pub body: String,
    pub user_info: Option<SubscriptionUserInfo>,
}
pub async fn fetch(
    client: &reqwest::Client,
    source: &str,
    hwid: &str,
) -> io::Result<FetchedSubscription> {
    tokio::time::timeout(Duration::from_secs(30), fetch_inner(client, source, hwid))
        .await
        .map_err(|_| failure("Subscription request timed out"))?
}
async fn fetch_inner(
    client: &reqwest::Client,
    source: &str,
    hwid: &str,
) -> io::Result<FetchedSubscription> {
    let original = validate_url(source)?;
    let mut url = original.clone();
    let mut forward_hwid = true;
    for redirect in 0..=5 {
        let mut request = client.get(url.clone());
        if forward_hwid && !hwid.is_empty() {
            let mut header = reqwest::header::HeaderValue::from_str(hwid)
                .map_err(|_| invalid("Invalid subscription HWID"))?;
            header.set_sensitive(true);
            request = request.header("X-HWID", header);
        }
        let mut response = request.send().await.map_err(|_| {
            failure("Could not fetch the subscription. Check the URL and network connection.")
        })?;
        if matches!(response.status().as_u16(), 301 | 302 | 303 | 307 | 308) {
            if redirect == 5 {
                return Err(failure("Subscription redirected too many times"));
            }
            let next = response
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|location| url.join(location).ok())
                .ok_or_else(|| invalid("Invalid subscription redirect"))?;
            validate_url(next.as_str())?;
            if url.scheme() == "https" && next.scheme() != "https" {
                return Err(invalid("Insecure subscription redirect was rejected"));
            }
            forward_hwid &= next.origin() == original.origin();
            url = next;
            continue;
        }
        if !response.status().is_success() {
            return Err(failure(&format!(
                "Subscription server returned HTTP {}",
                response.status().as_u16()
            )));
        }
        let user_info = response
            .headers()
            .get("subscription-userinfo")
            .and_then(|h| h.to_str().ok())
            .and_then(parse_subscription_userinfo);
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| failure("Could not read the subscription response"))?
        {
            if chunk.len() > MAX_SUBSCRIPTION_BODY_BYTES - bytes.len() {
                return Err(invalid("Subscription response exceeds the 1 MiB limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        let body =
            String::from_utf8(bytes).map_err(|_| invalid("Subscription response is not UTF-8"))?;
        return Ok(FetchedSubscription { body, user_info });
    }
    Err(failure("Subscription redirected too many times"))
}

pub struct SubscriptionImport<'a> {
    pub id: &'a str,
    pub url: &'a str,
    pub hwid: &'a str,
    pub name: &'a str,
    pub refresh_interval_minutes: Option<u32>,
}
pub fn import_body(
    vault: &ConfigVault,
    store: &ProfileStore,
    request: &SubscriptionImport<'_>,
    body: &str,
    user_info: Option<SubscriptionUserInfo>,
    available: impl Fn(u16) -> bool,
) -> io::Result<BatchImportResult> {
    crate::config_vault::sanitize_profile_id(request.id)?;
    validate_url(request.url)?;
    if body.len() > MAX_SUBSCRIPTION_BODY_BYTES {
        return Err(invalid("Subscription response exceeds the 1 MiB limit"));
    }
    if request
        .refresh_interval_minutes
        .is_some_and(|m| !matches!(m, 15 | 60 | 360))
    {
        return Err(invalid("unsupported subscription refresh interval"));
    }
    let document = store.load()?;
    if document.profiles.iter().any(|p| p.id == request.id) {
        return Err(invalid("A profile with this identifier already exists"));
    }
    let (urls, unsupported) = parse_subscription_body(body);
    if urls.is_empty() {
        return Err(invalid("Subscription contained no supported share links"));
    }
    let used = profile_listener_ports(&document.profiles, "");
    let (socks, http) = select_generated_ports(None, None, &used, available)?;
    let mut errors = Vec::new();
    if unsupported != 0 {
        errors.push(BatchImportError {
            path: "Subscription".into(),
            error: format!("{unsupported} unsupported share link(s) skipped"),
        });
    }
    let mut endpoints = Vec::new();
    let mut first_config = None;
    for (index, uri) in urls.into_iter().enumerate() {
        match xray::generate_share_link_config_with_http(&uri, socks, http) {
            Ok(config) => {
                if first_config.is_none() {
                    first_config = Some(config);
                }
                let name = xray::share_link_name(&uri)
                    .unwrap_or_else(|| format!("Endpoint {}", endpoints.len() + 1));
                endpoints.push(SubscriptionEndpoint { url: uri, name });
            }
            Err(_) => errors.push(BatchImportError {
                path: format!("Endpoint {}", index + 1),
                error: "Invalid or unsupported share link".into(),
            }),
        }
    }
    let first_config =
        first_config.ok_or_else(|| invalid("Subscription contained no valid share links"))?;
    let body = serde_json::to_vec_pretty(&first_config)?;
    let imported = vault.store_generated_xray(request.id, &body)?;
    let result = (|| {
        vault.store_subscription_endpoints(request.id, &endpoints)?;
        let profile = Profile {
            id: request.id.into(),
            name: if request.name.trim().is_empty() {
                xray::share_link_name(&endpoints[0].url).unwrap_or_else(|| "Subscription".into())
            } else {
                request.name.trim().into()
            },
            backend: TunnelBackend::Xray,
            config_path: imported.config_path,
            xray_socks_port: Some(socks),
            xray_http_port: Some(http),
            xray_mode: XrayMode::platform_default(),
            subscription: Some(SubscriptionMeta {
                url: request.url.trim().into(),
                hwid: request.hwid.into(),
                endpoint_count: endpoints.len(),
                active_index: 0,
                refresh_interval_minutes: request.refresh_interval_minutes,
                last_refresh_at_unix: Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                ),
                last_refresh_error: None,
                user_info,
            }),
            ..Profile::default()
        };
        store.upsert(profile)
    })();
    match result {
        Ok(document) => Ok(BatchImportResult {
            profiles: document.profiles,
            errors,
        }),
        Err(error) => {
            let _ = vault.remove_profile(request.id);
            Err(error)
        }
    }
}

pub fn switch_endpoint(
    vault: &ConfigVault,
    store: &ProfileStore,
    id: &str,
    index: usize,
    available: impl Fn(u16) -> bool,
) -> io::Result<ProfileDocument> {
    let document = store.load()?;
    let mut profile = document
        .profiles
        .iter()
        .find(|p| p.id == id)
        .cloned()
        .ok_or_else(|| invalid("Profile not found"))?;
    let subscription = profile
        .subscription
        .as_mut()
        .ok_or_else(|| invalid("Profile is not a subscription"))?;
    let endpoints = vault.read_subscription_endpoints(id)?;
    let endpoint = endpoints
        .get(index)
        .ok_or_else(|| invalid("Invalid endpoint index"))?;
    let used = profile_listener_ports(&document.profiles, id);
    let (socks, http) = select_generated_ports(
        profile.xray_socks_port,
        profile.xray_http_port,
        &used,
        available,
    )?;
    let config = xray::generate_share_link_config_with_http(&endpoint.url, socks, http)
        .map_err(|_| invalid("Invalid or unsupported share link"))?;
    let imported = vault.store_generated_xray(id, &serde_json::to_vec_pretty(&config)?)?;
    let old_path = profile.config_path;
    profile.config_path = imported.config_path.clone();
    profile.xray_socks_port = Some(socks);
    profile.xray_http_port = Some(http);
    profile.name = endpoint.name.clone();
    subscription.active_index = index;
    subscription.endpoint_count = endpoints.len();
    match store.upsert(profile) {
        Ok(document) => {
            if vault.is_managed_profile_path(id, &old_path) {
                vault.remove_revision_for_config(&old_path)?;
            }
            Ok(document)
        }
        Err(error) => {
            let _ = vault.remove_revision_for_config(&imported.config_path);
            Err(error)
        }
    }
}

pub fn public_profiles(mut profiles: Vec<Profile>) -> Vec<Profile> {
    for profile in &mut profiles {
        if let Some(subscription) = &mut profile.subscription {
            subscription.url.clear();
            subscription.hwid.clear();
        }
    }
    profiles
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    const BODY: &str = "vless://synthetic-id@one.test:443?security=tls#First\nhy2://synthetic-password@two.test:443#Second";

    #[test]
    fn imports_plain_and_unpadded_base64_and_preserves_private_metadata() {
        for body in [
            BODY.to_string(),
            base64::engine::general_purpose::STANDARD_NO_PAD.encode(BODY),
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(BODY),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let vault = ConfigVault::new(dir.path().join("configs"));
            let store = ProfileStore::new(dir.path().join("profiles.json"));
            let request = SubscriptionImport {
                id: "sub",
                url: "https://example.test/private-token",
                hwid: "private-hwid",
                name: "Custom name",
                refresh_interval_minutes: Some(60),
            };
            let result = import_body(&vault, &store, &request, &body, None, |_| true).unwrap();
            let profile = &result.profiles[0];
            assert_eq!(profile.name, "Custom name");
            assert_eq!(profile.xray_mode, XrayMode::platform_default());
            assert_eq!(profile.subscription.as_ref().unwrap().endpoint_count, 2);
            assert_eq!(profile.subscription.as_ref().unwrap().url, request.url);
            assert_eq!(
                profile
                    .subscription
                    .as_ref()
                    .unwrap()
                    .refresh_interval_minutes,
                Some(60)
            );
            assert!(
                !profile.auto_connect && !profile.use_system_proxy && profile.routes.is_empty()
            );
            let first_ports = (profile.xray_socks_port, profile.xray_http_port);
            let public = serde_json::to_string(&public_profiles(result.profiles)).unwrap();
            assert!(!public.contains("private-token") && !public.contains("private-hwid"));
            let switched = switch_endpoint(&vault, &store, "sub", 1, |_| true).unwrap();
            assert_eq!(
                switched.profiles[0]
                    .subscription
                    .as_ref()
                    .unwrap()
                    .active_index,
                1
            );
            assert_eq!(
                (
                    switched.profiles[0].xray_socks_port,
                    switched.profiles[0].xray_http_port
                ),
                first_ports
            );
        }
    }

    #[test]
    fn invalid_bodies_and_save_failures_leave_no_subscription_data() {
        let dir = tempfile::tempdir().unwrap();
        let vault = ConfigVault::new(dir.path().join("configs"));
        let store = ProfileStore::new(dir.path().join("profiles.json"));
        let request = SubscriptionImport {
            id: "sub",
            url: "https://example.test/sub",
            hwid: "",
            name: "",
            refresh_interval_minutes: None,
        };
        for body in [
            "",
            "trojan://private-secret@node.test:443",
            "vless://private-secret@:443",
            "<html>not a subscription</html>",
        ] {
            assert!(import_body(&vault, &store, &request, body, None, |_| true).is_err());
            assert!(!dir.path().join("configs").exists());
        }
        std::fs::create_dir(dir.path().join("profiles.json.tmp")).unwrap();
        assert!(import_body(&vault, &store, &request, BODY, None, |_| true).is_err());
        assert!(!vault.root().join("sub").exists());
    }

    #[test]
    fn url_validation_rejects_files_credentials_and_invalid_urls_without_echoing_them() {
        for url in [
            "file:///private-secret",
            "vless://private-secret@node.test:443",
            "https://private-user:private-secret@node.test/sub",
            "not a URL",
        ] {
            let error = validate_url(url).unwrap_err();
            assert!(!error.to_string().contains("private-secret"));
        }
        assert!(validate_url(" https://example.test/sub ").is_ok());
    }

    async fn fake_response(response: String) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/private-token", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let received = stream.read(&mut bytes).await.unwrap();
            assert!(received > 0);
            stream.write_all(response.as_bytes()).await.unwrap();
        });
        (url, task)
    }

    #[tokio::test]
    async fn bounded_http_errors_are_redacted_and_oversized_responses_rejected() {
        for response in [
            "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_string(),
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                MAX_SUBSCRIPTION_BODY_BYTES + 1,
                "x".repeat(MAX_SUBSCRIPTION_BODY_BYTES + 1)
            ),
        ] {
            let (url, server) = fake_response(response).await;
            let error = fetch(&http_client().unwrap(), &url, "private-hwid")
                .await
                .err()
                .unwrap()
                .to_string();
            assert!(!error.contains("private-token") && !error.contains("private-hwid"));
            assert!(error.contains("HTTP 403") || error.contains("1 MiB"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn cross_origin_redirect_does_not_forward_hwid() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let destination = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let destination_url = format!("http://{}/sub", destination.local_addr().unwrap());
        let target = tokio::spawn(async move {
            let (mut stream, _) = destination.accept().await.unwrap();
            let mut bytes = [0; 4096];
            let size = stream.read(&mut bytes).await.unwrap();
            assert!(!String::from_utf8_lossy(&bytes[..size])
                .to_ascii_lowercase()
                .contains("x-hwid"));
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await
                .unwrap();
        });
        let (url, source) = fake_response(format!("HTTP/1.1 302 Found\r\nLocation: {destination_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")).await;
        assert_eq!(
            fetch(&http_client().unwrap(), &url, "private-hwid")
                .await
                .unwrap()
                .body,
            "ok"
        );
        source.await.unwrap();
        target.await.unwrap();
    }
}
