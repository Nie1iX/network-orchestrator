#[path = "network_probe_proxy.rs"]
pub mod proxy;

use serde::Serialize;
use std::{
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::Instant,
};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPathProbe {
    pub target: String,
    pub scope: String,
    pub stages: Vec<NetworkPathProbeStage>,
}
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPathProbeStage {
    pub stage: String,
    pub outcome: String,
    pub message: String,
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
}
fn stage(
    stage: &str,
    outcome: &str,
    message: &str,
    duration: Option<u64>,
) -> NetworkPathProbeStage {
    NetworkPathProbeStage {
        stage: stage.into(),
        outcome: outcome.into(),
        message: message.into(),
        duration_ms: duration,
        interface_name: None,
        status_code: None,
    }
}

/// Accept a hostname, IP address, or HTTPS origin and return a credential/path-free origin.
pub fn parse_target(input: &str) -> Result<(String, String), &'static str> {
    let raw = input.trim();
    if raw.is_empty() {
        return Err("Enter a hostname, IP address, or HTTPS URL.");
    }
    let candidate = if raw.contains("://") {
        raw.to_owned()
    } else if raw.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("https://[{raw}]")
    } else {
        format!("https://{raw}")
    };
    let url = reqwest::Url::parse(&candidate).map_err(|_| "Target is not a valid HTTPS URL.")?;
    if url.scheme() != "https" {
        return Err("Target must use HTTPS.");
    }
    let authority = candidate
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    if authority.contains('@') || !url.username().is_empty() || url.password().is_some() {
        return Err("Target URL must not contain credentials.");
    }
    let host = url
        .host_str()
        .ok_or("Target URL must include a host.")?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let host_for_url = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.clone()
    };
    let origin = format!(
        "https://{host_for_url}{}",
        url.port().map(|p| format!(":{p}")).unwrap_or_default()
    );
    Ok((host, origin))
}

fn classify_route(
    result: Result<net_manager_core::models::RouteLookupResult, ()>,
    duration: u64,
) -> NetworkPathProbeStage {
    match result {
        Ok(route) => {
            let mut out = stage(
                "route",
                "healthy",
                "Kernel route lookup selected an interface.",
                Some(duration),
            );
            out.interface_name = Some(route.interface_name);
            out
        }
        Err(()) => stage(
            "route",
            "unknown",
            "Kernel route lookup did not return an interface.",
            Some(duration),
        ),
    }
}
fn https_error_stage(duration: u64) -> NetworkPathProbeStage {
    stage(
        "https",
        "failed",
        "HTTPS connection failed, timed out, or TLS validation failed.",
        Some(duration),
    )
}
fn https_response_stage(status: u16, duration: u64) -> NetworkPathProbeStage {
    let mut out = stage(
        "https",
        "healthy",
        "HTTPS transport and TLS succeeded; response does not validate application behavior.",
        Some(duration),
    );
    out.status_code = Some(status);
    if (300..400).contains(&status) {
        out.message = "HTTPS transport and TLS succeeded; redirect was not followed and destination behavior is unknown.".into();
    }
    out
}
fn should_attempt_https(resolved: Option<IpAddr>, via_proxy: bool) -> bool {
    via_proxy || resolved.is_some()
}
fn pinned_address(host: &str, resolved: Option<IpAddr>, port: u16) -> Option<SocketAddr> {
    if host.parse::<IpAddr>().is_ok() {
        None
    } else {
        resolved.map(|ip| SocketAddr::new(ip, port))
    }
}

/// Run explicit bounded transport checks. `proxy_url` is present only for an active owned user proxy.
pub async fn probe_current_path(
    target: &str,
    proxy_url: Option<&str>,
) -> Result<NetworkPathProbe, String> {
    let (host, origin) = parse_target(target).map_err(str::to_owned)?;
    let url =
        reqwest::Url::parse(&origin).map_err(|_| "Target is not a valid HTTPS URL.".to_string())?;
    let port = url.port().unwrap_or(443);
    let scope = if proxy_url.is_some() {
        "systemProxy"
    } else {
        "system"
    };
    let mut stages = Vec::with_capacity(3);
    let mut resolved = None;
    if proxy_url.is_some() {
        stages.push(stage(
            "dns",
            "unknown",
            "Name resolution is performed by the active proxy; no local DNS query was made.",
            None,
        ));
    } else if let Ok(ip) = host.parse::<IpAddr>() {
        resolved = Some(ip);
        stages.push(stage(
            "dns",
            "healthy",
            "Target is an IP address; no DNS query was needed.",
            Some(0),
        ));
    } else {
        let started = Instant::now();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            tokio::task::spawn_blocking({
                let host = host.clone();
                move || {
                    (host.as_str(), port)
                        .to_socket_addrs()
                        .map(|mut it| it.next())
                }
            }),
        )
        .await;
        let duration = started.elapsed().as_millis() as u64;
        match result {
            Ok(Ok(Ok(Some(address)))) => {
                resolved = Some(address.ip());
                stages.push(stage(
                    "dns",
                    "healthy",
                    "System resolver returned an address.",
                    Some(duration),
                ));
            }
            Ok(Ok(Ok(None))) => stages.push(stage(
                "dns",
                "failed",
                "System resolver returned no addresses.",
                Some(duration),
            )),
            _ => stages.push(stage(
                "dns",
                "failed",
                "System name resolution failed or timed out.",
                Some(duration),
            )),
        }
    }
    let route_ip = if let Some(proxy) = proxy_url {
        reqwest::Url::parse(proxy)
            .ok()
            .and_then(|url| url.host_str().and_then(|h| h.parse::<IpAddr>().ok()))
    } else {
        resolved
    };
    let route = if let Some(ip) = route_ip {
        let started = Instant::now();
        let found = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            crate::linux_network::lookup(ip),
        )
        .await;
        classify_route(
            match found {
                Ok(Ok(v)) => Ok(v),
                _ => Err(()),
            },
            started.elapsed().as_millis() as u64,
        )
    } else {
        stage(
            "route",
            "unknown",
            if proxy_url.is_some() {
                "Could not observe the active proxy route."
            } else {
                "No target address was resolved for route lookup."
            },
            None,
        )
    };
    stages.push(route);

    if !should_attempt_https(resolved, proxy_url.is_some()) {
        stages.push(stage(
            "https",
            "unknown",
            "HTTPS was not attempted because the target address could not be resolved locally.",
            None,
        ));
        return Ok(NetworkPathProbe {
            target: origin,
            scope: scope.into(),
            stages,
        });
    }
    let started = Instant::now();
    let mut builder = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none());
    if let Some(proxy) = proxy_url {
        let parsed = reqwest::Url::parse(proxy)
            .map_err(|_| "Active system proxy configuration is invalid.".to_string())?;
        builder = builder.proxy(
            reqwest::Proxy::all(parsed)
                .map_err(|_| "Active system proxy configuration is invalid.".to_string())?,
        );
    } else {
        builder = builder.no_proxy();
        if let Some(address) = pinned_address(&host, resolved, port) {
            builder = builder.resolve(&host, address);
        }
    }
    let client = builder
        .build()
        .map_err(|_| "Unable to initialize HTTPS probe.".to_string())?;
    let https = match client.head(&origin).send().await {
        Ok(response) => https_response_stage(
            response.status().as_u16(),
            started.elapsed().as_millis() as u64,
        ),
        Err(_) => https_error_stage(started.elapsed().as_millis() as u64),
    };
    stages.push(https);
    Ok(NetworkPathProbe {
        target: origin,
        scope: scope.into(),
        stages,
    })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn target_redacts_path_query_fragment_and_preserves_port() {
        let (host, target) = parse_target("example.test:8443/private?q=secret#token").unwrap();
        assert_eq!(host, "example.test");
        assert_eq!(target, "https://example.test:8443");
    }
    #[test]
    fn target_rejects_credentials_and_non_https() {
        assert!(parse_target("https://user:secret@example.test/path").is_err());
        assert!(parse_target("https://@example.test").is_err());
        assert!(parse_target("http://example.test").is_err());
    }
    #[test]
    fn target_accepts_bare_ipv6_without_double_brackets() {
        let (host, url) = parse_target("2001:db8::1").unwrap();
        assert_eq!(host, "2001:db8::1");
        assert_eq!(url, "https://[2001:db8::1]");
    }
    #[test]
    fn route_stage_reports_observed_interface_or_unknown() {
        let route = net_manager_core::models::RouteEntry {
            destination: "192.0.2.1".parse().unwrap(),
            prefix_len: 32,
            gateway: None,
            interface_index: 4,
            interface_name: "test0".into(),
            metric: 1,
        };
        let observed = net_manager_core::models::RouteLookupResult {
            destination: route.destination,
            matched_route: route,
            interface_name: "test0".into(),
            table: None,
        };
        let stage = classify_route(Ok(observed), 2);
        assert_eq!(stage.outcome, "healthy");
        assert_eq!(stage.interface_name.as_deref(), Some("test0"));
        assert_eq!(classify_route(Err(()), 3).outcome, "unknown");
    }
    #[test]
    fn redirect_is_transport_success_but_not_followed() {
        let response = https_response_stage(302, 1);
        assert_eq!(response.outcome, "healthy");
        assert_eq!(response.status_code, Some(302));
    }
    #[test]
    fn local_resolution_failure_skips_https_but_proxy_dns_is_remote() {
        assert!(!should_attempt_https(None, false));
        assert!(should_attempt_https(None, true));
    }
    #[test]
    fn direct_https_uses_the_address_that_was_observed_for_route_lookup() {
        let address = "192.0.2.8".parse().unwrap();
        assert_eq!(
            pinned_address("example.test", Some(address), 8443),
            Some(SocketAddr::new(address, 8443))
        );
        assert_eq!(pinned_address("192.0.2.8", Some(address), 443), None);
    }
}
