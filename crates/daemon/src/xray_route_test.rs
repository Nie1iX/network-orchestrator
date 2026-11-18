//! Minimal client for the pinned Xray RoutingService TestRoute API.
use prost::Message;
use std::net::IpAddr;
use std::time::Duration;
use tonic::client::Grpc;
use tonic::codegen::http::uri::PathAndQuery;
use tonic::transport::{Channel, Endpoint};
use tonic::{Request, Status};

use net_manager_core::daemon_protocol::{XrayTestRouteParams, XrayTestRouteResult};

const API_TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, PartialEq, Message)]
struct RoutingContext {
    #[prost(string, tag = "1")]
    inbound_tag: String,
    #[prost(int32, tag = "2")]
    network: i32,
    #[prost(bytes = "vec", repeated, tag = "4")]
    target_ips: Vec<Vec<u8>>,
    #[prost(uint32, tag = "6")]
    target_port: u32,
    #[prost(string, tag = "7")]
    target_domain: String,
    #[prost(string, tag = "8")]
    protocol: String,
}

#[derive(Clone, PartialEq, Message)]
struct TestRouteRequest {
    #[prost(message, optional, tag = "1")]
    routing_context: Option<RoutingContext>,
    #[prost(string, repeated, tag = "2")]
    field_selectors: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
struct TestRouteResponse {
    #[prost(string, tag = "12")]
    outbound_tag: String,
}

fn valid_target(target: &str) -> bool {
    if target.is_empty() || target.len() > 253 || target.chars().any(char::is_whitespace) {
        return false;
    }
    if target.parse::<IpAddr>().is_ok() {
        return true;
    }
    target.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn target_ip_bytes(target: &str) -> Vec<Vec<u8>> {
    match target.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => vec![ip.octets().to_vec()],
        Ok(IpAddr::V6(ip)) => vec![ip.octets().to_vec()],
        Err(_) => Vec::new(),
    }
}

async fn query(
    grpc: &mut Grpc<Channel>,
    params: &XrayTestRouteParams,
    inbound: &str,
) -> Result<TestRouteResponse, Status> {
    grpc.ready()
        .await
        .map_err(|_| Status::unavailable("API unavailable"))?;
    let target_ips = target_ip_bytes(&params.target);
    grpc.unary(
        Request::new(TestRouteRequest {
            routing_context: Some(RoutingContext {
                inbound_tag: inbound.to_owned(),
                network: if params.udp { 3 } else { 2 },
                target_domain: if target_ips.is_empty() {
                    params.target.clone()
                } else {
                    String::new()
                },
                target_ips,
                target_port: u32::from(params.port),
                protocol: params.protocol.clone().unwrap_or_default(),
            }),
            // Returning the target IP field can trigger an unnecessary DNS lookup.
            field_selectors: vec!["outbound".into()],
        }),
        PathAndQuery::from_static("/xray.app.router.command.RoutingService/TestRoute"),
        tonic_prost::ProstCodec::default(),
    )
    .await
    .map(|response| response.into_inner())
}

fn default_outbound(api: &std::path::Path) -> Result<String, Status> {
    let bytes = std::fs::read(api.with_file_name("config.json"))
        .map_err(|_| Status::failed_precondition("Xray config unavailable"))?;
    let config: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|_| Status::failed_precondition("Xray config unavailable"))?;
    config["outbounds"]
        .as_array()
        .and_then(|outbounds| outbounds.first())
        .and_then(|outbound| outbound["tag"].as_str())
        .map(str::to_owned)
        .ok_or_else(|| Status::failed_precondition("Xray default outbound unavailable"))
}

/// Test a synthetic TUN flow against the daemon-owned process; no raw API errors escape.
pub async fn test_route(
    uid: u32,
    name: &str,
    params: XrayTestRouteParams,
) -> Result<XrayTestRouteResult, Status> {
    if !valid_target(&params.target) || params.port == 0 {
        return Err(Status::invalid_argument("invalid route target"));
    }
    if params
        .protocol
        .as_deref()
        .is_some_and(|protocol| !matches!(protocol, "http" | "tls" | "quic" | "bittorrent"))
    {
        return Err(Status::invalid_argument("unsupported sniffed protocol"));
    }
    tokio::time::timeout(API_TIMEOUT, async move {
        let api = crate::xray_process::checked_api_socket_path(uid, name).map_err(|_| {
            Status::failed_precondition("Xray API unavailable; reconnect the profile")
        })?;
        let endpoint = Endpoint::from_shared(format!("unix://{}", api.display()))
            .map_err(|_| Status::failed_precondition("Xray API unavailable"))?;
        let mut grpc = Grpc::new(
            endpoint
                .connect()
                .await
                .map_err(|_| Status::unavailable("Xray API unavailable; reconnect the profile"))?,
        );
        let (first_tag, matched) = match query(&mut grpc, &params, "tun-in").await {
            Ok(response) => (response.outbound_tag, true),
            Err(status) if status.message().contains("not enough information") => {
                (default_outbound(&api)?, false)
            }
            Err(_) => return Err(Status::unavailable("Xray route test failed")),
        };
        if !matched && first_tag == crate::xray::FAILOVER_DEFAULT_OUTBOUND {
            let response = query(&mut grpc, &params, crate::xray::FAILOVER_DEFAULT_INBOUND)
                .await
                .map_err(|_| Status::unavailable("Xray failover route test failed"))?;
            return Ok(XrayTestRouteResult {
                matched,
                outbound_tag: response.outbound_tag,
            });
        }
        Ok(XrayTestRouteResult {
            matched,
            outbound_tag: first_tag,
        })
    })
    .await
    .map_err(|_| Status::deadline_exceeded("Xray route test timed out"))?
}
