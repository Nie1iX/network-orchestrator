//! A panel's whole-Xray config, reduced by `tun_compatible_config`, must pass
//! the daemon's own validator: the two lists of allowed fields cannot drift
//! apart unnoticed.
#![cfg(target_os = "linux")]
use net_manager_core::daemon_protocol::XrayConnectParams;
use net_manager_core::xray;
use network_orchestrator_daemon::xray::prepare_xray;
use serde_json::{json, Value};

fn params(config: &Value) -> XrayConnectParams {
    XrayConnectParams {
        profile_id: "sub1".into(),
        config: serde_json::to_string(config).unwrap(),
        routes: vec![],
        dns_servers: vec![],
        dns_domains: vec![],
        dns_bypass: vec![],
        interface_name: None,
        geo_assets: None,
        macos_data_root: None,
        role: Default::default(),
    }
}

fn panel(proxy: Value) -> Value {
    json!({
        "burstObservatory": {"subjectSelector": ["proxy"]},
        "policy": {"levels": {"0": {"handshake": 4}}},
        "dns": {"servers": ["1.1.1.1"]},
        "inbounds": [
            {"tag": "socks-in", "listen": "127.0.0.1", "port": 10808, "protocol": "socks",
             "settings": {"udp": true}},
            {"tag": "http-in", "listen": "127.0.0.1", "port": 10809, "protocol": "http"}
        ],
        "outbounds": [proxy,
            {"tag": "at4pda", "protocol": "freedom"},
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "block", "protocol": "blackhole"}],
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": []},
    })
}

#[test]
fn a_reduced_panel_vless_reality_config_passes_the_daemon_validator() {
    let config = panel(json!({
        "tag": "proxy", "protocol": "vless",
        "settings": {"vnext": [{"address": "node.test", "port": 443,
            "users": [{"id": "u", "encryption": "none", "flow": "xtls-rprx-vision", "level": 0}]}]},
        "streamSettings": {"network": "tcp", "security": "reality",
            "realitySettings": {"serverName": "s", "fingerprint": "chrome", "publicKey": "k",
                "shortId": "a", "spiderX": "/", "show": false},
            "sockopt": {"mark": 1}},
        "mux": {"enabled": false, "concurrency": -1}
    }));
    assert!(
        prepare_xray(1000, params(&config), 1).is_err(),
        "raw panel config"
    );
    let reduced = xray::tun_compatible_config(&config).unwrap();
    prepare_xray(1000, params(&reduced), 1).expect("reduced config");
}

#[test]
fn a_reduced_panel_hysteria_config_passes_the_daemon_validator() {
    let config = panel(json!({
        "tag": "proxy", "protocol": "hysteria",
        "settings": {"version": 2, "address": "h.test", "port": 443},
        "streamSettings": {"network": "hysteria", "security": "tls",
            "tlsSettings": {"serverName": "h.test", "alpn": ["h3"]},
            "hysteriaSettings": {"version": 2, "auth": "secret", "congestion": {"type": "bbr"}},
            "finalmask": {"udp": [{"type": "salamander", "settings": {"password": "p"}}]}}
    }));
    let reduced = xray::tun_compatible_config(&config).unwrap();
    prepare_xray(1000, params(&reduced), 1).expect("reduced config");
}
