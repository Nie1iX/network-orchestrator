#![cfg(target_os = "windows")]
//! Opt-in end-to-end harness for a disposable Windows VM.
//!
//! Mutating scenarios are `#[ignore]`d and additionally gated on the
//! `NETWORK_ORCHESTRATOR_E2E`/`NETWORK_ORCHESTRATOR_E2E_ACK` markers plus an
//! elevated token. See `docs/testing.md` for the fixture contract.

use ipnet::IpNet;
use net_manager_core::analysis::analyze_profile;
use net_manager_core::explorer::{list_interfaces, list_routes, lookup_route};
use net_manager_core::models::{InterfaceState, Profile, TunnelBackend, TunnelState};
use net_manager_core::vpn::TunnelManager;
use std::env;
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const GATE_ENV: &str = "NETWORK_ORCHESTRATOR_E2E";
const GATE_VALUE: &str = "disposable-windows-vm";
const ACK_ENV: &str = "NETWORK_ORCHESTRATOR_E2E_ACK";
const ACK_VALUE: &str = "routes-and-vpn-will-change";
const POLL_LIMIT: Duration = Duration::from_secs(15);
const POLL_STEP: Duration = Duration::from_millis(250);

fn scenario_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

#[derive(Debug)]
struct IfSnap {
    name: String,
    #[allow(dead_code)]
    index: u32,
    up: bool,
}

#[derive(Debug)]
struct RtSnap {
    network: IpAddr,
    prefix_len: u8,
    interface: String,
    #[allow(dead_code)]
    metric: u32,
}

fn interfaces() -> io::Result<Vec<IfSnap>> {
    list_interfaces().map(|list| {
        list.into_iter()
            .map(|i| IfSnap {
                name: i.friendly_name,
                index: i.if_index,
                up: matches!(i.state, InterfaceState::Up),
            })
            .collect()
    })
}

async fn routes() -> io::Result<Vec<RtSnap>> {
    list_routes().await.map(|list| {
        list.into_iter()
            .map(|r| RtSnap {
                network: r.destination,
                prefix_len: r.prefix_len,
                interface: r.interface_name,
                metric: r.metric,
            })
            .collect()
    })
}

fn basename(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default()
}

fn env_required(name: &str) -> Result<String, String> {
    env::var(name).map_err(|_| format!("missing fixture env var {name}"))
}

fn fixture_file(name: &str) -> Result<PathBuf, String> {
    let path = PathBuf::from(env_required(name)?);
    let meta = std::fs::metadata(&path)
        .map_err(|e| format!("{name} does not point to an accessible file: {e}"))?;
    if !meta.is_file() {
        return Err(format!("{name} does not point to a regular file"));
    }
    Ok(path)
}

fn fixture_cidr(name: &str) -> Result<IpNet, String> {
    env_required(name)?
        .parse::<IpNet>()
        .map_err(|_| format!("{name} is not a valid CIDR"))
}

fn is_elevated() -> io::Result<bool> {
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    struct Token(HANDLE);
    impl Drop for Token {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }

    unsafe {
        let mut handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle)
            .map_err(|_| io::Error::last_os_error())?;
        let token = Token(handle);
        let mut elevation = TOKEN_ELEVATION::default();
        let mut size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        GetTokenInformation(
            token.0,
            TokenElevation,
            Some(&mut elevation as *mut TOKEN_ELEVATION as *mut _),
            size,
            &mut size,
        )
        .map_err(|_| io::Error::last_os_error())?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

fn require_gate() -> Result<(), String> {
    if env::var(GATE_ENV).ok().as_deref() != Some(GATE_VALUE) {
        return Err(format!("refusing to run: set {GATE_ENV}={GATE_VALUE}"));
    }
    if env::var(ACK_ENV).ok().as_deref() != Some(ACK_VALUE) {
        return Err(format!("refusing to run: set {ACK_ENV}={ACK_VALUE}"));
    }
    if !is_elevated().map_err(|e| format!("elevation check failed: {e}"))? {
        return Err("refusing to run: process is not elevated".into());
    }
    Ok(())
}

fn fixture_profile(
    id: &str,
    backend: TunnelBackend,
    config_path: PathBuf,
    interface: &str,
) -> Profile {
    Profile {
        id: id.into(),
        name: format!("e2e-{id}"),
        backend,
        config_path,
        interface_name: interface.into(),
        routes: vec![],
        auto_connect: false,
        domain_policies: vec![],
        xray_socks_port: None,
    }
}

fn guard_profile(profile: &Profile) -> Result<(), String> {
    let analysis = analyze_profile(profile).map_err(|e| {
        format!(
            "cannot analyze fixture '{}' ({}): {e}",
            profile.id,
            basename(&profile.config_path)
        )
    })?;
    for route in analysis
        .os_routes
        .iter()
        .chain(analysis.internal_routes.iter())
    {
        if route.destination.prefix_len() == 0 {
            return Err(format!(
                "fixture '{}' requests a default route; refusing to connect",
                profile.id
            ));
        }
    }
    Ok(())
}

async fn poll_until<F, Fut>(what: &str, mut check: F) -> Result<(), String>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + POLL_LIMIT;
    loop {
        if check().await {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for {what}"));
        }
        tokio::time::sleep(POLL_STEP).await;
    }
}

fn interface_is_up(name: &str) -> bool {
    interfaces()
        .map(|list| list.iter().any(|i| i.up && i.name == name))
        .unwrap_or(false)
}

fn route_present(list: &[RtSnap], net: IpNet, interface: &str) -> bool {
    list.iter().any(|r| {
        r.network == net.network() && r.prefix_len == net.prefix_len() && r.interface == interface
    })
}

fn combine(scenario: Result<(), String>, cleanup: Vec<String>) -> Result<(), String> {
    match (scenario, cleanup.is_empty()) {
        (Ok(()), true) => Ok(()),
        (Ok(()), false) => Err(format!("cleanup errors: {}", cleanup.join("; "))),
        (Err(e), true) => Err(e),
        (Err(e), false) => Err(format!("{e}; cleanup errors: {}", cleanup.join("; "))),
    }
}

fn report(result: Result<(), String>) {
    if let Err(e) = result {
        panic!("{e}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "mutates routes; disposable VM only"]
async fn wireguard_lifecycle_e2e() {
    let _serial = scenario_lock().lock().await;
    report(wireguard_lifecycle().await);
}

async fn wireguard_lifecycle() -> Result<(), String> {
    require_gate()?;
    let config = fixture_file("NO_E2E_WG_CONFIG")?;
    let interface = env_required("NO_E2E_WG_INTERFACE")?;
    let cidr = fixture_cidr("NO_E2E_WG_CIDR")?;
    let profile = fixture_profile("e2e-wg", TunnelBackend::WireGuard, config, &interface);
    guard_profile(&profile)?;

    let mut manager = TunnelManager::new();
    let scenario = async {
        let status = manager.connect(&profile).map_err(|e| {
            format!(
                "WireGuard connect failed for {}: {e}",
                basename(&profile.config_path)
            )
        })?;
        if status.state != TunnelState::Running {
            return Err(format!(
                "WireGuard profile '{}' did not report Running",
                profile.id
            ));
        }
        poll_until("WireGuard interface up", || async {
            interface_is_up(&interface)
        })
        .await?;
        poll_until("expected route present", || async {
            routes()
                .await
                .map(|list| route_present(&list, cidr, &interface))
                .unwrap_or(false)
        })
        .await?;
        Ok(())
    }
    .await;

    let mut cleanup = Vec::new();
    if let Err(e) = manager.disconnect(&profile) {
        cleanup.push(format!("WireGuard disconnect failed: {e}"));
    }
    if let Err(e) = poll_until("WireGuard interface down", || async {
        !interface_is_up(&interface)
    })
    .await
    {
        cleanup.push(e);
    }
    if let Err(e) = poll_until("expected route removed", || async {
        routes()
            .await
            .map(|list| !route_present(&list, cidr, &interface))
            .unwrap_or(false)
    })
    .await
    {
        cleanup.push(e);
    }
    combine(scenario, cleanup)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "mutates routes; disposable VM only"]
async fn openvpn_lifecycle_e2e() {
    let _serial = scenario_lock().lock().await;
    report(openvpn_lifecycle().await);
}

async fn openvpn_lifecycle() -> Result<(), String> {
    require_gate()?;
    let config = fixture_file("NO_E2E_OVPN_CONFIG")?;
    let interface = env_required("NO_E2E_OVPN_INTERFACE")?;
    let cidr = fixture_cidr("NO_E2E_OVPN_CIDR")?;
    let profile = fixture_profile("e2e-ovpn", TunnelBackend::OpenVpn, config, &interface);
    guard_profile(&profile)?;

    let mut manager = TunnelManager::new();
    let scenario = async {
        let status = manager.connect(&profile).map_err(|e| {
            format!(
                "OpenVPN connect failed for {}: {e}",
                basename(&profile.config_path)
            )
        })?;
        if status.state != TunnelState::Running {
            return Err(format!(
                "OpenVPN profile '{}' did not report Running",
                profile.id
            ));
        }
        poll_until("OpenVPN interface up", || async {
            interface_is_up(&interface)
        })
        .await?;
        poll_until("expected route present", || async {
            routes()
                .await
                .map(|list| route_present(&list, cidr, &interface))
                .unwrap_or(false)
        })
        .await?;
        Ok(())
    }
    .await;

    let mut cleanup = Vec::new();
    if let Err(e) = manager.disconnect(&profile) {
        cleanup.push(format!("OpenVPN disconnect failed: {e}"));
    }
    if let Err(e) = poll_until("OpenVPN interface down", || async {
        !interface_is_up(&interface)
    })
    .await
    {
        cleanup.push(e);
    }
    if let Err(e) = poll_until("expected route removed", || async {
        routes()
            .await
            .map(|list| !route_present(&list, cidr, &interface))
            .unwrap_or(false)
    })
    .await
    {
        cleanup.push(e);
    }
    combine(scenario, cleanup)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "spawns Xray; disposable VM only"]
async fn xray_lifecycle_e2e() {
    let _serial = scenario_lock().lock().await;
    report(xray_lifecycle().await);
}

async fn xray_lifecycle() -> Result<(), String> {
    require_gate()?;
    let config = fixture_file("NO_E2E_XRAY_CONFIG")?;
    let listener = env::var("NO_E2E_XRAY_LISTENER")
        .ok()
        .map(|v| v.parse::<SocketAddr>())
        .transpose()
        .map_err(|_| "NO_E2E_XRAY_LISTENER must be 127.0.0.1:port".to_string())?;
    if let Some(addr) = listener {
        if !addr.ip().is_loopback() {
            return Err("NO_E2E_XRAY_LISTENER must be a loopback address".into());
        }
    }
    let profile = fixture_profile("e2e-xray", TunnelBackend::Xray, config, "");
    guard_profile(&profile)?;

    let mut manager = TunnelManager::new();
    let scenario = async {
        let status = manager.connect(&profile).map_err(|e| {
            format!(
                "Xray connect failed for {}: {e}",
                basename(&profile.config_path)
            )
        })?;
        if status.state != TunnelState::Running {
            return Err(format!(
                "Xray profile '{}' did not report Running",
                profile.id
            ));
        }
        if let Some(addr) = listener {
            poll_until("Xray listener accepts TCP", || async {
                TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_ok()
            })
            .await?;
        }
        Ok(())
    }
    .await;

    let mut cleanup = Vec::new();
    if let Err(e) = manager.disconnect(&profile) {
        cleanup.push(format!("Xray disconnect failed: {e}"));
    }
    if manager.status(&profile).state == TunnelState::Running {
        cleanup.push("Xray profile still Running after disconnect".into());
    }
    if let Some(addr) = listener {
        if let Err(e) = poll_until("Xray listener closed", || async {
            TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err()
        })
        .await
        {
            cleanup.push(e);
        }
    }
    combine(scenario, cleanup)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "mutates routes; disposable VM only"]
async fn wireguard_openvpn_longest_prefix_e2e() {
    let _serial = scenario_lock().lock().await;
    report(longest_prefix().await);
}

async fn longest_prefix() -> Result<(), String> {
    require_gate()?;
    let wg_config = fixture_file("NO_E2E_WG_CONFIG")?;
    let wg_interface = env_required("NO_E2E_WG_INTERFACE")?;
    let wg_cidr = fixture_cidr("NO_E2E_WG_CIDR")?;
    let ovpn_config = fixture_file("NO_E2E_OVPN_CONFIG")?;
    let ovpn_interface = env_required("NO_E2E_OVPN_INTERFACE")?;
    let ovpn_cidr = fixture_cidr("NO_E2E_OVPN_CIDR")?;

    if wg_cidr.prefix_len() >= ovpn_cidr.prefix_len() {
        return Err("fixture requires the OpenVPN CIDR to be strictly more specific".into());
    }
    if !wg_cidr.contains(&ovpn_cidr.network()) {
        return Err("fixture requires the OpenVPN CIDR inside the WireGuard CIDR".into());
    }
    let probe = ovpn_cidr.network();

    let wg = fixture_profile("e2e-wg", TunnelBackend::WireGuard, wg_config, &wg_interface);
    let ovpn = fixture_profile(
        "e2e-ovpn",
        TunnelBackend::OpenVpn,
        ovpn_config,
        &ovpn_interface,
    );
    guard_profile(&wg)?;
    guard_profile(&ovpn)?;

    let mut manager = TunnelManager::new();
    let scenario = async {
        manager
            .connect(&wg)
            .map_err(|e| format!("WireGuard connect failed: {e}"))?;
        manager
            .connect(&ovpn)
            .map_err(|e| format!("OpenVPN connect failed: {e}"))?;
        poll_until("both routes present", || async {
            routes()
                .await
                .map(|list| {
                    route_present(&list, wg_cidr, &wg_interface)
                        && route_present(&list, ovpn_cidr, &ovpn_interface)
                })
                .unwrap_or(false)
        })
        .await?;
        let lookup = lookup_route(probe)
            .await
            .map_err(|e| format!("route lookup for {probe} failed: {e}"))?;
        if lookup.interface_name != ovpn_interface {
            return Err(format!(
                "expected {probe} to resolve via '{ovpn_interface}', got '{}'",
                lookup.interface_name
            ));
        }
        Ok(())
    }
    .await;

    let mut cleanup = Vec::new();
    if let Err(e) = manager.disconnect(&ovpn) {
        cleanup.push(format!("OpenVPN disconnect failed: {e}"));
    }
    if let Err(e) = manager.disconnect(&wg) {
        cleanup.push(format!("WireGuard disconnect failed: {e}"));
    }
    if let Err(e) = poll_until("fixtures routes removed", || async {
        routes()
            .await
            .map(|list| {
                !route_present(&list, wg_cidr, &wg_interface)
                    && !route_present(&list, ovpn_cidr, &ovpn_interface)
            })
            .unwrap_or(false)
    })
    .await
    {
        cleanup.push(e);
    }
    combine(scenario, cleanup)
}

#[test]
fn wireguard_killswitch_is_rejected_by_fixture_guard() {
    let dir = std::env::temp_dir().join(format!("netmgr-e2e-guard-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("killswitch.conf");
    std::fs::write(
        &config,
        "[Interface]\nPrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\
         [Peer]\nPublicKey=BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=\n\
         Endpoint=198.51.100.1:51820\nAllowedIPs=0.0.0.0/0\n",
    )
    .unwrap();
    let profile = fixture_profile("e2e-killswitch", TunnelBackend::WireGuard, config, "wg0");
    let err = guard_profile(&profile).expect_err("/0 fixture must be rejected");
    assert!(err.contains("default route"), "{err}");
    let _ = std::fs::remove_dir_all(&dir);
}
