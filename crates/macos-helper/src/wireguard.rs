//! WireGuard executor: the helper creates the `utun`, assigns the config's
//! addresses, runs the userspace engine on it, installs the routes the peers'
//! `AllowedIPs` ask for and points the uplink's DNS at the config's servers —
//! all journaled so a crash, an exit or a restart leaves nothing behind.

use crate::dns;
use crate::event_log::EventLog;
use crate::journal::{Journal, Record};
use crate::resolver;
use crate::routes;
use crate::sysexec::{Runner, IFCONFIG};
use crate::wg_engine::{Engine, EngineConfig, PacketIo, PeerSetup};
use crate::wireguard_config::{self, Warning};
use crate::xray::{Error, TunDevice};
use ipnet::IpNet;
use net_manager_core::daemon_protocol::{
    WireGuardConnectParams, WireGuardConnectResult, WireGuardDisconnectResult,
    WireGuardStatusResult, WireGuardWarning,
};
use net_manager_core::models::{secondary_networks, TunnelRole, TunnelState};
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Mutex;

/// Standard WireGuard MTU when the config does not set one.
const DEFAULT_MTU: u32 = 1420;

/// What needs root or a real machine.
pub trait WgPlatform: Send + Sync {
    /// A fresh tun device and the packet stream the engine reads and writes.
    fn create_tun(&self, mtu: u32) -> io::Result<(Box<dyn TunDevice>, Box<dyn PacketIo>)>;
    /// First usable address of `host:port` (IPv4 preferred).
    fn resolve(&self, endpoint: &str) -> Option<SocketAddr>;
}

struct Active {
    profile_id: String,
    owner_uid: u32,
    role: TunnelRole,
    record: Record,
    tun: Box<dyn TunDevice>,
    engine: Engine,
    warnings: Vec<WireGuardWarning>,
    dns_applied: bool,
}

pub struct WireGuardExecutor {
    platform: Box<dyn WgPlatform>,
    runner: Box<dyn Runner>,
    journal: Journal,
    /// Where split-DNS files go (`/etc/resolver`).
    resolver_dir: PathBuf,
    active: Mutex<Option<Active>>,
    log: EventLog,
}

fn warning(warning: Warning) -> WireGuardWarning {
    match warning {
        Warning::IgnoredHook => WireGuardWarning::IgnoredHook,
        Warning::IgnoredSaveConfig => WireGuardWarning::IgnoredSaveConfig,
    }
}

fn ifconfig_address_args(tun: &str, address: &IpNet) -> Vec<String> {
    match address {
        IpNet::V4(net) => vec![
            tun.into(),
            "inet".into(),
            format!("{}/{}", net.addr(), net.prefix_len()),
            net.addr().to_string(),
            "alias".into(),
        ],
        IpNet::V6(net) => vec![
            tun.into(),
            "inet6".into(),
            net.addr().to_string(),
            "prefixlen".into(),
            net.prefix_len().to_string(),
            "alias".into(),
        ],
    }
}

fn covers(networks: &[IpNet], v6: bool) -> bool {
    networks
        .iter()
        .any(|net| net.prefix_len() == 0 && net.addr().is_ipv6() == v6)
}

impl WireGuardExecutor {
    pub fn new(
        platform: Box<dyn WgPlatform>,
        runner: Box<dyn Runner>,
        journal: Journal,
        resolver_dir: PathBuf,
    ) -> Self {
        Self {
            platform,
            runner,
            journal,
            resolver_dir,
            active: Mutex::new(None),
            log: EventLog::default(),
        }
    }

    /// Where connect, disconnect and failures are written for the app's Logs page.
    pub fn with_log(mut self, log: EventLog) -> Self {
        self.log = log;
        self
    }

    fn status_of(active: &Active) -> WireGuardStatusResult {
        let stats = active.engine.stats();
        WireGuardStatusResult {
            profile_id: active.profile_id.clone(),
            state: if active.engine.alive() {
                TunnelState::Running
            } else {
                TunnelState::Failed
            },
            interface_name: Some(active.record.interface.clone()),
            latest_handshake: stats.latest_handshake,
            rx_bytes: stats.rx_bytes,
            tx_bytes: stats.tx_bytes,
            dns_applied: active.dns_applied,
            warnings: active.warnings.clone(),
        }
    }

    fn stopped(profile_id: &str) -> WireGuardStatusResult {
        WireGuardStatusResult {
            profile_id: profile_id.into(),
            state: TunnelState::Stopped,
            interface_name: None,
            latest_handshake: None,
            rx_bytes: 0,
            tx_bytes: 0,
            dns_applied: false,
            warnings: Vec::new(),
        }
    }

    /// Reverse order; the journal stays when DNS could not be put back.
    fn teardown(&self, active: Active) -> io::Result<()> {
        let Active {
            engine,
            record,
            tun,
            ..
        } = active;
        engine.stop();
        let dns_ok = match &record.dns {
            Some(snapshot) => dns::restore(&*self.runner, snapshot).is_ok(),
            None => true,
        };
        routes::remove(&*self.runner, &record.routes);
        resolver::remove(&*self.runner, &self.resolver_dir, &record.resolver_domains);
        drop(tun);
        if dns_ok {
            self.journal.clear()
        } else {
            Err(io::Error::other("system DNS could not be restored"))
        }
    }

    /// Undo the changes of an engine that died on its own.
    pub fn reap(&self) {
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if guard.as_ref().is_some_and(|active| !active.engine.alive()) {
            if let Some(active) = guard.take() {
                self.log
                    .warning("the tunnel stopped on its own; its routes and DNS were undone");
                let _ = self.teardown(active);
            }
        }
    }

    pub fn connect(
        &self,
        uid: u32,
        params: WireGuardConnectParams,
    ) -> Result<WireGuardConnectResult, Error> {
        self.log.hand_to(uid);
        self.log.info(&format!(
            "connecting ({})",
            if params.role == TunnelRole::Secondary {
                "secondary"
            } else {
                "primary"
            }
        ));
        let result = self.connect_logged(uid, params);
        match &result {
            Ok(connected) => {
                let status = &connected.status;
                self.log.info(&format!(
                    "connected on {}",
                    status
                        .interface_name
                        .as_deref()
                        .unwrap_or("an unnamed interface")
                ));
                for warning in &status.warnings {
                    self.log.warning(match warning {
                        WireGuardWarning::Ipv6NotCovered => {
                            "IPv6 is not covered by the allowed addresses and keeps using the uplink"
                        }
                        WireGuardWarning::DnsNotApplied => "the tunnel's DNS settings were not applied",
                        WireGuardWarning::IgnoredHook => "a PostUp/PreDown hook in the config was ignored",
                        WireGuardWarning::IgnoredSaveConfig => "SaveConfig in the config was ignored",
                    });
                }
            }
            Err(error) => self.log.error(&error.to_string()),
        }
        result
    }

    fn connect_logged(
        &self,
        uid: u32,
        params: WireGuardConnectParams,
    ) -> Result<WireGuardConnectResult, Error> {
        if params.profile_id.is_empty() || params.profile_id.len() > 128 {
            return Err(Error::Invalid("invalid profile id".into()));
        }
        let config = wireguard_config::parse(&params.config)
            .map_err(|error| Error::Invalid(error.to_string()))?;
        let secondary = params.role == TunnelRole::Secondary;
        let networks = if secondary {
            secondary_networks(&params.routes).map_err(|message| Error::Invalid(message.into()))?
        } else {
            Vec::new()
        };
        self.reap();
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = guard.as_ref() {
            return Err(Error::Conflict(if active.profile_id == params.profile_id {
                "this connection is already running".into()
            } else {
                "another WireGuard connection already owns the tunnel".into()
            }));
        }
        self.recover_locked()?;

        let uplink = routes::detect_uplink(&*self.runner).map_err(|err| {
            if err.kind() == io::ErrorKind::AlreadyExists {
                Error::Conflict(err.to_string())
            } else {
                Error::Unavailable("There is no network connection to use".into())
            }
        })?;
        let mut peers = Vec::with_capacity(config.peers.len());
        for peer in &config.peers {
            let endpoint = match &peer.endpoint {
                Some(text) => Some(self.platform.resolve(text).ok_or_else(|| {
                    Error::Unavailable("The WireGuard endpoint could not be resolved".into())
                })?),
                None => None,
            };
            let mut allowed_ips = peer.allowed_ips.clone();
            if secondary && config.peers.len() == 1 {
                // The user's networks must reach the only peer even when the
                // config's AllowedIPs name something narrower.
                for net in &networks {
                    if !allowed_ips.contains(net) {
                        allowed_ips.push(*net);
                    }
                }
            }
            peers.push(PeerSetup {
                public_key: peer.public_key,
                preshared_key: peer.preshared_key,
                endpoint,
                allowed_ips,
                keepalive: peer.keepalive,
            });
        }
        let mut record = Record {
            profile_id: params.profile_id.clone(),
            interface: String::new(),
            pid: 0,
            routes: Vec::new(),
            dns: None,
            resolver_domains: Vec::new(),
        };
        self.journal
            .save(&record)
            .map_err(|_| Error::Unavailable("The tunnel state could not be recorded".into()))?;
        let rollback = |this: &Self, record: &Record, dns_touched: bool| {
            routes::remove(&*this.runner, &record.routes);
            if let (true, Some(snapshot)) = (dns_touched, &record.dns) {
                let _ = dns::restore(&*this.runner, snapshot);
            }
            let _ = this.journal.clear();
        };

        let (tun, io) = self
            .platform
            .create_tun(config.mtu.unwrap_or(DEFAULT_MTU))
            .map_err(|err| {
                rollback(self, &record, false);
                eprintln!("network-orchestrator-helper: wireguard device: {err}");
                if err.kind() == io::ErrorKind::PermissionDenied {
                    Error::Unavailable(format!("The helper may not create a tunnel device ({err})"))
                } else {
                    Error::Unavailable(format!("The tunnel device could not be created ({err})"))
                }
            })?;
        record.interface = tun.name().to_string();
        for address in &config.addresses {
            if let Err(err) = self
                .runner
                .run(IFCONFIG, &ifconfig_address_args(tun.name(), address))
            {
                eprintln!("network-orchestrator-helper: wireguard address: {err}");
                rollback(self, &record, false);
                return Err(Error::Unavailable(format!(
                    "The tunnel address could not be set ({err})"
                )));
            }
        }

        let all_allowed: Vec<IpNet> = config
            .peers
            .iter()
            .flat_map(|peer| peer.allowed_ips.iter().copied())
            .collect();
        let planned = if secondary {
            routes::interface_routes(tun.name(), &networks)
        } else if config.table_off {
            Vec::new()
        } else {
            routes::interface_routes(tun.name(), &all_allowed)
        };
        record.routes = planned.iter().filter(|op| !op.optional).cloned().collect();
        // The primary replaces its service's DNS; a secondary only adds
        // per-domain resolvers and never touches the system DNS.
        let snapshot = if config.dns_servers.is_empty() || secondary {
            None
        } else {
            dns::snapshot(&*self.runner, &uplink.interface).ok()
        };
        let split_dns: Vec<String> = if secondary && !config.dns_servers.is_empty() {
            params.dns_domains.clone()
        } else {
            Vec::new()
        };
        record.resolver_domains = split_dns
            .iter()
            .map(|domain| domain.to_ascii_lowercase())
            .filter(|domain| net_manager_core::models::valid_dns_suffix(domain))
            .collect();
        record.dns = snapshot.clone();
        record.pid = std::process::id();
        if self.journal.save(&record).is_err() {
            rollback(self, &record, false);
            return Err(Error::Unavailable(
                "The tunnel state could not be recorded".into(),
            ));
        }

        let engine = Engine::start(
            EngineConfig {
                private_key: config.private_key,
                listen_port: config.listen_port.unwrap_or(0),
                peers,
                bind_interface: Some(uplink.interface.clone()),
            },
            io,
        )
        .map_err(|err| {
            eprintln!("network-orchestrator-helper: wireguard engine: {err}");
            rollback(self, &record, false);
            Error::Unavailable(format!("The WireGuard engine could not start ({err})"))
        })?;

        match routes::apply(&*self.runner, &planned) {
            Ok(installed) if secondary && installed.is_empty() => {
                engine.stop();
                record.routes.clear();
                rollback(self, &record, false);
                return Err(Error::Unavailable(
                    "None of this connection's networks could be routed".into(),
                ));
            }
            Ok(installed) => {
                record.routes = installed;
                let _ = self.journal.save(&record);
            }
            Err(err) => {
                eprintln!("network-orchestrator-helper: wireguard routes: {err}");
                engine.stop();
                record.routes.clear();
                rollback(self, &record, false);
                return Err(Error::Unavailable(format!(
                    "The tunnel routes could not be installed ({err})"
                )));
            }
        }

        let mut warnings: Vec<WireGuardWarning> =
            config.warnings.iter().copied().map(warning).collect();
        let mut dns_applied = false;
        if let Some(snapshot) = &snapshot {
            match dns::apply(&*self.runner, snapshot, &config.dns_servers) {
                Ok(()) => dns_applied = true,
                Err(_) => {
                    // Not fatal: the tunnel works, names resolve as before.
                    warnings.push(WireGuardWarning::DnsNotApplied);
                    let _ = dns::restore(&*self.runner, snapshot);
                    record.dns = None;
                    let _ = self.journal.save(&record);
                }
            }
        } else if !config.dns_servers.is_empty() {
            warnings.push(WireGuardWarning::DnsNotApplied);
        }
        if !record.resolver_domains.is_empty() {
            match resolver::apply(
                &*self.runner,
                &self.resolver_dir,
                &record.resolver_domains,
                &config.dns_servers,
            ) {
                Ok(written) => dns_applied = !written.is_empty(),
                Err(_) => warnings.push(WireGuardWarning::DnsNotApplied),
            }
            let _ = self.journal.save(&record);
        }
        if !secondary
            && !config.table_off
            && covers(&all_allowed, false)
            && !covers(&all_allowed, true)
        {
            // IPv4 is captured but IPv6 keeps using the uplink.
            warnings.push(WireGuardWarning::Ipv6NotCovered);
        }
        let active = Active {
            profile_id: params.profile_id,
            owner_uid: uid,
            role: params.role,
            record,
            tun,
            engine,
            warnings,
            dns_applied,
        };
        let status = Self::status_of(&active);
        *guard = Some(active);
        Ok(WireGuardConnectResult { status })
    }

    pub fn status(&self, uid: u32, profile_id: &str) -> WireGuardStatusResult {
        self.reap();
        let guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(active) if active.profile_id == profile_id && active.owner_uid == uid => {
                Self::status_of(active)
            }
            _ => Self::stopped(profile_id),
        }
    }

    pub fn disconnect(
        &self,
        uid: u32,
        profile_id: &str,
    ) -> Result<WireGuardDisconnectResult, Error> {
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        match guard.as_ref() {
            Some(active) if active.profile_id == profile_id && active.owner_uid == uid => {}
            _ => return Ok(WireGuardDisconnectResult { stopped: false }),
        }
        let active = guard.take().expect("checked above");
        self.teardown(active).map_err(|_| {
            self.log
                .error("the previous DNS settings could not be restored");
            Error::Unavailable("The previous DNS settings could not be restored".into())
        })?;
        self.log.info("disconnected");
        Ok(WireGuardDisconnectResult { stopped: true })
    }

    pub fn holds_primary(&self) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .is_some_and(|active| active.role == TunnelRole::Primary)
    }

    pub fn active(&self) -> bool {
        self.active
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .is_some()
    }

    pub fn owned(&self) -> Option<Record> {
        let guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        guard
            .as_ref()
            .map(|active| active.record.clone())
            .or_else(|| self.journal.load().ok().flatten())
    }

    /// A live tunnel is left to its own disconnect; only what a dead helper
    /// left in the journal is undone.
    pub fn recover(&self) -> io::Result<bool> {
        let guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_some() {
            return Ok(false);
        }
        self.recover_locked_io()
    }

    fn recover_locked(&self) -> Result<(), Error> {
        self.recover_locked_io()
            .map(|_| ())
            .map_err(|_| Error::Unavailable("A previous tunnel could not be cleaned up".into()))
    }

    /// The engine lived inside the dead helper, so only routes and DNS remain.
    fn recover_locked_io(&self) -> io::Result<bool> {
        let Some(record) = self.journal.load()? else {
            return Ok(false);
        };
        let dns_ok = match &record.dns {
            Some(snapshot) => dns::restore(&*self.runner, snapshot).is_ok(),
            None => true,
        };
        routes::remove(&*self.runner, &record.routes);
        resolver::remove(&*self.runner, &self.resolver_dir, &record.resolver_domains);
        if dns_ok {
            self.journal.clear()?;
            Ok(true)
        } else {
            Err(io::Error::other("system DNS could not be restored"))
        }
    }

    pub fn shutdown(&self) {
        let mut guard = self.active.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(active) = guard.take() {
            let _ = self.teardown(active);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sysexec::fake::FakeRunner;
    use base64::Engine as _;
    use std::os::fd::{AsRawFd, RawFd};
    use std::os::unix::net::UnixDatagram;
    use std::sync::Arc;

    struct FakeTun(String);
    impl TunDevice for FakeTun {
        fn name(&self) -> &str {
            &self.0
        }
    }

    struct FakeIo(UnixDatagram);
    impl PacketIo for FakeIo {
        fn raw_fd(&self) -> RawFd {
            self.0.as_raw_fd()
        }
        fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.0.recv(buf)
        }
        fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
            self.0.send(packet).map(|_| ())
        }
    }

    #[derive(Default)]
    struct Flags {
        tun_fails: std::sync::atomic::AtomicBool,
        unresolvable: std::sync::atomic::AtomicBool,
    }

    struct FakePlatform(Arc<Flags>);
    impl WgPlatform for FakePlatform {
        fn create_tun(&self, _: u32) -> io::Result<(Box<dyn TunDevice>, Box<dyn PacketIo>)> {
            if self.0.tun_fails.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(io::Error::from(io::ErrorKind::PermissionDenied));
            }
            let (engine_side, _test_side) = UnixDatagram::pair().unwrap();
            engine_side.set_nonblocking(true).unwrap();
            // The far end is leaked on purpose: closing it would look like the
            // device vanishing and stop the engine.
            std::mem::forget(_test_side);
            Ok((
                Box::new(FakeTun("utun11".into())),
                Box::new(FakeIo(engine_side)),
            ))
        }
        fn resolve(&self, endpoint: &str) -> Option<SocketAddr> {
            if self
                .0
                .unresolvable
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                return None;
            }
            endpoint
                .parse()
                .ok()
                .or_else(|| Some("203.0.113.7:51820".parse().unwrap()))
        }
    }

    fn key(byte: u8) -> String {
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    }

    fn config(allowed: &str, dns: &str) -> String {
        format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.7.0.2/32\n{}\n[Peer]\nPublicKey = {}\nEndpoint = vpn.example.com:51820\nAllowedIPs = {}\nPersistentKeepalive = 25\n",
            key(1),
            dns,
            key(2),
            allowed
        )
    }

    fn params(id: &str, config: String) -> WireGuardConnectParams {
        WireGuardConnectParams {
            profile_id: id.into(),
            config,
            routes: vec![],
            interface_name: None,
            role: Default::default(),
            dns_domains: Vec::new(),
        }
    }

    struct Fixture {
        executor: WireGuardExecutor,
        flags: Arc<Flags>,
        runner: Arc<FakeRunner>,
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn runner_box(&self) -> Box<dyn Runner> {
            Box::new(Shared(self.runner.clone()))
        }
    }

    struct Shared(Arc<FakeRunner>);
    impl Runner for Shared {
        fn run(&self, program: &str, args: &[String]) -> io::Result<String> {
            self.0.run(program, args)
        }
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let flags = Arc::new(Flags::default());
        let runner = Arc::new(FakeRunner::default());
        runner.reply(
            "route -n get default",
            "gateway: 192.168.1.1\n interface: en0\n",
        );
        runner.reply(
            "networksetup -listnetworkserviceorder",
            "(1) Wi-Fi\n(Hardware Port: Wi-Fi, Device: en0)\n",
        );
        runner.reply("networksetup -getdnsservers", "1.1.1.1\n");
        let executor = WireGuardExecutor::new(
            Box::new(FakePlatform(flags.clone())),
            Box::new(Shared(runner.clone())),
            Journal::named(dir.path(), "wireguard.json"),
            dir.path().join("resolver"),
        );
        Fixture {
            executor,
            flags,
            runner,
            dir,
        }
    }

    #[test]
    fn full_tunnel_sets_address_routes_and_dns_and_disconnect_undoes_them() {
        let f = fixture();
        let result = f
            .executor
            .connect(
                501,
                params("wg", config("0.0.0.0/0, ::/0", "DNS = 10.7.0.1")),
            )
            .unwrap();
        assert_eq!(result.status.state, TunnelState::Running);
        assert_eq!(result.status.interface_name.as_deref(), Some("utun11"));
        assert!(result.status.dns_applied);
        assert!(result.status.warnings.is_empty());

        let calls = f.runner.calls();
        assert!(calls.contains(&"ifconfig utun11 inet 10.7.0.2/32 10.7.0.2 alias".to_string()));
        for expected in [
            "route -n add -net 0.0.0.0 -netmask 128.0.0.0 -interface utun11",
            "route -n add -net 128.0.0.0 -netmask 128.0.0.0 -interface utun11",
            "route -n add -inet6 -net :: -prefixlen 1 -interface utun11",
            "route -n add -inet6 -net 8000:: -prefixlen 1 -interface utun11",
            "networksetup -setdnsservers Wi-Fi 10.7.0.1",
        ] {
            assert!(calls.contains(&expected.to_string()), "{expected}");
        }
        assert_eq!(f.executor.owned().unwrap().interface, "utun11");

        assert!(f.executor.disconnect(501, "wg").unwrap().stopped);
        let calls = f.runner.calls();
        assert!(calls.contains(&"networksetup -setdnsservers Wi-Fi 1.1.1.1".to_string()));
        assert!(calls
            .iter()
            .any(|c| c.starts_with("route -n delete -net 0.0.0.0")));
        assert!(f.executor.owned().is_none());
        assert_eq!(f.executor.status(501, "wg").state, TunnelState::Stopped);
    }

    #[test]
    fn split_tunnel_routes_only_the_allowed_networks_and_skips_failures() {
        let f = fixture();
        f.runner.fail("route -n add -net 192.168.50.0");
        let result = f
            .executor
            .connect(
                501,
                params("wg", config("10.9.0.0/16, 192.168.50.0/24", "")),
            )
            .unwrap();
        assert_eq!(result.status.state, TunnelState::Running);
        let calls = f.runner.calls();
        assert!(calls.contains(
            &"route -n add -net 10.9.0.0 -netmask 255.255.0.0 -interface utun11".to_string()
        ));
        // No default capture and no DNS change without a DNS line.
        assert!(!calls.iter().any(|c| c.contains("-setdnsservers")));
        // The failed (optional) route is not ours to delete later.
        f.executor.disconnect(501, "wg").unwrap();
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n delete -net 192.168.50.0")));
    }

    #[test]
    fn v4_only_default_warns_that_ipv6_is_not_covered() {
        let f = fixture();
        let result = f
            .executor
            .connect(501, params("wg", config("0.0.0.0/0", "")))
            .unwrap();
        assert!(result
            .status
            .warnings
            .contains(&WireGuardWarning::Ipv6NotCovered));
    }

    #[test]
    fn table_off_installs_no_routes_and_hooks_are_reported() {
        let f = fixture();
        let text = config("0.0.0.0/0", "Table = off\nPostUp = rm -rf /");
        let result = f.executor.connect(501, params("wg", text)).unwrap();
        assert!(result
            .status
            .warnings
            .contains(&WireGuardWarning::IgnoredHook));
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n add")));
        // Nothing the config said was ever executed.
        assert!(!f.runner.calls().iter().any(|c| c.contains("rm -rf")));
    }

    #[test]
    fn a_required_route_failure_rolls_everything_back() {
        let f = fixture();
        f.runner.fail("route -n add -net 128.0.0.0");
        let error = f
            .executor
            .connect(501, params("wg", config("0.0.0.0/0", "DNS = 10.7.0.1")))
            .expect_err("must fail");
        assert!(matches!(error, Error::Unavailable(_)));
        assert!(f.executor.owned().is_none());
        // DNS was never touched, so it is not "restored" either.
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.contains("-setdnsservers")));
    }

    #[test]
    fn device_resolution_and_config_errors_are_reported_without_side_effects() {
        let f = fixture();
        f.flags
            .tun_fails
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            f.executor
                .connect(501, params("wg", config("0.0.0.0/0", ""))),
            Err(Error::Unavailable(_))
        ));
        f.flags
            .tun_fails
            .store(false, std::sync::atomic::Ordering::SeqCst);
        f.flags
            .unresolvable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            f.executor
                .connect(501, params("wg", config("0.0.0.0/0", ""))),
            Err(Error::Unavailable(_))
        ));
        assert!(matches!(
            f.executor.connect(501, params("wg", "garbage".into())),
            Err(Error::Invalid(_))
        ));
        assert!(f.executor.owned().is_none());
        assert!(!f
            .runner
            .calls()
            .iter()
            .any(|c| c.starts_with("route -n add")));
    }

    #[test]
    fn a_second_connection_and_other_users_are_refused() {
        let f = fixture();
        f.executor
            .connect(501, params("wg", config("0.0.0.0/0", "")))
            .unwrap();
        assert!(matches!(
            f.executor
                .connect(501, params("other", config("0.0.0.0/0", ""))),
            Err(Error::Conflict(_))
        ));
        assert_eq!(f.executor.status(502, "wg").state, TunnelState::Stopped);
        assert!(!f.executor.disconnect(502, "wg").unwrap().stopped);
    }

    fn logged(f: &Fixture) -> String {
        std::fs::read_to_string(f.dir.path().join("wireguard.log")).unwrap_or_default()
    }

    #[test]
    fn connecting_and_disconnecting_leave_a_readable_trail() {
        let mut f = fixture();
        f.executor = f
            .executor
            .with_log(EventLog::at(f.dir.path().join("wireguard.log")));
        f.executor
            .connect(501, params("wg", config("0.0.0.0/0", "")))
            .unwrap();
        f.executor.disconnect(501, "wg").unwrap();
        let log = logged(&f);
        assert!(log.contains("[Info] connecting (primary)"), "{log}");
        assert!(log.contains("[Info] connected on utun"), "{log}");
        assert!(log.contains("[Warning] IPv6 is not covered"), "{log}");
        assert!(log.contains("[Info] disconnected"), "{log}");
        // No keys, endpoints or profile ids.
        assert!(
            !log.contains("vpn.example.com") && !log.contains("wg\n"),
            "{log}"
        );
    }

    #[test]
    fn a_failed_connect_is_logged_with_the_reason_shown_to_the_user() {
        let mut f = fixture();
        f.executor = f
            .executor
            .with_log(EventLog::at(f.dir.path().join("wireguard.log")));
        f.flags
            .unresolvable
            .store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(f
            .executor
            .connect(501, params("wg", config("0.0.0.0/0", "")))
            .is_err());
        assert!(
            logged(&f).contains("[Error] The WireGuard endpoint could not be resolved"),
            "{}",
            logged(&f)
        );
    }

    #[test]
    fn recovery_leaves_a_live_tunnel_alone() {
        let f = fixture();
        f.executor
            .connect(501, params("wg", config("0.0.0.0/0", "")))
            .unwrap();
        assert!(!f.executor.recover().unwrap());
        assert!(f.executor.owned().is_some());
        assert_eq!(f.executor.status(501, "wg").state, TunnelState::Running);
    }

    #[test]
    fn recovery_removes_a_dead_helpers_routes_and_dns() {
        let f = fixture();
        let record = Record {
            profile_id: "wg".into(),
            interface: "utun11".into(),
            pid: 4,
            routes: routes::interface_routes("utun11", &["0.0.0.0/0".parse().unwrap()]),
            dns: Some(dns::Snapshot {
                service: "Wi-Fi".into(),
                servers: vec![],
            }),
            resolver_domains: Vec::new(),
        };
        Journal::named(f.dir.path(), "wireguard.json")
            .save(&record)
            .unwrap();
        assert!(f.executor.recover().unwrap());
        let calls = f.runner.calls();
        assert!(calls.contains(&"networksetup -setdnsservers Wi-Fi Empty".to_string()));
        assert!(calls.iter().any(|c| c.starts_with("route -n delete")));
        assert!(!f.executor.recover().unwrap());
    }

    fn secondary(
        id: &str,
        text: String,
        networks: &[&str],
        domains: &[&str],
    ) -> WireGuardConnectParams {
        use net_manager_core::models::PolicyRoute;
        let mut p = params(id, text);
        p.role = TunnelRole::Secondary;
        p.routes = networks
            .iter()
            .map(|n| PolicyRoute {
                destination: n.parse().unwrap(),
                metric: 5,
                via: None,
            })
            .collect();
        p.dns_domains = domains.iter().map(|d| d.to_string()).collect();
        p
    }

    #[test]
    fn a_secondary_tunnel_routes_only_its_networks_and_adds_split_dns() {
        let f = fixture();
        let result = f
            .executor
            .connect(
                501,
                secondary(
                    "corp",
                    config("0.0.0.0/0, ::/0", "DNS = 10.20.0.53"),
                    &["10.20.0.0/16"],
                    &["corp.example"],
                ),
            )
            .unwrap();
        assert!(result.status.dns_applied);
        let calls = f.runner.calls();
        // Only the listed network — the config's default route is ignored.
        assert!(calls.contains(
            &"route -n add -net 10.20.0.0 -netmask 255.255.0.0 -interface utun11".to_string()
        ));
        assert!(!calls
            .iter()
            .any(|c| c.starts_with("route -n add -net 0.0.0.0")));
        assert!(!calls
            .iter()
            .any(|c| c.contains("-setdnsservers") || c.contains("getdnsservers")));
        // Split DNS instead of the system DNS.
        let file = f.dir.path().join("resolver/corp.example");
        let text = std::fs::read_to_string(&file).unwrap();
        assert!(text.contains("nameserver 10.20.0.53"));
        assert!(!f.executor.holds_primary());
        assert_eq!(
            f.executor.owned().unwrap().resolver_domains,
            ["corp.example"]
        );

        f.executor.disconnect(501, "corp").unwrap();
        assert!(!file.exists());
        assert!(f.executor.owned().is_none());
    }

    #[test]
    fn a_secondary_tunnel_without_domains_leaves_dns_completely_alone() {
        let f = fixture();
        f.executor
            .connect(
                501,
                secondary(
                    "corp",
                    config("10.20.0.0/16", "DNS = 10.20.0.53"),
                    &["10.20.0.0/16"],
                    &[],
                ),
            )
            .unwrap();
        assert!(!f.dir.path().join("resolver").exists());
        assert!(!f.runner.calls().iter().any(|c| c.contains("dnsservers")));
    }

    #[test]
    fn secondary_networks_are_validated_and_must_be_routable() {
        let f = fixture();
        for bad in [vec![], vec!["0.0.0.0/0"]] {
            assert!(matches!(
                f.executor.connect(
                    501,
                    secondary("corp", config("10.20.0.0/16", ""), &bad, &[])
                ),
                Err(Error::Invalid(_))
            ));
        }
        f.runner.fail("route -n add -net 10.20.0.0");
        assert!(matches!(
            f.executor.connect(
                501,
                secondary("corp", config("10.20.0.0/16", ""), &["10.20.0.0/16"], &[])
            ),
            Err(Error::Unavailable(_))
        ));
        assert!(f.executor.owned().is_none());
    }

    #[test]
    fn recovery_removes_split_dns_files_a_dead_helper_left() {
        let f = fixture();
        let dir = f.dir.path().join("resolver");
        std::fs::create_dir_all(&dir).unwrap();
        let domains = vec!["corp.example".to_string()];
        crate::resolver::apply(
            &*f.runner_box(),
            &dir,
            &domains,
            &["10.20.0.53".parse().unwrap()],
        )
        .unwrap();
        let record = Record {
            profile_id: "wg".into(),
            interface: "utun11".into(),
            pid: 4,
            routes: vec![],
            dns: None,
            resolver_domains: domains,
        };
        Journal::named(f.dir.path(), "wireguard.json")
            .save(&record)
            .unwrap();
        assert!(f.executor.recover().unwrap());
        assert!(!dir.join("corp.example").exists());
    }
}
