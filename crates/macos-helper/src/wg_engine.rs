//! Userspace WireGuard data path: one thread moves IP packets between a tun
//! device and UDP sockets through `boringtun`'s per-peer state machines
//! (handshakes, sessions, timers). No kernel module, no external binary.
//!
//! The UDP sockets are bound to the physical interface (`IP_BOUND_IF`), so the
//! tunnel's own traffic never re-enters the routes it installs.

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::IpNet;
use std::io;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_PACKET: usize = 65_536;
const TICK: Duration = Duration::from_millis(250);
/// macOS socket options that pin a socket to one interface.
const IP_BOUND_IF: libc::c_int = 25;
const IPV6_BOUND_IF: libc::c_int = 125;

/// A tun device as the engine sees it: whole IP packets, no link header.
pub trait PacketIo: Send {
    fn raw_fd(&self) -> RawFd;
    /// One packet, or `WouldBlock`.
    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize>;
    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()>;
}

/// A `utun` descriptor: every packet carries a 4-byte address-family header.
pub struct UtunIo {
    fd: OwnedFd,
}

impl UtunIo {
    pub fn new(fd: OwnedFd) -> io::Result<Self> {
        // SAFETY: plain fcntl on a descriptor we own.
        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
        if flags < 0
            || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { fd })
    }
}

impl PacketIo for UtunIo {
    fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    fn read_packet(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut framed = vec![0u8; buf.len() + 4];
        // SAFETY: the buffer is valid for its length.
        let n = unsafe {
            libc::read(
                self.fd.as_raw_fd(),
                framed.as_mut_ptr().cast(),
                framed.len(),
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        if n <= 4 {
            return Ok(0);
        }
        buf[..n - 4].copy_from_slice(&framed[4..n]);
        Ok(n - 4)
    }

    fn write_packet(&mut self, packet: &[u8]) -> io::Result<()> {
        let family = match packet.first().map(|b| b >> 4) {
            Some(4) => libc::AF_INET as u8,
            Some(6) => libc::AF_INET6 as u8,
            _ => return Err(io::Error::from(io::ErrorKind::InvalidData)),
        };
        let mut framed = Vec::with_capacity(packet.len() + 4);
        framed.extend_from_slice(&[0, 0, 0, family]);
        framed.extend_from_slice(packet);
        // SAFETY: the buffer is valid for its length.
        let n = unsafe { libc::write(self.fd.as_raw_fd(), framed.as_ptr().cast(), framed.len()) };
        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }
}

pub struct PeerSetup {
    pub public_key: [u8; 32],
    pub preshared_key: Option<[u8; 32]>,
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub keepalive: Option<u16>,
}

pub struct EngineConfig {
    pub private_key: [u8; 32],
    /// 0 picks a random port.
    pub listen_port: u16,
    pub peers: Vec<PeerSetup>,
    /// Interface the UDP sockets are pinned to; `None` leaves them unbound.
    pub bind_interface: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    /// Unix time of the newest completed handshake.
    pub latest_handshake: Option<u64>,
}

pub struct Engine {
    stop: OwnedFd,
    alive: Arc<AtomicBool>,
    stats: Arc<Mutex<Stats>>,
    handle: Option<JoinHandle<()>>,
}

fn bind_to_interface(socket: &UdpSocket, name: &str, v6: bool) -> io::Result<()> {
    let cname = std::ffi::CString::new(name)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid interface"))?;
    // SAFETY: a valid C string.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        return Err(io::Error::last_os_error());
    }
    let (level, option) = if v6 {
        (libc::IPPROTO_IPV6, IPV6_BOUND_IF)
    } else {
        (libc::IPPROTO_IP, IP_BOUND_IF)
    };
    // SAFETY: a plain integer option on a socket we own.
    let rc = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            level,
            option,
            (&index as *const libc::c_uint).cast(),
            std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
        )
    };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn open_socket(port: u16, v6: bool, interface: Option<&str>) -> io::Result<UdpSocket> {
    let addr: SocketAddr = if v6 {
        (std::net::Ipv6Addr::UNSPECIFIED, port).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, port).into()
    };
    let socket = UdpSocket::bind(addr)?;
    socket.set_nonblocking(true)?;
    if let Some(name) = interface {
        bind_to_interface(&socket, name, v6)?;
    }
    Ok(socket)
}

struct PeerState {
    tunn: Tunn,
    public_key: [u8; 32],
    endpoint: Option<SocketAddr>,
    allowed: Vec<IpNet>,
}

struct Runner {
    device: Box<dyn PacketIo>,
    udp4: Option<UdpSocket>,
    udp6: Option<UdpSocket>,
    private: StaticSecret,
    public: PublicKey,
    peers: Vec<PeerState>,
    out: Vec<u8>,
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Runner {
    fn send(&self, to: SocketAddr, data: &[u8]) {
        let socket = if to.is_ipv4() { &self.udp4 } else { &self.udp6 };
        if let Some(socket) = socket {
            // A full buffer or an unreachable endpoint drops this datagram;
            // WireGuard retransmits what matters.
            let _ = socket.send_to(data, to);
        }
    }

    /// The peer whose longest matching `AllowedIPs` entry contains `dst`.
    fn peer_for(&self, dst: IpAddr) -> Option<usize> {
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(index, peer)| {
                peer.allowed
                    .iter()
                    .filter(|net| net.contains(&dst))
                    .map(IpNet::prefix_len)
                    .max()
                    .map(|len| (index, len))
            })
            .max_by_key(|(_, len)| *len)
            .map(|(index, _)| index)
    }

    fn outgoing(&mut self, packet: &[u8]) {
        let Some(dst) = Tunn::dst_address(packet) else {
            return;
        };
        let Some(index) = self.peer_for(dst) else {
            return;
        };
        let endpoint = self.peers[index].endpoint;
        let mut out = std::mem::take(&mut self.out);
        if let TunnResult::WriteToNetwork(datagram) =
            self.peers[index].tunn.encapsulate(packet, &mut out)
        {
            if let Some(endpoint) = endpoint {
                self.send(endpoint, datagram);
            }
        }
        self.out = out;
    }

    fn peer_for_datagram(&self, datagram: &[u8]) -> Option<usize> {
        match Tunn::parse_incoming_packet(datagram).ok()? {
            Packet::HandshakeInit(init) => {
                let half = parse_handshake_anon(&self.private, &self.public, &init).ok()?;
                self.peers
                    .iter()
                    .position(|peer| peer.public_key == half.peer_static_public)
            }
            Packet::HandshakeResponse(p) => self.index_of(p.receiver_idx),
            Packet::PacketCookieReply(p) => self.index_of(p.receiver_idx),
            Packet::PacketData(p) => self.index_of(p.receiver_idx),
        }
    }

    fn index_of(&self, receiver_idx: u32) -> Option<usize> {
        let index = (receiver_idx >> 8) as usize;
        (index < self.peers.len()).then_some(index)
    }

    fn incoming(&mut self, from: SocketAddr, datagram: &[u8]) {
        let Some(index) = self.peer_for_datagram(datagram) else {
            return;
        };
        let mut out = std::mem::take(&mut self.out);
        let mut input: &[u8] = datagram;
        let mut accepted = false;
        // After a handshake message, boringtun may have queued packets: call
        // again with an empty datagram until it reports nothing to do.
        loop {
            let result = self.peers[index]
                .tunn
                .decapsulate(Some(from.ip()), input, &mut out);
            input = &[];
            match result {
                TunnResult::Done => break,
                TunnResult::Err(_) => break,
                TunnResult::WriteToNetwork(reply) => {
                    accepted = true;
                    if let Some(endpoint) = self.peers[index].endpoint.or(Some(from)) {
                        let reply = reply.to_vec();
                        self.send(endpoint, &reply);
                    }
                }
                TunnResult::WriteToTunnelV4(packet, source) => {
                    accepted = true;
                    if self.peers[index]
                        .allowed
                        .iter()
                        .any(|n| n.contains(&IpAddr::V4(source)))
                    {
                        let _ = self.device.write_packet(packet);
                    }
                }
                TunnResult::WriteToTunnelV6(packet, source) => {
                    accepted = true;
                    if self.peers[index]
                        .allowed
                        .iter()
                        .any(|n| n.contains(&IpAddr::V6(source)))
                    {
                        let _ = self.device.write_packet(packet);
                    }
                }
            }
        }
        if accepted {
            // The peer may roam: answer where it last spoke from.
            self.peers[index].endpoint = Some(from);
        }
        self.out = out;
    }

    fn tick(&mut self) {
        let mut out = std::mem::take(&mut self.out);
        for index in 0..self.peers.len() {
            let endpoint = self.peers[index].endpoint;
            if let TunnResult::WriteToNetwork(datagram) =
                self.peers[index].tunn.update_timers(&mut out)
            {
                if let Some(endpoint) = endpoint {
                    self.send(endpoint, datagram);
                }
            }
        }
        self.out = out;
    }

    fn stats(&self) -> Stats {
        let mut stats = Stats::default();
        let now = unix_now();
        for peer in &self.peers {
            let (since, tx, rx, _, _) = peer.tunn.stats();
            stats.tx_bytes += tx as u64;
            stats.rx_bytes += rx as u64;
            if let Some(since) = since {
                let at = now.saturating_sub(since.as_secs());
                stats.latest_handshake = Some(stats.latest_handshake.map_or(at, |old| old.max(at)));
            }
        }
        stats
    }
}

fn readable(fd: RawFd, events: &[libc::pollfd]) -> bool {
    events
        .iter()
        .any(|e| e.fd == fd && e.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0)
}

fn run(mut runner: Runner, stop: RawFd, alive: &AtomicBool, shared: &Mutex<Stats>) {
    let device_fd = runner.device.raw_fd();
    let mut packet = vec![0u8; MAX_PACKET];
    let mut datagram = vec![0u8; MAX_PACKET];
    let mut last_tick = Instant::now();
    'outer: loop {
        let mut fds = vec![
            libc::pollfd {
                fd: stop,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: device_fd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let udp4 = runner.udp4.as_ref().map(|s| s.as_raw_fd());
        let udp6 = runner.udp6.as_ref().map(|s| s.as_raw_fd());
        for fd in [udp4, udp6].into_iter().flatten() {
            fds.push(libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            });
        }
        let timeout = TICK
            .checked_sub(last_tick.elapsed())
            .unwrap_or(Duration::ZERO)
            .as_millis() as libc::c_int;
        // SAFETY: `fds` is a valid array for the call.
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) };
        if ready < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            break;
        }
        if readable(stop, &fds) {
            break;
        }
        if readable(device_fd, &fds) {
            for _ in 0..256 {
                match runner.device.read_packet(&mut packet) {
                    Ok(0) => break,
                    Ok(n) => runner.outgoing(&packet[..n]),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    // The device went away (interface removed): stop.
                    Err(_) => break 'outer,
                }
            }
        }
        for (fd, v6) in [(udp4, false), (udp6, true)] {
            let Some(fd) = fd else { continue };
            if !readable(fd, &fds) {
                continue;
            }
            for _ in 0..256 {
                let socket = if v6 { &runner.udp6 } else { &runner.udp4 };
                let Some(socket) = socket else { break };
                match socket.recv_from(&mut datagram) {
                    Ok((n, from)) => {
                        let data = datagram[..n].to_vec();
                        runner.incoming(from, &data);
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(_) => break,
                }
            }
        }
        if last_tick.elapsed() >= TICK {
            runner.tick();
            if let Ok(mut stats) = shared.lock() {
                *stats = runner.stats();
            }
            last_tick = Instant::now();
        }
    }
    alive.store(false, Ordering::SeqCst);
}

impl Engine {
    pub fn start(config: EngineConfig, device: Box<dyn PacketIo>) -> io::Result<Self> {
        let private = StaticSecret::from(config.private_key);
        let public = PublicKey::from(&private);
        let mut peers = Vec::new();
        for (index, setup) in config.peers.iter().enumerate() {
            let tunn = Tunn::new(
                private.clone(),
                PublicKey::from(setup.public_key),
                setup.preshared_key,
                setup.keepalive,
                index as u32,
                None,
            )
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid peer parameters"))?;
            peers.push(PeerState {
                tunn,
                public_key: setup.public_key,
                endpoint: setup.endpoint,
                allowed: setup.allowed_ips.clone(),
            });
        }
        let interface = config.bind_interface.as_deref();
        let udp4 = open_socket(config.listen_port, false, interface).ok();
        let udp6 = open_socket(config.listen_port, true, interface).ok();
        if udp4.is_none() && udp6.is_none() {
            return Err(io::Error::other("no UDP socket could be opened"));
        }
        let mut pipe = [0 as libc::c_int; 2];
        // SAFETY: a two-element array for pipe().
        if unsafe { libc::pipe(pipe.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: both descriptors are fresh from pipe().
        let (read_end, write_end) =
            unsafe { (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1])) };
        let alive = Arc::new(AtomicBool::new(true));
        let stats = Arc::new(Mutex::new(Stats::default()));
        let runner = Runner {
            device,
            udp4,
            udp6,
            private,
            public,
            peers,
            out: vec![0u8; MAX_PACKET + 32],
        };
        let (alive_thread, stats_thread) = (alive.clone(), stats.clone());
        let handle = std::thread::Builder::new()
            .name("wireguard".into())
            .spawn(move || {
                run(runner, read_end.as_raw_fd(), &alive_thread, &stats_thread);
                drop(read_end);
            })?;
        Ok(Self {
            stop: write_end,
            alive,
            stats,
            handle: Some(handle),
        })
    }

    pub fn alive(&self) -> bool {
        self.alive.load(Ordering::SeqCst)
    }

    pub fn stats(&self) -> Stats {
        self.stats.lock().map(|s| *s).unwrap_or_default()
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        // SAFETY: a single byte to the engine's wake-up pipe.
        unsafe { libc::write(self.stop.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixDatagram;

    /// A tun stand-in: every datagram is one packet.
    struct FakeDevice(UnixDatagram);
    impl PacketIo for FakeDevice {
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

    fn pair() -> (FakeDevice, UnixDatagram) {
        let (engine_side, test_side) = UnixDatagram::pair().unwrap();
        engine_side.set_nonblocking(true).unwrap();
        test_side
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        (FakeDevice(engine_side), test_side)
    }

    fn ipv4_packet(src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
        let total = 20 + 8 + payload.len();
        let mut p = vec![0u8; total];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&(total as u16).to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p[20..22].copy_from_slice(&1234u16.to_be_bytes());
        p[22..24].copy_from_slice(&5678u16.to_be_bytes());
        p[24..26].copy_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
        p[28..].copy_from_slice(payload);
        p
    }

    fn free_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port()
    }

    fn keypair(seed: u8) -> ([u8; 32], [u8; 32]) {
        let secret = StaticSecret::from([seed; 32]);
        let public = PublicKey::from(&secret);
        ([seed; 32], *public.as_bytes())
    }

    #[test]
    fn two_engines_handshake_and_carry_packets_both_ways() {
        let (a_priv, a_pub) = keypair(7);
        let (b_priv, b_pub) = keypair(9);
        let b_port = free_port();
        let (a_dev, a_side) = pair();
        let (b_dev, b_side) = pair();

        let b = Engine::start(
            EngineConfig {
                private_key: b_priv,
                listen_port: b_port,
                peers: vec![PeerSetup {
                    public_key: a_pub,
                    preshared_key: Some([5; 32]),
                    endpoint: None,
                    allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
                    keepalive: None,
                }],
                bind_interface: None,
            },
            Box::new(b_dev),
        )
        .unwrap();
        let a = Engine::start(
            EngineConfig {
                private_key: a_priv,
                listen_port: 0,
                peers: vec![PeerSetup {
                    public_key: b_pub,
                    preshared_key: Some([5; 32]),
                    endpoint: Some(format!("127.0.0.1:{b_port}").parse().unwrap()),
                    allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                    keepalive: Some(1),
                }],
                bind_interface: None,
            },
            Box::new(a_dev),
        )
        .unwrap();

        // A → B: the first packet triggers the handshake and is delivered after it.
        let hello = ipv4_packet([10, 0, 1, 2], [10, 0, 0, 5], b"ping");
        a_side.send(&hello).unwrap();
        let mut buf = vec![0u8; 2048];
        let n = b_side.recv(&mut buf).expect("B receives A's packet");
        assert_eq!(&buf[..n], &hello[..]);

        // B → A over the session B learned A's address from.
        let reply = ipv4_packet([10, 0, 0, 5], [10, 0, 1, 2], b"pong");
        b_side.send(&reply).unwrap();
        let n = a_side.recv(&mut buf).expect("A receives B's reply");
        assert_eq!(&buf[..n], &reply[..]);

        std::thread::sleep(Duration::from_millis(600));
        let stats = a.stats();
        assert!(stats.tx_bytes > 0 && stats.rx_bytes > 0, "{stats:?}");
        assert!(stats.latest_handshake.is_some());
        assert!(a.alive() && b.alive());
        a.stop();
        b.stop();
    }

    #[test]
    fn packets_outside_allowed_ips_are_dropped_in_both_directions() {
        let (a_priv, a_pub) = keypair(3);
        let (b_priv, b_pub) = keypair(4);
        let b_port = free_port();
        let (a_dev, a_side) = pair();
        let (b_dev, b_side) = pair();
        b_side
            .set_read_timeout(Some(Duration::from_millis(700)))
            .unwrap();
        let b = Engine::start(
            EngineConfig {
                private_key: b_priv,
                listen_port: b_port,
                peers: vec![PeerSetup {
                    public_key: a_pub,
                    preshared_key: None,
                    endpoint: None,
                    // B only accepts 10.0.1.0/24 from A.
                    allowed_ips: vec!["10.0.1.0/24".parse().unwrap()],
                    keepalive: None,
                }],
                bind_interface: None,
            },
            Box::new(b_dev),
        )
        .unwrap();
        let a = Engine::start(
            EngineConfig {
                private_key: a_priv,
                listen_port: 0,
                peers: vec![PeerSetup {
                    public_key: b_pub,
                    preshared_key: None,
                    endpoint: Some(format!("127.0.0.1:{b_port}").parse().unwrap()),
                    allowed_ips: vec!["10.0.0.0/24".parse().unwrap()],
                    keepalive: None,
                }],
                bind_interface: None,
            },
            Box::new(a_dev),
        )
        .unwrap();
        // Not routed to any peer on A's side: dropped before leaving.
        a_side
            .send(&ipv4_packet([10, 0, 1, 2], [192, 168, 9, 9], b"x"))
            .unwrap();
        // Routed, but its source is outside what B allows from A: dropped on arrival.
        a_side
            .send(&ipv4_packet([172, 16, 0, 1], [10, 0, 0, 5], b"y"))
            .unwrap();
        let mut buf = vec![0u8; 2048];
        assert!(b_side.recv(&mut buf).is_err(), "nothing may be delivered");
        a.stop();
        b.stop();
    }

    #[test]
    fn longest_prefix_picks_the_peer() {
        let (priv_key, _) = keypair(1);
        let (_, p1) = keypair(2);
        let (_, p2) = keypair(3);
        let (dev, _side) = pair();
        let private = StaticSecret::from(priv_key);
        let mk = |index: u32, public: [u8; 32], nets: &[&str]| PeerState {
            tunn: Tunn::new(
                private.clone(),
                PublicKey::from(public),
                None,
                None,
                index,
                None,
            )
            .unwrap(),
            public_key: public,
            endpoint: None,
            allowed: nets.iter().map(|n| n.parse().unwrap()).collect(),
        };
        let runner = Runner {
            device: Box::new(dev),
            udp4: None,
            udp6: None,
            public: PublicKey::from(&private),
            private: private.clone(),
            peers: vec![
                mk(0, p1, &["10.0.0.0/8"]),
                mk(1, p2, &["10.1.0.0/16", "fd00::/8"]),
            ],
            out: vec![0; MAX_PACKET + 32],
        };
        assert_eq!(runner.peer_for("10.1.2.3".parse().unwrap()), Some(1));
        assert_eq!(runner.peer_for("10.9.9.9".parse().unwrap()), Some(0));
        assert_eq!(runner.peer_for("fd00::1".parse().unwrap()), Some(1));
        assert_eq!(runner.peer_for("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn stopping_ends_the_thread_and_reports_not_alive() {
        let (a_priv, _) = keypair(5);
        let (_, b_pub) = keypair(6);
        let (dev, _side) = pair();
        let engine = Engine::start(
            EngineConfig {
                private_key: a_priv,
                listen_port: 0,
                peers: vec![PeerSetup {
                    public_key: b_pub,
                    preshared_key: None,
                    endpoint: None,
                    allowed_ips: vec![],
                    keepalive: None,
                }],
                bind_interface: None,
            },
            Box::new(dev),
        )
        .unwrap();
        assert!(engine.alive());
        let alive = engine.alive.clone();
        engine.stop();
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn utun_framing_prefixes_the_address_family() {
        let (a, b) = UnixDatagram::pair().unwrap();
        // A datagram socket pair behaves like the tun fd for framing purposes.
        let fd = unsafe { OwnedFd::from_raw_fd(libc::dup(a.as_raw_fd())) };
        let mut io = UtunIo::new(fd).unwrap();
        io.write_packet(&ipv4_packet([1, 1, 1, 1], [2, 2, 2, 2], b"z"))
            .unwrap();
        let mut got = vec![0u8; 128];
        let n = b.recv(&mut got).unwrap();
        assert_eq!(&got[..4], &[0, 0, 0, libc::AF_INET as u8]);
        assert_eq!(got[4] >> 4, 4);
        assert!(n > 4);
        // And the reverse direction strips it.
        let mut framed = vec![0, 0, 0, libc::AF_INET as u8];
        framed.extend_from_slice(&ipv4_packet([3, 3, 3, 3], [4, 4, 4, 4], b"q"));
        b.send(&framed).unwrap();
        std::thread::sleep(Duration::from_millis(50));
        let mut out = vec![0u8; 128];
        let read = io.read_packet(&mut out).unwrap();
        assert_eq!(read, framed.len() - 4);
        assert_eq!(out[0] >> 4, 4);
        assert!(io.write_packet(&[]).is_err());
    }
}
