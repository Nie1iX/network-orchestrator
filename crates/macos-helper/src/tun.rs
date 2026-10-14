//! utun device ownership: create, configure and close the tunnel interface.
//!
//! Only root can open a utun (the `com.apple.net.utun_control` system
//! socket). Xray consumes the resulting fd through `XRAY_TUN_FD` and treats
//! the device as fully configured (`ownsFd=false` in its source), so the
//! helper applies everything Xray's own Darwin path would: MTU, the
//! point-to-point address (Darwin routing requires it) and the link-local
//! v6 address.

use std::collections::BTreeSet;
use std::ffi::CStr;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd};

/// Point-to-point pair every Darwin tunnel needs to be routable. Mirrors
/// Xray's `defaultDarwinGateway` (proxy/tun/tun_darwin.go).
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(169, 254, 10, 1);
pub const LOCAL: Ipv4Addr = Ipv4Addr::new(169, 254, 10, 2);
pub const PREFIX_LEN: u8 = 30;
pub const DEFAULT_MTU: u32 = 1500;

/// `utunN` numbers are picked from N >= 10 — the same range Xray uses for its
/// own names, keeping the system/NetworkExtension tunnels (utun0..9) clear.
pub const MIN_UNIT: u32 = 10;
pub const MAX_UNIT: u32 = 1024;

const UTUN_CONTROL: &str = "com.apple.net.utun_control";
/// Protocol of the system-control socket; also the getsockopt level that
/// returns the interface name bound to the fd.
const SYS_PROTO_CONTROL: i32 = 2;
const UTUN_OPT_IFNAME: i32 = 2;
// XNU values (private ioctls, not in the public SDK); the request sizes are
// encoded in the values and match the structs below byte for byte.
const CTLIOCGINFO: libc::c_ulong = 0xc064_4e03;
const SIOCSIFMTU: libc::c_ulong = 0x8020_6934;
const SIOCAIFADDR: libc::c_ulong = 0x8040_691a;
const SIOCAIFADDR6: libc::c_ulong = 0x8080_691a;
const IN6_IFF_NODAD: u32 = 0x0020;
const ND6_INFINITE_LIFETIME: u32 = 0xffff_ffff;

/// The utun interface and the handles that keep it alive. Dropping closes
/// the fd and removes the interface.
#[derive(Debug)]
pub struct Utun {
    pub name: String,
    pub gateway: Ipv4Addr,
    pub local: Ipv4Addr,
    fd: OwnedFd,
}

impl Utun {
    /// The raw fd, for handing to Xray via `XRAY_TUN_FD` (dup'd; this device
    /// keeps its own copy).
    pub fn fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// Keeps the error kind and adds which step failed; the OS error text
/// carries no user data.
fn stage(step: &str, err: io::Error) -> io::Error {
    io::Error::new(err.kind(), format!("utun {step}: {err}"))
}

/// Smallest free unit number not in `used`.
pub fn pick_free_unit(used: &BTreeSet<u32>) -> Option<u32> {
    (MIN_UNIT..=MAX_UNIT).find(|n| !used.contains(n))
}

/// Numbers of the existing `utunN` interfaces, from the system interface
/// list.
pub fn used_units() -> io::Result<BTreeSet<u32>> {
    let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `head` is valid until freeifaddrs below.
    let mut used = BTreeSet::new();
    unsafe {
        let mut cur = head;
        while !cur.is_null() {
            let ifa = &*cur;
            let name = CStr::from_ptr(ifa.ifa_name).to_bytes();
            if let Some(rest) = name.strip_prefix(b"utun") {
                let num: &[_] = rest.split(|b| *b == b'.').next().unwrap_or(&[]);
                if let Some(unit) = std::str::from_utf8(num)
                    .ok()
                    .and_then(|s| s.parse::<u32>().ok())
                {
                    used.insert(unit);
                }
            }
            cur = ifa.ifa_next;
        }
        libc::freeifaddrs(head);
    }
    Ok(used)
}

/// Create `utunN` (smallest free N >= 10), set MTU and the point-to-point
/// address, and keep the interface alive for the lifetime of the returned
/// value.
pub fn open(mtu: u32) -> io::Result<Utun> {
    if !(512..=9000).contains(&mtu) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid TUN MTU",
        ));
    }
    let unit =
        pick_free_unit(&used_units()?).ok_or_else(|| io::Error::other("no free utun unit"))?;
    let fd = open_control_socket(unit).map_err(|err| stage("connect", err))?;
    let name = interface_name(&fd).unwrap_or_else(|_| format!("utun{unit}"));
    set_mtu(&name, mtu).map_err(|err| stage("set MTU", err))?;
    set_ipv4_pair(&name).map_err(|err| stage("set IPv4 address", err))?;
    set_ipv6_link_local(&name).map_err(|err| stage("set IPv6 address", err))?;
    // SAFETY: `fd` is owned by this process from the socket() above.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    Ok(Utun {
        name,
        gateway: GATEWAY,
        local: LOCAL,
        fd,
    })
}

/// Connect the `com.apple.net.utun_control` system socket at `unit`.
/// Control units are off by one from interface numbers: creating `utunN`
/// connects unit N+1.
fn open_control_socket(unit: u32) -> io::Result<libc::c_int> {
    // SAFETY: plain socket creation with fixed constants.
    let fd = unsafe { libc::socket(libc::AF_SYSTEM, libc::SOCK_DGRAM, SYS_PROTO_CONTROL) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // Keep the control socket out of any child; the launcher dup2()s it onto
    // the fixed fd Xray reads from.
    unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
    let mut info: libc::ctl_info = unsafe { std::mem::zeroed() };
    let name = UTUN_CONTROL.as_bytes();
    if name.len() > info.ctl_name.len() {
        unsafe { libc::close(fd) };
        return Err(io::Error::other("control name too long"));
    }
    for (slot, byte) in info.ctl_name.iter_mut().zip(name) {
        *slot = *byte as libc::c_char;
    }
    // SAFETY: `info` lives long enough for the ioctl.
    if unsafe {
        libc::ioctl(
            fd,
            CTLIOCGINFO,
            &mut info as *mut libc::ctl_info as *mut libc::c_void,
        )
    } < 0
    {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    let mut addr: libc::sockaddr_ctl = unsafe { std::mem::zeroed() };
    addr.sc_len = std::mem::size_of::<libc::sockaddr_ctl>() as u8;
    addr.sc_family = libc::AF_SYSTEM as u8;
    addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
    addr.sc_id = info.ctl_id;
    addr.sc_unit = unit + 1;
    // SAFETY: the address is valid for the call.
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_ctl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_ctl>() as u32,
        )
    };
    if rc < 0 {
        unsafe { libc::close(fd) };
        return Err(io::Error::last_os_error());
    }
    Ok(fd)
}

/// The kernel returns the name as a C string whose length includes the
/// terminator; everything from the first NUL on is not part of the name.
fn name_from_bytes(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// Interface name the kernel bound to the control fd.
fn interface_name(fd: &libc::c_int) -> io::Result<String> {
    let mut buf = [0u8; 64];
    let mut len = buf.len() as libc::socklen_t;
    // SAFETY: the buffer is valid for `len` bytes.
    let rc = unsafe {
        libc::getsockopt(
            *fd,
            SYS_PROTO_CONTROL,
            UTUN_OPT_IFNAME,
            buf.as_mut_ptr().cast(),
            &mut len,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(name_from_bytes(&buf[..(len as usize).min(buf.len())]))
}

#[repr(C)]
struct IfreqMtu {
    name: [u8; 16],
    mtu: i32,
    // The ioctl encodes sizeof(struct ifreq) = 32; the kernel copies that
    // many bytes, so the request must really be that long.
    _pad: [u8; 12],
}

fn set_mtu(name: &str, mtu: u32) -> io::Result<()> {
    let ifr = IfreqMtu {
        name: copy_name(name),
        mtu: mtu as i32,
        _pad: [0; 12],
    };
    // SAFETY: plain socket for a scoped ioctl.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the ifreq is valid for the ioctl.
    let rc = unsafe {
        libc::ioctl(
            socket,
            SIOCSIFMTU,
            &ifr as *const IfreqMtu as *const libc::c_void,
        )
    };
    unsafe { libc::close(socket) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Embedded-socket layout; the request size in the ioctl (64/128 bytes)
/// matches these structs exactly.
#[repr(C)]
struct Ifaliasreq4 {
    name: [u8; 16],
    addr: libc::sockaddr_in,
    dstaddr: libc::sockaddr_in,
    mask: libc::sockaddr_in,
}

#[repr(C)]
struct AddrLifetime6 {
    expire: i64,
    preferred: i64,
    vltime: u32,
    pltime: u32,
}

#[repr(C)]
struct Ifaliasreq6 {
    name: [u8; 16],
    addr: libc::sockaddr_in6,
    dstaddr: libc::sockaddr_in6,
    mask: libc::sockaddr_in6,
    flags: u32,
    lifetime: AddrLifetime6,
}

fn copy_name(name: &str) -> [u8; 16] {
    let mut out = [0u8; 16];
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    out[..len].copy_from_slice(&bytes[..len]);
    out
}

fn ipv4_sockaddr(addr: Ipv4Addr) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    sa.sin_family = libc::AF_INET as u8;
    sa.sin_addr.s_addr = u32::from(addr).to_be();
    sa
}

fn ipv4_mask(bits: u8) -> libc::sockaddr_in {
    let mut sa: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    sa.sin_len = std::mem::size_of::<libc::sockaddr_in>() as u8;
    sa.sin_family = libc::AF_INET as u8;
    sa.sin_addr.s_addr = if bits == 0 {
        0
    } else {
        0xffff_ffff_u32 << (32 - bits)
    }
    .to_be();
    sa
}

fn set_ipv4_pair(name: &str) -> io::Result<()> {
    let req = Ifaliasreq4 {
        name: copy_name(name),
        addr: ipv4_sockaddr(LOCAL),
        dstaddr: ipv4_sockaddr(GATEWAY),
        mask: ipv4_mask(PREFIX_LEN),
    };
    // SAFETY: plain socket for a scoped ioctl.
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the request is valid for the ioctl.
    let rc = unsafe {
        libc::ioctl(
            socket,
            SIOCAIFADDR,
            &req as *const Ifaliasreq4 as *const libc::c_void,
        )
    };
    unsafe { libc::close(socket) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn ipv6_sockaddr(addr: Ipv6Addr) -> libc::sockaddr_in6 {
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    sa.sin6_family = libc::AF_INET6 as u8;
    sa.sin6_addr = libc::in6_addr {
        s6_addr: addr.octets(),
    };
    sa
}

fn ipv6_mask(bits: u8) -> libc::sockaddr_in6 {
    let mut octets = [0u8; 16];
    for (i, octet) in octets.iter_mut().enumerate() {
        let remaining = (bits as usize).saturating_sub(i * 8);
        *octet = if remaining >= 8 {
            0xff
        } else if remaining > 0 {
            0xff_u8 << (8 - remaining)
        } else {
            0
        };
    }
    let mut sa: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    sa.sin6_len = std::mem::size_of::<libc::sockaddr_in6>() as u8;
    sa.sin6_family = libc::AF_INET6 as u8;
    sa.sin6_addr = libc::in6_addr { s6_addr: octets };
    sa
}

/// Link-local derived from the v4 local address, the way Xray does it
/// (all four v4 octets at the tail of the fe80::/10 address).
fn ipv6_link_local() -> Ipv6Addr {
    let local4 = LOCAL.octets();
    Ipv6Addr::new(
        0xfe80,
        0,
        0,
        0,
        0,
        0,
        u16::from_be_bytes([local4[0], local4[1]]),
        u16::from_be_bytes([local4[2], local4[3]]),
    )
}

/// The link-local address is what makes IPv6 routable through the tunnel
/// (utun gets none of its own). The ioctl is tried first; if the kernel
/// rejects the request, the system `ifconfig` — the reference user of the
/// same interface — does the job. Failing both is an error: leaving IPv6
/// uncovered would leak it around the tunnel.
fn set_ipv6_link_local(name: &str) -> io::Result<()> {
    set_ipv6_link_local_ioctl(name).or_else(|ioctl_err| {
        run_ifconfig(&ifconfig_ipv6_args(name)).map_err(|cmd_err| {
            io::Error::new(
                ioctl_err.kind(),
                format!("{ioctl_err}; ifconfig fallback: {cmd_err}"),
            )
        })
    })
}

fn ifconfig_ipv6_args(name: &str) -> Vec<String> {
    vec![
        name.to_string(),
        "inet6".into(),
        ipv6_link_local().to_string(),
        "prefixlen".into(),
        "64".into(),
    ]
}

fn run_ifconfig(args: &[String]) -> io::Result<()> {
    let output = std::process::Command::new("/sbin/ifconfig")
        .args(args)
        .stdin(std::process::Stdio::null())
        .output()?;
    if output.status.success() {
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        Err(io::Error::other(stderr.trim().to_string()))
    }
}

fn set_ipv6_link_local_ioctl(name: &str) -> io::Result<()> {
    // `ifconfig` leaves the destination empty; on a point-to-point utun a
    // filled-in `::` makes the kernel validate it as a peer address.
    // SAFETY: an all-zero sockaddr_in6 is the "no address" value.
    let dstaddr: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
    let req = Ifaliasreq6 {
        name: copy_name(name),
        addr: ipv6_sockaddr(ipv6_link_local()),
        dstaddr,
        mask: ipv6_mask(64),
        flags: IN6_IFF_NODAD,
        lifetime: AddrLifetime6 {
            expire: 0,
            preferred: 0,
            vltime: ND6_INFINITE_LIFETIME,
            pltime: ND6_INFINITE_LIFETIME,
        },
    };
    // SAFETY: plain socket for a scoped ioctl.
    let socket = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if socket < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the request is valid for the ioctl.
    let rc = unsafe {
        libc::ioctl(
            socket,
            SIOCAIFADDR6,
            &req as *const Ifaliasreq6 as *const libc::c_void,
        )
    };
    unsafe { libc::close(socket) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pick_free_unit_skips_used_and_keeps_range() {
        let mut used = BTreeSet::new();
        used.insert(10);
        used.insert(11);
        assert_eq!(pick_free_unit(&used), Some(12));
        let full: BTreeSet<u32> = (MIN_UNIT..=MAX_UNIT).collect();
        assert_eq!(pick_free_unit(&full), None);
        assert_eq!(pick_free_unit(&BTreeSet::new()), Some(MIN_UNIT));
    }

    #[test]
    fn used_units_reads_interface_list_without_panic() {
        // getifaddrs is unprivileged; on a dev machine this returns whatever
        // utuns exist (possibly none).
        assert!(used_units().is_ok());
    }

    #[test]
    fn open_without_privileges_refuses() {
        if unsafe { libc::getuid() } == 0 {
            eprintln!("skipping: running as root, utun creation would succeed");
            return;
        }
        // Opening the utun control socket needs root; expect a clean error,
        // not a panic, for the unprivileged case.
        let err = open(DEFAULT_MTU).unwrap_err();
        // EPERM specifically: a malformed control address would fail with
        // EINVAL before the privilege check is reached.
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied, "{err}");
    }

    #[test]
    fn open_rejects_bad_mtu_before_any_syscall() {
        assert_eq!(open(100).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(open(99999).unwrap_err().kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn ipv4_sockaddr_builds_addresses_and_masks() {
        let addr = ipv4_sockaddr(Ipv4Addr::new(169, 254, 10, 2));
        assert_eq!(addr.sin_addr.s_addr.to_ne_bytes(), [169, 254, 10, 2]);
        assert_eq!(addr.sin_family, libc::AF_INET as u8);
        let mask = ipv4_mask(30);
        assert_eq!(mask.sin_addr.s_addr.to_ne_bytes(), [255, 255, 255, 252]);
        let mask0 = ipv4_mask(0);
        assert_eq!(mask0.sin_addr.s_addr, 0);
    }

    #[test]
    fn ipv6_mask_builds_cidr_masks() {
        let mask = ipv6_mask(64);
        assert_eq!(
            mask.sin6_addr.s6_addr,
            [255, 255, 255, 255, 255, 255, 255, 255, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        let mask0 = ipv6_mask(0);
        assert!(mask0.sin6_addr.s6_addr.iter().all(|b| *b == 0));
        let mask92 = ipv6_mask(92);
        assert_eq!(mask92.sin6_addr.s6_addr[10], 0xff);
        assert_eq!(mask92.sin6_addr.s6_addr[11], 0xf0);
        assert_eq!(mask92.sin6_addr.s6_addr[12], 0);
    }

    #[test]
    fn ipv6_link_local_matches_xray_derivation() {
        // Xray: fe80:: with the four v4 octets (169.254.10.2) at the tail.
        assert_eq!(ipv6_link_local().to_string(), "fe80::a9fe:a02");
    }

    #[test]
    fn interface_name_drops_the_c_string_terminator() {
        assert_eq!(name_from_bytes(b"utun10\0"), "utun10");
        assert_eq!(name_from_bytes(b"utun10\0\0\0"), "utun10");
        assert_eq!(name_from_bytes(b"utun10"), "utun10");
        assert!(!name_from_bytes(b"utun10\0").contains('\0'));
    }

    #[test]
    fn ifconfig_fallback_uses_the_same_link_local_address() {
        assert_eq!(
            ifconfig_ipv6_args("utun10"),
            ["utun10", "inet6", "fe80::a9fe:a02", "prefixlen", "64"]
        );
    }

    #[test]
    fn alias_request_sizes_match_the_ioctl_encodings() {
        // The request sizes are encoded in the ioctl values: 0x40 = 64,
        // 0x80 = 128. A layout drift here breaks the ioctl at runtime.
        assert_eq!(std::mem::size_of::<Ifaliasreq4>(), 0x40);
        assert_eq!(std::mem::size_of::<Ifaliasreq6>(), 0x80);
        // SIOCSIFMTU: sizeof(struct ifreq) = 32.
        assert_eq!(std::mem::size_of::<IfreqMtu>(), 0x20);
    }
}
