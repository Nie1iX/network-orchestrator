use base64::Engine as _;
use serde_json::Value;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::process::Child;
use std::thread;
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const RESPONSE_LIMIT: usize = 8192;
const REQUEST_LIMIT: usize = 4096;

pub struct StartupProbe {
    origin: Option<TcpListener>,
    origin_port: u16,
    proxy_reservation: Option<TcpListener>,
    proxy_port: u16,
    auth: Option<String>,
}

impl StartupProbe {
    pub fn prepare(config: &mut Value) -> io::Result<Self> {
        let origin = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        origin.set_nonblocking(true)?;
        let origin_port = origin.local_addr()?.port();
        let root = config
            .as_object_mut()
            .ok_or_else(|| invalid("Mihomo configuration must be an object"))?;
        root.insert("bind-address".into(), Value::String("127.0.0.1".into()));
        let (proxy_port, proxy_reservation, auth) = match root.get("mixed-port") {
            Some(value) => {
                let port = value
                    .as_u64()
                    .filter(|p| *p > 0 && *p <= u16::MAX as u64)
                    .ok_or_else(|| invalid("Mihomo mixed-port is invalid"))?
                    as u16;
                let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, port))?;
                (port, Some(reservation), None)
            }
            None => {
                let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
                let port = reservation.local_addr()?.port();
                let mut random = [0u8; 32];
                File::open("/dev/urandom")?.read_exact(&mut random)?;
                let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
                let credentials = format!("startup-{token}:{token}");
                root.insert("skip-auth-prefixes".into(), serde_json::json!([]));
                root.insert(
                    "lan-allowed-ips".into(),
                    serde_json::json!(["127.0.0.1/32"]),
                );
                root.insert("lan-disallowed-ips".into(), serde_json::json!([]));
                root.insert("mixed-port".into(), Value::from(port));
                match root.entry("authentication") {
                    serde_json::map::Entry::Vacant(entry) => {
                        entry.insert(Value::Array(vec![Value::String(credentials.clone())]));
                    }
                    serde_json::map::Entry::Occupied(mut entry) => {
                        entry
                            .get_mut()
                            .as_array_mut()
                            .ok_or_else(|| invalid("Mihomo authentication must be an array"))?
                            .push(Value::String(credentials.clone()));
                    }
                }
                let header = format!(
                    "Basic {}",
                    base64::engine::general_purpose::STANDARD.encode(credentials)
                );
                (port, Some(reservation), Some(header))
            }
        };
        let rule =
            format!("AND,((IP-CIDR,127.0.0.1/32,no-resolve),(DST-PORT,{origin_port})),DIRECT");
        let rules = root
            .entry("rules")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .ok_or_else(|| invalid("Mihomo rules must be an array"))?;
        rules.insert(0, Value::String(rule));
        Ok(Self {
            origin: Some(origin),
            origin_port,
            proxy_reservation,
            proxy_port,
            auth,
        })
    }

    pub fn release_proxy_reservation(&mut self) {
        self.proxy_reservation.take();
    }

    pub fn wait(&mut self, child: &mut Child) -> io::Result<()> {
        let result = self.wait_inner(child);
        self.proxy_reservation.take();
        if result.is_err() {
            self.origin.take();
        }
        result
    }

    fn wait_inner(&mut self, child: &mut Child) -> io::Result<()> {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        let mut random = [0u8; 24];
        File::open("/dev/urandom")?.read_exact(&mut random)?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(random);
        let nonce_matcher = format!("nonce={nonce}");
        let auth = self
            .auth
            .as_ref()
            .map(|v| format!("Proxy-Authorization: {v}\r\n"))
            .unwrap_or_default();
        let request = format!("GET http://127.0.0.1:{}/probe?nonce={} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\n{}Connection: close\r\n\r\n", self.origin_port, nonce, self.origin_port, auth);
        loop {
            if child.try_wait()?.is_some() {
                return Err(unavailable("Mihomo exited before data-plane readiness"));
            }
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "Mihomo data plane did not become ready within 30 seconds",
                ));
            }
            if self.probe_once(&request, &nonce_matcher, &nonce, deadline) {
                return Ok(());
            }
            thread::sleep(remaining_timeout(deadline, Duration::from_millis(50)));
        }
    }

    fn probe_once(
        &mut self,
        request: &str,
        nonce_matcher: &str,
        nonce: &str,
        deadline: Instant,
    ) -> bool {
        let timeout = remaining_timeout(deadline, IO_TIMEOUT);
        if timeout.is_zero() {
            return false;
        }
        let address = SocketAddr::from((Ipv4Addr::LOCALHOST, self.proxy_port));
        let Ok(mut proxy) = TcpStream::connect_timeout(&address, timeout) else {
            return false;
        };
        let timeout = remaining_timeout(deadline, IO_TIMEOUT);
        if timeout.is_zero()
            || proxy.set_write_timeout(Some(timeout)).is_err()
            || proxy.write_all(request.as_bytes()).is_err()
        {
            return false;
        }

        let origin_deadline = deadline.min(Instant::now() + IO_TIMEOUT);
        let mut forwarded = false;
        while Instant::now() < origin_deadline {
            let Some(listener) = self.origin.as_ref() else {
                return false;
            };
            match listener.accept() {
                Ok((mut origin, _)) => {
                    let timeout = remaining_timeout(origin_deadline, IO_TIMEOUT);
                    if timeout.is_zero() || origin.set_read_timeout(Some(timeout)).is_err() {
                        return false;
                    }
                    let mut request = [0u8; REQUEST_LIMIT];
                    let mut used = 0;
                    while used < request.len()
                        && !request[..used].windows(4).any(|w| w == b"\r\n\r\n")
                    {
                        let timeout = remaining_timeout(origin_deadline, IO_TIMEOUT);
                        if timeout.is_zero() || origin.set_read_timeout(Some(timeout)).is_err() {
                            return false;
                        }
                        match origin.read(&mut request[used..]) {
                            Ok(0) => return false,
                            Ok(count) => used += count,
                            Err(_) => return false,
                        }
                    }
                    if !request[..used]
                        .windows(4)
                        .any(|window| window == b"\r\n\r\n")
                        || !request[..used]
                            .windows(nonce_matcher.len())
                            .any(|part| part == nonce_matcher.as_bytes())
                    {
                        return false;
                    }
                    let body = nonce.as_bytes();
                    let timeout = remaining_timeout(origin_deadline, IO_TIMEOUT);
                    if timeout.is_zero() || origin.set_write_timeout(Some(timeout)).is_err() {
                        return false;
                    }
                    if write!(
                        origin,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        body.len()
                    )
                    .is_err()
                        || origin.write_all(body).is_err()
                    {
                        return false;
                    }
                    if origin.shutdown(std::net::Shutdown::Write).is_err() {
                        return false;
                    }
                    forwarded = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(
                    remaining_timeout(origin_deadline, Duration::from_millis(10)),
                ),
                Err(_) => return false,
            }
        }
        forwarded && read_response(&mut proxy, nonce, deadline)
    }
}

fn read_response(stream: &mut TcpStream, nonce: &str, deadline: Instant) -> bool {
    let mut bytes = [0u8; RESPONSE_LIMIT];
    let mut used = 0;
    let header_end = loop {
        if let Some(index) = bytes[..used]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
        {
            break index + 4;
        }
        if used == bytes.len() {
            return false;
        }
        let timeout = remaining_timeout(deadline, IO_TIMEOUT);
        if timeout.is_zero() || stream.set_read_timeout(Some(timeout)).is_err() {
            return false;
        }
        match stream.read(&mut bytes[used..]) {
            Ok(0) | Err(_) => return false,
            Ok(count) => used += count,
        }
    };
    let Ok(headers) = std::str::from_utf8(&bytes[..header_end]) else {
        return false;
    };
    let Some(status) = headers.lines().next() else {
        return false;
    };
    if status != "HTTP/1.1 200 OK" && status != "HTTP/1.0 200 OK" {
        return false;
    }
    let Some(length) = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    }) else {
        return false;
    };
    if length != nonce.len() {
        return false;
    }
    while used - header_end < length {
        let timeout = remaining_timeout(deadline, IO_TIMEOUT);
        if timeout.is_zero() || stream.set_read_timeout(Some(timeout)).is_err() {
            return false;
        }
        match stream.read(&mut bytes[used..]) {
            Ok(0) | Err(_) => return false,
            Ok(count) => used += count,
        }
    }
    used - header_end == length && &bytes[header_end..used] == nonce.as_bytes()
}

fn remaining_timeout(deadline: Instant, cap: Duration) -> Duration {
    deadline.saturating_duration_since(Instant::now()).min(cap)
}
fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn unavailable(message: &str) -> io::Error {
    io::Error::other(message.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn startup_requires_forwarded_origin_response() {
        let mut config = serde_json::json!({"rules":["MATCH,Proxy"]});
        let mut probe = StartupProbe::prepare(&mut config).unwrap();
        assert_eq!(config["rules"][1], "MATCH,Proxy");
        let mut child = Command::new("sleep").arg("30").spawn().unwrap();
        probe.release_proxy_reservation();
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, probe.proxy_port)).unwrap();
        let origin_port = probe.origin_port;
        let server = thread::spawn(move || {
            for attempt in 0..2 {
                let (mut stream, _) = proxy.accept().unwrap();
                let mut request = [0; 1024];
                let n = stream.read(&mut request).unwrap();
                if attempt == 0 {
                    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\ncontroller").unwrap();
                    continue;
                }
                let request = String::from_utf8_lossy(&request[..n]);
                let target = request
                    .lines()
                    .next()
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap();
                let mut origin = TcpStream::connect((Ipv4Addr::LOCALHOST, origin_port)).unwrap();
                write!(origin, "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", target).unwrap();
                origin.shutdown(std::net::Shutdown::Write).unwrap();
                let mut response = Vec::new();
                origin.read_to_end(&mut response).unwrap();
                stream.write_all(&response).unwrap();
            }
        });
        probe.wait(&mut child).unwrap();
        server.join().unwrap();
        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn child_exit_fails_and_releases_origin_listener() {
        let mut config = serde_json::json!({});
        let mut probe = StartupProbe::prepare(&mut config).unwrap();
        let port = probe.origin_port;
        let mut child = Command::new("sh").arg("-c").arg("exit 7").spawn().unwrap();
        let error = probe.wait(&mut child).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Other);
        child.wait().unwrap();
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }

    #[test]
    fn existing_mixed_port_remains_reserved_until_released() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut config = serde_json::json!({"mixed-port": port});
        let mut probe = StartupProbe::prepare(&mut config).unwrap();
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_err());
        probe.release_proxy_reservation();
        assert!(TcpListener::bind((Ipv4Addr::LOCALHOST, port)).is_ok());
    }
}
