use std::{
    collections::BTreeMap,
    io::{self, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    time::{Duration, Instant},
};

const TIMEOUT: Duration = Duration::from_secs(3);
const MAX_RESPONSE: usize = 64 * 1024;

pub fn apply_group_selections(
    socket: &Path,
    selections: &BTreeMap<String, String>,
) -> io::Result<()> {
    let deadline = Instant::now() + TIMEOUT;
    for (group, member) in selections {
        let path = format!("/proxies/{}", encode_path_segment(group));
        let body = serde_json::to_vec(&serde_json::json!({"name": member}))
            .map_err(|_| request_error())?;
        request(socket, "PUT", &path, &body, deadline)?;
        let response = request(socket, "GET", &path, &[], deadline)?;
        let value: serde_json::Value = serde_json::from_slice(&response)
            .map_err(|_| io::Error::other("Mihomo controller verification failed"))?;
        if value.get("now").and_then(serde_json::Value::as_str) != Some(member.as_str()) {
            return Err(io::Error::other("Mihomo controller verification failed"));
        }
    }
    Ok(())
}

fn encode_path_segment(segment: &str) -> String {
    let mut encoded = String::with_capacity(segment.len());
    for byte in segment.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(byte as char);
        } else {
            use std::fmt::Write as _;
            write!(encoded, "%{byte:02X}").unwrap();
        }
    }
    encoded
}

fn request(
    socket: &Path,
    method: &str,
    path: &str,
    body: &[u8],
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut stream = UnixStream::connect(socket).map_err(|_| request_error())?;
    let timeout = deadline.saturating_duration_since(Instant::now());
    if timeout.is_zero() {
        return Err(timeout_error());
    }
    stream
        .set_read_timeout(Some(timeout))
        .map_err(|_| request_error())?;
    stream
        .set_write_timeout(Some(timeout))
        .map_err(|_| request_error())?;
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .and_then(|_| stream.write_all(body))
    .map_err(|_| request_error())?;
    let mut response = Vec::new();
    let mut buffer = [0; 4096];
    loop {
        let timeout = deadline.saturating_duration_since(Instant::now());
        if timeout.is_zero() {
            return Err(timeout_error());
        }
        stream
            .set_read_timeout(Some(timeout))
            .map_err(|_| request_error())?;
        let count = stream.read(&mut buffer).map_err(|_| request_error())?;
        if count == 0 {
            break;
        }
        if response.len().saturating_add(count) > MAX_RESPONSE {
            return Err(invalid_response());
        }
        response.extend_from_slice(&buffer[..count]);
    }
    decode_response(&response)
}

fn decode_response(response: &[u8]) -> io::Result<Vec<u8>> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(invalid_response)?;
    let headers = std::str::from_utf8(&response[..header_end]).map_err(|_| invalid_response())?;
    let mut lines = headers.lines();
    let status = lines.next().ok_or_else(invalid_response)?;
    let code = status
        .split_ascii_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(invalid_response)?;
    if !(200..300).contains(&code) {
        return Err(request_error());
    }
    let mut content_length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(invalid_response)?;
        if name.eq_ignore_ascii_case("content-length") {
            let length = value
                .trim()
                .parse::<usize>()
                .map_err(|_| invalid_response())?;
            if content_length.replace(length).is_some() {
                return Err(invalid_response());
            }
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if !value.trim().eq_ignore_ascii_case("chunked") || chunked {
                return Err(invalid_response());
            }
            chunked = true;
        }
    }
    if chunked && content_length.is_some() {
        return Err(invalid_response());
    }
    let payload = &response[header_end + 4..];
    if code == 204 {
        return if payload.is_empty() && !chunked && content_length.is_none_or(|length| length == 0)
        {
            Ok(Vec::new())
        } else {
            Err(invalid_response())
        };
    }
    if chunked {
        decode_chunked(payload)
    } else if let Some(length) = content_length {
        if length > MAX_RESPONSE || payload.len() != length {
            Err(invalid_response())
        } else {
            Ok(payload.to_vec())
        }
    } else {
        Ok(payload.to_vec())
    }
}

fn decode_chunked(mut payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    loop {
        let line_end = payload
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or_else(invalid_response)?;
        let size = std::str::from_utf8(&payload[..line_end])
            .ok()
            .and_then(|line| usize::from_str_radix(line.split(';').next()?, 16).ok())
            .ok_or_else(invalid_response)?;
        payload = &payload[line_end + 2..];
        if size == 0 {
            if payload == b"\r\n" {
                return Ok(decoded);
            }
            let trailer_end = payload
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .ok_or_else(invalid_response)?;
            if payload.len() != trailer_end + 4 {
                return Err(invalid_response());
            }
            return Ok(decoded);
        }
        if decoded.len().saturating_add(size) > MAX_RESPONSE
            || payload.len() < size + 2
            || &payload[size..size + 2] != b"\r\n"
        {
            return Err(invalid_response());
        }
        decoded.extend_from_slice(&payload[..size]);
        payload = &payload[size + 2..];
    }
}

fn request_error() -> io::Error {
    io::Error::other("Mihomo controller request failed")
}
fn invalid_response() -> io::Error {
    io::Error::other("Mihomo controller response invalid")
}
fn timeout_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "Mihomo controller deadline exceeded",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{io::BufRead, os::unix::net::UnixListener, thread};

    #[test]
    fn independent_selections_encode_group_segments_and_verify_chunked_responses() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("controller.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = thread::spawn(move || {
            let expected = [
                ("/proxies/Asia", "Beta"),
                ("/proxies/Europe%20%F0%9F%8C%8D%2FWest", "Alpha"),
            ];
            for (path, member) in expected {
                for method in ["PUT", "GET"] {
                    let (mut stream, _) = listener.accept().unwrap();
                    let mut reader = io::BufReader::new(stream.try_clone().unwrap());
                    let mut request = String::new();
                    reader.read_line(&mut request).unwrap();
                    assert_eq!(request.split_ascii_whitespace().next(), Some(method));
                    assert_eq!(request.split_ascii_whitespace().nth(1), Some(path));
                    let mut line = String::new();
                    let mut length = 0;
                    loop {
                        line.clear();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" {
                            break;
                        }
                        if let Some(value) = line.strip_prefix("Content-Length: ") {
                            length = value.trim().parse().unwrap();
                        }
                    }
                    let mut body = vec![0; length];
                    reader.read_exact(&mut body).unwrap();
                    if method == "PUT" {
                        assert_eq!(
                            serde_json::from_slice::<serde_json::Value>(&body).unwrap()["name"],
                            member
                        );
                        stream
                            .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                            .unwrap();
                    } else {
                        let payload = serde_json::json!({"now": member}).to_string();
                        write!(stream, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n{}\r\n0\r\n\r\n", payload.len(), payload).unwrap();
                    }
                    drop(stream);
                }
            }
        });
        let selections = BTreeMap::from([
            ("Asia".to_owned(), "Beta".to_owned()),
            ("Europe 🌍/West".to_owned(), "Alpha".to_owned()),
        ]);
        apply_group_selections(&socket, &selections).unwrap();
        server.join().unwrap();
    }

    #[test]
    fn response_framing_rejects_truncated_and_ambiguous_bodies() {
        assert!(decode_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}").is_ok());
        assert!(decode_response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{").is_err());
        assert!(decode_response(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"
        )
        .is_err());
        assert!(decode_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n"
        )
        .is_ok());
        assert!(decode_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nx"
        )
        .is_err());
        assert!(decode_response(b"HTTP/1.1 200 OK\r\n\r\n{}").is_ok());
    }
}
