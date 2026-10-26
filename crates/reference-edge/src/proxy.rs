//! The link to the service behind the edge: one request, one answer, and the relay.
//!
//! The edge opens one connection to the service for each request, and it asks the
//! service to close it (`Connection: close`). The edge relays the answer to the
//! client as the service frames it. A body with a length goes through with the same
//! length. A chunked body goes through chunk by chunk. The edge sends each chunk
//! at once, so that a stream of events (MCP over SSE) is not held back. A body that
//! ends with the connection also ends the connection to the client.
//!
//! The edge removes the headers that are valid for one hop only (RFC 9110, 7.6.1).

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::Duration;

use procurauth_pep::reply::HttpReply;

use crate::http::{Connection, reason};

/// The largest head of an answer of the service.
const MAX_HEAD_BYTES: usize = 64 * 1024;
/// The longest line of a chunk header in a chunked answer.
const MAX_CHUNK_LINE: usize = 1024;
/// The headers that are for one hop. The edge never copies them.
const HOP_BY_HOP: [&str; 9] = [
    "connection",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "content-length",
];

/// The service behind the edge.
#[derive(Clone, Debug)]
pub struct Upstream {
    /// The host name or the IP address.
    pub host: String,
    /// The port.
    pub port: u16,
    /// The longest time to open the connection.
    pub connect_timeout: Duration,
    /// The longest wait for a byte of the answer.
    pub response_timeout: Duration,
}

/// The request that the edge sends to the service.
#[derive(Clone, Debug)]
pub struct Forward {
    /// The method.
    pub method: String,
    /// The target: the path and the query, as the client sent them.
    pub target: String,
    /// The headers, after the edge changed them (protocol 9.1).
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
}

/// How a forward ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Relayed {
    /// The answer went to the client. The status is for the log.
    Done {
        /// The status of the answer of the service.
        status: u16,
        /// True when the connection of the client can stay open.
        reusable: bool,
    },
    /// The service gave no answer, and nothing went to the client. The caller sends this reply.
    NoAnswer(u16),
    /// The answer broke after it started. The connection of the client must close.
    Broken,
}

/// The headers that the edge copies from the client to the service. It drops five groups.
/// These are the headers of one hop, `Host` (the edge writes it), `Expect`, the header
/// of the token, and `Authorization`. The last one holds the text of the key (protocol 9.1).
pub fn request_headers(
    client: &[(String, String)],
    token_header: &str,
    token: &str,
) -> Vec<(String, String)> {
    let named_by_connection: Vec<String> = client
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case("connection"))
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .filter(|t| !t.is_empty())
        .collect();
    let mut out: Vec<(String, String)> = client
        .iter()
        .filter(|(n, _)| {
            let lower = n.to_ascii_lowercase();
            !HOP_BY_HOP.contains(&lower.as_str())
                && !named_by_connection.contains(&lower)
                && lower != "authorization"
                && lower != "expect"
                && lower != "host"
                && !lower.eq_ignore_ascii_case(token_header)
        })
        .cloned()
        .collect();
    // The edge sets the header of the token. A copy that the client sent is gone (protocol 9.1).
    out.push((token_header.to_owned(), token.to_owned()));
    out
}

/// A reader with a buffer, for the answer of the service.
struct Source {
    stream: TcpStream,
    buf: Vec<u8>,
    timeout: Duration,
}

impl Source {
    fn fill(&mut self) -> io::Result<usize> {
        let _ = self.stream.set_read_timeout(Some(self.timeout));
        let mut chunk = [0_u8; 16 * 1024];
        loop {
            match self.stream.read(&mut chunk) {
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }

    /// Take up to `max` bytes. It reads from the service when the buffer is empty. It returns
    /// an empty list at the end of the connection.
    fn take(&mut self, max: usize) -> io::Result<Vec<u8>> {
        if self.buf.is_empty() && self.fill()? == 0 {
            return Ok(Vec::new());
        }
        let n = max.min(self.buf.len());
        Ok(self.buf.drain(..n).collect())
    }

    fn line(&mut self) -> io::Result<String> {
        loop {
            if let Some(end) = self.buf.windows(2).position(|w| w == b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..end + 2).take(end).collect();
                return String::from_utf8(line)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "line"));
            }
            if self.buf.len() > MAX_CHUNK_LINE.max(MAX_HEAD_BYTES) {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
            }
            if self.fill()? == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
        }
    }
}

struct AnswerHead {
    status: u16,
    reason: String,
    headers: Vec<(String, String)>,
}

fn parse_answer_head(raw: &[u8]) -> Option<AnswerHead> {
    let text = std::str::from_utf8(raw).ok()?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    if !(100..=599).contains(&status) {
        return None;
    }
    let reason = parts.next().unwrap_or("").to_owned();
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line.split_once(':')?;
        if !crate::http::is_token(name) {
            return None;
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    Some(AnswerHead {
        status,
        reason,
        headers,
    })
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

impl Upstream {
    fn connect(&self) -> Result<TcpStream, u16> {
        let addresses: Vec<SocketAddr> = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|_| 502_u16)?
            .collect();
        let mut timed_out = false;
        for address in addresses {
            match TcpStream::connect_timeout(&address, self.connect_timeout) {
                Ok(stream) => return Ok(stream),
                Err(e) => timed_out |= e.kind() == io::ErrorKind::TimedOut,
            }
        }
        Err(if timed_out { 504 } else { 502 })
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    /// Send the request to the service, and relay the answer to the client.
    pub fn forward(&self, request: &Forward, client: &mut Connection, keep_alive: bool) -> Relayed {
        let mut stream = match self.connect() {
            Ok(stream) => stream,
            Err(status) => return Relayed::NoAnswer(status),
        };
        let _ = stream.set_nodelay(true);
        let mut head = format!("{} {} HTTP/1.1\r\n", request.method, request.target);
        head.push_str(&format!("Host: {}\r\n", self.host_header()));
        for (name, value) in &request.headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if !request.body.is_empty() || !matches!(request.method.as_str(), "GET" | "HEAD" | "DELETE")
        {
            head.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
        }
        head.push_str("Connection: close\r\n\r\n");
        let _ = stream.set_write_timeout(Some(self.response_timeout));
        if stream.write_all(head.as_bytes()).is_err()
            || stream.write_all(&request.body).is_err()
            || stream.flush().is_err()
        {
            return Relayed::NoAnswer(502);
        }
        let mut source = Source {
            stream,
            buf: Vec::new(),
            timeout: self.response_timeout,
        };
        let answer = loop {
            let end = loop {
                if let Some(end) = source.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                    break end;
                }
                if source.buf.len() > MAX_HEAD_BYTES {
                    return Relayed::NoAnswer(502);
                }
                match source.fill() {
                    Ok(0) => return Relayed::NoAnswer(502),
                    Ok(_) => {}
                    Err(e) => {
                        return Relayed::NoAnswer(
                            if matches!(
                                e.kind(),
                                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                            ) {
                                504
                            } else {
                                502
                            },
                        );
                    }
                }
            };
            let raw: Vec<u8> = source.buf.drain(..end + 4).take(end).collect();
            let Some(answer) = parse_answer_head(&raw) else {
                return Relayed::NoAnswer(502);
            };
            // An interim answer (1xx) is for the edge. The client gets the final answer only.
            if answer.status >= 200 {
                break answer;
            }
        };
        relay(answer, &request.method, &mut source, client, keep_alive)
    }
}

/// How the edge sends the body of an answer.
enum BodyKind {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

fn relay(
    answer: AnswerHead,
    method: &str,
    source: &mut Source,
    client: &mut Connection,
    keep_alive: bool,
) -> Relayed {
    let status = answer.status;
    let kind = if method == "HEAD" || status == 204 || status == 304 {
        BodyKind::None
    } else if header(&answer.headers, "transfer-encoding")
        .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
    {
        BodyKind::Chunked
    } else if let Some(length) = header(&answer.headers, "content-length") {
        match length.parse::<u64>() {
            Ok(n) => BodyKind::Length(n),
            Err(_) => return Relayed::NoAnswer(502),
        }
    } else {
        BodyKind::UntilClose
    };
    let reusable = keep_alive && !matches!(kind, BodyKind::UntilClose);
    let mut out = format!(
        "HTTP/1.1 {status} {}\r\n",
        if answer.reason.is_empty() || answer.reason.bytes().any(|b| b < 0x20 || b == 0x7f) {
            reason(status).to_owned()
        } else {
            answer.reason.clone()
        }
    );
    for (name, value) in &answer.headers {
        if !HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str()) {
            out.push_str(&format!("{name}: {value}\r\n"));
        }
    }
    match &kind {
        BodyKind::None => {
            // A reply to HEAD and a 304 keep the length of the body that a GET gives.
            if let Some(length) = header(&answer.headers, "content-length") {
                out.push_str(&format!("Content-Length: {length}\r\n"));
            }
        }
        BodyKind::Length(n) => out.push_str(&format!("Content-Length: {n}\r\n")),
        BodyKind::Chunked => out.push_str("Transfer-Encoding: chunked\r\n"),
        BodyKind::UntilClose => {}
    }
    out.push_str(if reusable {
        "Connection: keep-alive\r\n\r\n"
    } else {
        "Connection: close\r\n\r\n"
    });
    let socket = client.stream_mut();
    let _ = socket.set_write_timeout(Some(Duration::from_secs(30)));
    if socket.write_all(out.as_bytes()).is_err() || socket.flush().is_err() {
        return Relayed::Broken;
    }
    let sent = match kind {
        BodyKind::None => Ok(()),
        BodyKind::Length(n) => copy_length(source, socket, n),
        BodyKind::Chunked => copy_chunks(source, socket),
        BodyKind::UntilClose => copy_until_close(source, socket),
    };
    match sent {
        Ok(()) => Relayed::Done { status, reusable },
        Err(_) => Relayed::Broken,
    }
}

fn copy_length(source: &mut Source, socket: &mut TcpStream, mut left: u64) -> io::Result<()> {
    while left > 0 {
        let want = usize::try_from(left).unwrap_or(usize::MAX).min(16 * 1024);
        let part = source.take(want)?;
        if part.is_empty() {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        socket.write_all(&part)?;
        socket.flush()?;
        left -= part.len() as u64;
    }
    Ok(())
}

fn copy_until_close(source: &mut Source, socket: &mut TcpStream) -> io::Result<()> {
    loop {
        let part = source.take(16 * 1024)?;
        if part.is_empty() {
            return Ok(());
        }
        socket.write_all(&part)?;
        socket.flush()?;
    }
}

fn copy_chunks(source: &mut Source, socket: &mut TcpStream) -> io::Result<()> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "chunk");
    loop {
        let line = source.line()?;
        let size_text = line.split(';').next().unwrap_or("").trim().to_owned();
        let size = usize::from_str_radix(&size_text, 16).map_err(|_| bad())?;
        if size == 0 {
            // The edge drops the trailers.
            while !source.line()?.is_empty() {}
            socket.write_all(b"0\r\n\r\n")?;
            return socket.flush();
        }
        socket.write_all(format!("{size:X}\r\n").as_bytes())?;
        let mut left = size;
        while left > 0 {
            let part = source.take(left.min(16 * 1024))?;
            if part.is_empty() {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            socket.write_all(&part)?;
            left -= part.len();
        }
        if !source.line()?.is_empty() {
            return Err(bad());
        }
        socket.write_all(b"\r\n")?;
        socket.flush()?;
    }
}

/// A reply for a failure of the link to the service. The body is empty.
pub fn failure_reply(status: u16) -> HttpReply {
    HttpReply::empty(status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Instant;

    fn pairs(v: &[(&str, &str)]) -> Vec<(String, String)> {
        v.iter()
            .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
            .collect()
    }

    #[test]
    fn p_9_1_the_key_text_and_a_client_copy_of_the_token_header_never_reach_the_service() {
        let client = pairs(&[
            ("Authorization", "Bearer secret"),
            ("x-identity-token", "forged"),
            ("X-Identity-Token", "forged too"),
            ("Accept", "text/html"),
            ("Connection", "keep-alive, X-Hop"),
            ("X-Hop", "1"),
            ("Expect", "100-continue"),
            ("Host", "edge.example"),
            ("Content-Length", "5"),
        ]);
        let out = request_headers(&client, "X-Identity-Token", "good.token.text");
        assert_eq!(
            out,
            pairs(&[
                ("Accept", "text/html"),
                ("X-Identity-Token", "good.token.text")
            ])
        );
    }

    /// A service that answers with the given bytes, and a client connection on the other side.
    fn relay_of(method: &str, wire: &'static [u8], keep_alive: bool) -> (Relayed, String) {
        let service = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = service.local_addr().unwrap().port();
        std::thread::spawn(move || {
            let (mut socket, _) = service.accept().unwrap();
            let mut seen = [0_u8; 4096];
            let _ = socket.read(&mut seen);
            let _ = socket.write_all(wire);
        });
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let mut connection = Connection::new(server_side, Arc::new(AtomicBool::new(false)));
        let upstream = Upstream {
            host: "127.0.0.1".to_owned(),
            port,
            connect_timeout: Duration::from_secs(2),
            response_timeout: Duration::from_secs(2),
        };
        let request = Forward {
            method: method.to_owned(),
            target: "/x?y=1".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        let result = upstream.forward(&request, &mut connection, keep_alive);
        drop(connection);
        reader
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            let mut part = [0_u8; 4096];
            match reader.read(&mut part) {
                Ok(0) | Err(_) => break,
                Ok(n) => got.extend_from_slice(&part[..n]),
            }
        }
        (result, String::from_utf8_lossy(&got).into_owned())
    }

    #[test]
    fn a_body_with_a_length_goes_through_with_the_same_length() {
        let (result, text) = relay_of(
            "GET",
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\nConnection: close\r\nKeep-Alive: x\r\n\r\nhello",
            true,
        );
        assert_eq!(
            result,
            Relayed::Done {
                status: 200,
                reusable: true
            }
        );
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("Content-Type: text/plain\r\n"));
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.contains("Connection: keep-alive\r\n"));
        assert!(!text.contains("Keep-Alive"));
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn a_chunked_body_goes_through_chunk_by_chunk() {
        let (result, text) = relay_of(
            "POST",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;e=1\r\nhello\r\n1\r\n!\r\n0\r\nT: x\r\n\r\n",
            true,
        );
        assert!(matches!(
            result,
            Relayed::Done {
                status: 200,
                reusable: true
            }
        ));
        assert!(text.contains("Transfer-Encoding: chunked\r\n"));
        assert!(
            text.ends_with("\r\n\r\n5\r\nhello\r\n1\r\n!\r\n0\r\n\r\n"),
            "{text}"
        );
    }

    #[test]
    fn a_body_that_ends_with_the_connection_closes_the_client_connection() {
        let (result, text) = relay_of("GET", b"HTTP/1.1 200 OK\r\n\r\nrest of the body", true);
        assert_eq!(
            result,
            Relayed::Done {
                status: 200,
                reusable: false
            }
        );
        assert!(text.contains("Connection: close\r\n"));
        assert!(!text.contains("Content-Length"));
        assert!(text.ends_with("\r\n\r\nrest of the body"));
    }

    #[test]
    fn an_interim_answer_is_dropped_and_a_redirect_goes_through_as_it_is() {
        let (result, text) = relay_of(
            "GET",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n",
            false,
        );
        assert_eq!(
            result,
            Relayed::Done {
                status: 302,
                reusable: false
            }
        );
        assert!(text.starts_with("HTTP/1.1 302 Found\r\n"), "{text}");
        assert!(text.contains("Location: /next\r\n"));
    }

    #[test]
    fn an_answer_to_head_has_no_body_and_keeps_the_length() {
        let (result, text) = relay_of(
            "HEAD",
            b"HTTP/1.1 200 OK\r\nContent-Length: 42\r\n\r\n",
            true,
        );
        assert!(matches!(
            result,
            Relayed::Done {
                status: 200,
                reusable: true
            }
        ));
        assert!(text.contains("Content-Length: 42\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn a_service_that_gives_a_bad_answer_gets_502_and_one_that_is_absent_gets_502() {
        let (result, _) = relay_of("GET", b"garbage\r\n\r\n", true);
        assert_eq!(result, Relayed::NoAnswer(502));
        let upstream = Upstream {
            host: "127.0.0.1".to_owned(),
            port: 1,
            connect_timeout: Duration::from_millis(500),
            response_timeout: Duration::from_millis(500),
        };
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let _reader = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server_side, _) = listener.accept().unwrap();
        let mut connection = Connection::new(server_side, Arc::new(AtomicBool::new(false)));
        let request = Forward {
            method: "GET".to_owned(),
            target: "/".to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
        };
        assert_eq!(
            upstream.forward(&request, &mut connection, true),
            Relayed::NoAnswer(502)
        );
    }
}
