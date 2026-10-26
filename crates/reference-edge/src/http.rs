//! The HTTP/1.1 layer of the client side of the edge.
//!
//! The layer reads the head of a request first, and the body later. The edge
//! must decide on the head alone: a refusal needs no part of the body (protocol
//! 9.8). The layer bounds the head and the body, and it has timeouts. It reads a
//! body with a length or in chunks. It supports keep-alive and `Expect: 100-continue`.
//!
//! The parser refuses a folded header, a bad `Content-Length`, a request with both
//! `Content-Length` and `Transfer-Encoding`, and a version other than HTTP/1.0 and
//! HTTP/1.1.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use procurauth_pep::reply::HttpReply;

/// The largest head of a request: the request line and the headers.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The most headers in one request.
const MAX_HEADERS: usize = 100;
/// The longest request target.
const MAX_TARGET_BYTES: usize = 8 * 1024;
/// The longest line of a chunk header in a chunked body: a size and its extensions.
const MAX_CHUNK_LINE: usize = 1024;
/// How often a read that has no data looks at the stop flag.
const POLL: Duration = Duration::from_millis(50);
/// The longest time that the edge reads the rest of a request that it refused.
const DRAIN_TIME: Duration = Duration::from_secs(2);

/// The bounds of one connection of a client.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The largest body, in bytes.
    pub max_body: usize,
    /// The time to read a whole request after its first byte.
    pub read_timeout: Duration,
    /// The time that an idle connection stays open.
    pub idle_timeout: Duration,
}

/// The form of the body of a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Framing {
    /// The request has no body.
    None,
    /// The body has this length.
    Length(usize),
    /// The body is in chunks.
    Chunked,
}

/// The head of a request: everything before the body.
#[derive(Clone, Debug)]
pub struct Head {
    /// The method, for example `GET`.
    pub method: String,
    /// The request target, as the client sent it: the path and the query.
    pub target: String,
    /// The headers, with their names and values as the client sent them.
    pub headers: Vec<(String, String)>,
    /// True when the connection stays open after the answer.
    pub keep_alive: bool,
    /// The form of the body.
    pub framing: Framing,
    /// True when the client waits for `100 Continue` before it sends the body.
    pub expect_continue: bool,
}

impl Head {
    /// The path of the target, with no query.
    pub fn path(&self) -> &str {
        self.target.split_once('?').map_or(&self.target, |(p, _)| p)
    }

    /// The values of a header. The name has no case.
    pub fn header_values<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }
}

/// What the read of a head gives.
pub enum ReadHead {
    /// The client closed the connection, or the edge stops.
    Closed,
    /// The request is not valid. Send this reply and close the connection.
    Reject(HttpReply),
    /// A good head.
    Head(Head),
}

/// A connection with a buffer for the bytes that the client sent ahead.
pub struct Connection {
    stream: TcpStream,
    buf: Vec<u8>,
    stop: Arc<AtomicBool>,
}

enum Wait {
    Data,
    Closed,
    Stop,
    Timeout,
}

fn reject(status: u16) -> ReadHead {
    ReadHead::Reject(HttpReply::empty(status))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// True when the text is an HTTP token (RFC 9110, 5.6.2).
pub fn is_token(text: &str) -> bool {
    !text.is_empty()
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

impl Connection {
    /// A connection. The stop flag ends each wait.
    pub fn new(stream: TcpStream, stop: Arc<AtomicBool>) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            stop,
        }
    }

    /// The socket, for the relay of an answer.
    pub fn stream_mut(&mut self) -> &mut TcpStream {
        &mut self.stream
    }

    fn fill(&mut self, deadline: Instant) -> Wait {
        let mut chunk = [0_u8; 8192];
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Wait::Stop;
            }
            let now = Instant::now();
            if now >= deadline {
                return Wait::Timeout;
            }
            let _ = self
                .stream
                .set_read_timeout(Some(POLL.min(deadline - now).max(Duration::from_millis(1))));
            match self.stream.read(&mut chunk) {
                Ok(0) => return Wait::Closed,
                Ok(n) => {
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Wait::Data;
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Wait::Closed,
            }
        }
    }

    /// Read the head of one request. The body stays unread.
    pub fn read_head(&mut self, limits: &Limits) -> ReadHead {
        // Wait for the first byte of the next request.
        let mut deadline = Instant::now() + limits.idle_timeout;
        let mut started = !self.buf.is_empty();
        if started {
            deadline = Instant::now() + limits.read_timeout;
        }
        let head_end = loop {
            if let Some(end) = find(&self.buf, b"\r\n\r\n") {
                break end;
            }
            if self.buf.len() > MAX_HEAD_BYTES {
                return reject(431);
            }
            match self.fill(deadline) {
                Wait::Data => {
                    if !started {
                        started = true;
                        deadline = Instant::now() + limits.read_timeout;
                    }
                }
                Wait::Closed | Wait::Stop => return ReadHead::Closed,
                Wait::Timeout => {
                    return if started {
                        reject(408)
                    } else {
                        ReadHead::Closed
                    };
                }
            }
        };
        if head_end > MAX_HEAD_BYTES {
            return reject(431);
        }
        let raw = self.buf[..head_end].to_vec();
        self.buf.drain(..head_end + 4);
        parse_head(&raw)
    }

    /// Read the body of the request that `head` describes. The edge calls this
    /// after it accepted the request. It sends `100 Continue` when the client waits for it.
    ///
    /// # Errors
    /// Returns the reply to send, and the connection must close after it.
    pub fn read_body(&mut self, head: &Head, limits: &Limits) -> Result<Vec<u8>, HttpReply> {
        if head.expect_continue && head.framing != Framing::None && self.buf.is_empty() {
            let _ = self.stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        let deadline = Instant::now() + limits.read_timeout;
        match head.framing {
            Framing::None => Ok(Vec::new()),
            Framing::Length(length) => {
                if length > limits.max_body {
                    return Err(HttpReply::empty(413));
                }
                while self.buf.len() < length {
                    self.wait(deadline)?;
                }
                Ok(self.buf.drain(..length).collect())
            }
            Framing::Chunked => self.read_chunks(limits.max_body, deadline),
        }
    }

    fn wait(&mut self, deadline: Instant) -> Result<(), HttpReply> {
        match self.fill(deadline) {
            Wait::Data => Ok(()),
            Wait::Closed | Wait::Stop => Err(HttpReply::empty(400)),
            Wait::Timeout => Err(HttpReply::empty(408)),
        }
    }

    /// Take one line that ends with CRLF from the buffer, without the line end.
    fn take_line(&mut self, deadline: Instant) -> Result<String, HttpReply> {
        loop {
            if let Some(end) = find(&self.buf, b"\r\n") {
                let line: Vec<u8> = self.buf.drain(..end + 2).take(end).collect();
                return String::from_utf8(line).map_err(|_| HttpReply::empty(400));
            }
            if self.buf.len() > MAX_CHUNK_LINE {
                return Err(HttpReply::empty(400));
            }
            self.wait(deadline)?;
        }
    }

    fn read_chunks(&mut self, max: usize, deadline: Instant) -> Result<Vec<u8>, HttpReply> {
        let mut body = Vec::new();
        loop {
            let line = self.take_line(deadline)?;
            let size_text = line.split(';').next().unwrap_or("").trim();
            if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(HttpReply::empty(400));
            }
            let size = usize::from_str_radix(size_text, 16).map_err(|_| HttpReply::empty(413))?;
            if size == 0 {
                // The trailers end with an empty line. The edge reads them and drops them.
                loop {
                    if self.take_line(deadline)?.is_empty() {
                        return Ok(body);
                    }
                }
            }
            if body.len().saturating_add(size) > max {
                return Err(HttpReply::empty(413));
            }
            while self.buf.len() < size + 2 {
                self.wait(deadline)?;
            }
            if &self.buf[size..size + 2] != b"\r\n" {
                return Err(HttpReply::empty(400));
            }
            body.extend(self.buf.drain(..size + 2).take(size));
        }
    }

    /// Write one reply. `Content-Length` and `Connection` come from the layer.
    ///
    /// # Errors
    /// Returns the error of the socket.
    pub fn write_reply(&mut self, reply: &HttpReply, keep_alive: bool) -> io::Result<()> {
        let mut head = format!("HTTP/1.1 {} {}\r\n", reply.status, reason(reply.status));
        for (name, value) in &reply.headers {
            let lower = name.to_ascii_lowercase();
            if lower == "content-length" || lower == "connection" {
                continue;
            }
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        head.push_str(&format!("Content-Length: {}\r\n", reply.body.len()));
        head.push_str(if keep_alive {
            "Connection: keep-alive\r\n\r\n"
        } else {
            "Connection: close\r\n\r\n"
        });
        let mut out = head.into_bytes();
        out.extend_from_slice(&reply.body);
        let _ = self.stream.set_write_timeout(Some(Duration::from_secs(10)));
        self.stream.write_all(&out)?;
        self.stream.flush()
    }

    /// Write a reply to a request that the edge refused, and close the connection.
    ///
    /// The edge did not read the body. It closes its write side. Then it reads
    /// and drops what the client still sends, for a short time. A client that
    /// sends a large body then still reads the answer, and does not get a reset.
    pub fn refuse_and_close(&mut self, reply: &HttpReply) {
        if self.write_reply(reply, false).is_err() {
            return;
        }
        let _ = self.stream.shutdown(Shutdown::Write);
        let deadline = Instant::now() + DRAIN_TIME;
        let mut dropped = 0_usize;
        let mut chunk = [0_u8; 8192];
        while Instant::now() < deadline && dropped < 16 * 1024 * 1024 {
            if self.stop.load(Ordering::SeqCst) {
                break;
            }
            let _ = self.stream.set_read_timeout(Some(POLL));
            match self.stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => dropped += n,
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => break,
            }
        }
    }
}

fn parse_head(raw: &[u8]) -> ReadHead {
    let Ok(head) = std::str::from_utf8(raw) else {
        return reject(400);
    };
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split(' ');
    let (Some(method), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return reject(400);
    };
    if !is_token(method)
        || !target.starts_with('/')
        || target.bytes().any(|b| b <= 0x20 || b >= 0x7f)
    {
        return reject(400);
    }
    if target.len() > MAX_TARGET_BYTES {
        return reject(414);
    }
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return reject(505),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return reject(431);
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            return reject(400);
        }
        let Some((name, value)) = line.split_once(':') else {
            return reject(400);
        };
        if !is_token(name) || value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
            return reject(400);
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    let get = |name: &str| -> Vec<&str> {
        headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    };
    let encodings = get("transfer-encoding");
    let lengths = get("content-length");
    let framing = if !encodings.is_empty() {
        if !lengths.is_empty() {
            return reject(400);
        }
        if encodings.len() != 1 || !encodings[0].eq_ignore_ascii_case("chunked") {
            return reject(501);
        }
        Framing::Chunked
    } else {
        match lengths.first() {
            None => Framing::None,
            Some(first) => {
                if lengths.iter().any(|l| l != first)
                    || first.is_empty()
                    || !first.bytes().all(|b| b.is_ascii_digit())
                {
                    return reject(400);
                }
                match first.parse::<usize>() {
                    Ok(0) => Framing::None,
                    Ok(n) => Framing::Length(n),
                    Err(_) => return reject(413),
                }
            }
        }
    };
    let expect_continue = get("expect")
        .iter()
        .any(|v| v.eq_ignore_ascii_case("100-continue"));
    let connection: Vec<String> = get("connection")
        .iter()
        .flat_map(|v| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    let keep_alive = if http10 {
        connection.iter().any(|t| t == "keep-alive")
    } else {
        !connection.iter().any(|t| t == "close")
    };
    ReadHead::Head(Head {
        method: method.to_owned(),
        target: target.to_owned(),
        headers,
        keep_alive,
        framing,
        expect_continue,
    })
}

/// The reason phrase of a status.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    fn pair() -> (TcpStream, Connection) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (
            client,
            Connection::new(server, Arc::new(AtomicBool::new(false))),
        )
    }

    const LIMITS: Limits = Limits {
        max_body: 64,
        read_timeout: Duration::from_millis(300),
        idle_timeout: Duration::from_millis(300),
    };

    fn head_of(wire: &[u8]) -> ReadHead {
        let (mut client, mut conn) = pair();
        client.write_all(wire).unwrap();
        conn.read_head(&LIMITS)
    }

    fn status_of(result: ReadHead) -> u16 {
        match result {
            ReadHead::Reject(reply) => reply.status,
            ReadHead::Closed => 0,
            ReadHead::Head(_) => 200,
        }
    }

    #[test]
    fn a_good_head_has_its_parts_and_the_body_stays_unread() {
        let (mut client, mut conn) = pair();
        client
            .write_all(
                b"POST /a/b?x=1 HTTP/1.1\r\nHost: h\r\nX-A:  b \r\nContent-Length: 3\r\n\r\nabc",
            )
            .unwrap();
        let ReadHead::Head(head) = conn.read_head(&LIMITS) else {
            panic!("not a head");
        };
        assert_eq!(
            (head.method.as_str(), head.path(), head.target.as_str()),
            ("POST", "/a/b", "/a/b?x=1")
        );
        assert_eq!(head.header_values("x-a").collect::<Vec<_>>(), ["b"]);
        assert_eq!(head.framing, Framing::Length(3));
        assert!(head.keep_alive);
        assert_eq!(conn.read_body(&head, &LIMITS).unwrap(), b"abc");
    }

    #[test]
    fn a_bad_head_gets_a_status() {
        assert_eq!(status_of(head_of(b"GARBAGE\r\n\r\n")), 400);
        assert_eq!(status_of(head_of(b"GET /a HTTP/2\r\n\r\n")), 505);
        assert_eq!(status_of(head_of(b"GET a HTTP/1.1\r\n\r\n")), 400);
        assert_eq!(
            status_of(head_of(b"GET /a HTTP/1.1\r\nA: b\r\n c\r\n\r\n")),
            400
        );
        assert_eq!(
            status_of(head_of(
                b"POST /a HTTP/1.1\r\nTransfer-Encoding: gzip\r\n\r\n"
            )),
            501
        );
        assert_eq!(
            status_of(head_of(
                b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 1\r\n\r\n"
            )),
            400
        );
        assert_eq!(
            status_of(head_of(b"POST /a HTTP/1.1\r\nContent-Length: x\r\n\r\n")),
            400
        );
        assert_eq!(
            status_of(head_of(
                b"POST /a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
            )),
            400
        );
    }

    #[test]
    fn p_9_8_a_body_above_the_bound_is_not_read_before_the_head_is_good() {
        // The head is good: the edge can refuse the request with no body read.
        let ReadHead::Head(head) = head_of(b"POST /a HTTP/1.1\r\nContent-Length: 65\r\n\r\n")
        else {
            panic!("not a head");
        };
        assert_eq!(head.framing, Framing::Length(65));
        let (mut client, mut conn) = pair();
        client
            .write_all(b"POST /a HTTP/1.1\r\nContent-Length: 65\r\n\r\n")
            .unwrap();
        let ReadHead::Head(head) = conn.read_head(&LIMITS) else {
            panic!("not a head");
        };
        assert_eq!(conn.read_body(&head, &LIMITS).unwrap_err().status, 413);
    }

    #[test]
    fn a_chunked_body_is_read_and_its_trailers_are_dropped() {
        let (mut client, mut conn) = pair();
        client
            .write_all(
                b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=y\r\nde\r\n0\r\nT: v\r\n\r\nGET /b HTTP/1.1\r\n\r\n",
            )
            .unwrap();
        let ReadHead::Head(head) = conn.read_head(&LIMITS) else {
            panic!("not a head");
        };
        assert_eq!(head.framing, Framing::Chunked);
        assert_eq!(conn.read_body(&head, &LIMITS).unwrap(), b"abcde");
        let ReadHead::Head(next) = conn.read_head(&LIMITS) else {
            panic!("not a head");
        };
        assert_eq!(next.path(), "/b");
    }

    #[test]
    fn a_bad_chunk_gets_400_and_a_large_chunked_body_gets_413() {
        for (wire, status) in [
            (
                &b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n"[..],
                400,
            ),
            (
                &b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabcXX"[..],
                400,
            ),
            (
                &b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n41\r\n"[..],
                413,
            ),
        ] {
            let (mut client, mut conn) = pair();
            client.write_all(wire).unwrap();
            let ReadHead::Head(head) = conn.read_head(&LIMITS) else {
                panic!("not a head");
            };
            assert_eq!(conn.read_body(&head, &LIMITS).unwrap_err().status, status);
        }
    }

    #[test]
    fn a_slow_request_gets_408_and_an_idle_connection_closes() {
        let (mut client, mut conn) = pair();
        client.write_all(b"GET /a HTTP/1.1\r\nHost: h\r\n").unwrap();
        assert_eq!(status_of(conn.read_head(&LIMITS)), 408);
        let (_client, mut conn) = pair();
        assert!(matches!(conn.read_head(&LIMITS), ReadHead::Closed));
    }

    #[test]
    fn keep_alive_follows_the_version_and_the_connection_header() {
        let keep = |wire: &[u8]| match head_of(wire) {
            ReadHead::Head(h) => h.keep_alive,
            _ => panic!("not a head"),
        };
        assert!(keep(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!keep(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"));
        assert!(!keep(b"GET / HTTP/1.0\r\n\r\n"));
        assert!(keep(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"));
    }

    #[test]
    fn p_9_8_a_refusal_has_an_empty_body_and_the_client_can_still_send_its_body() {
        let (mut client, mut conn) = pair();
        let reply = HttpReply::empty(401).with_header("WWW-Authenticate", "Bearer");
        let writer = std::thread::spawn(move || {
            // A body that is larger than the buffers of the socket.
            let body = vec![b'x'; 2_000_000];
            let _ = client.write_all(b"POST /a HTTP/1.1\r\nContent-Length: 2000000\r\n\r\n");
            let _ = client.write_all(&body);
            let mut got = Vec::new();
            let _ = client.read_to_end(&mut got);
            String::from_utf8_lossy(&got).into_owned()
        });
        let ReadHead::Head(_) = conn.read_head(&LIMITS) else {
            panic!("not a head");
        };
        conn.refuse_and_close(&reply);
        let text = writer.join().unwrap();
        assert!(text.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{text}");
        assert!(text.contains("WWW-Authenticate: Bearer\r\n"));
        assert!(text.contains("Content-Length: 0\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "the body is empty: {text}");
    }
}
