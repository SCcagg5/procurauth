//! A small HTTP/1.1 server layer on the standard library.
//!
//! The service has its own layer, as `fake-pdp` has. The reference service must
//! read its requests with strict rules, and it must stay small enough to read.
//! A framework would hide these rules. The layer reads one request at a time from
//! a connection. It bounds the size of the head and of the body, and it has
//! timeouts. It supports keep-alive and `Expect: 100-continue`.
//!
//! The parser refuses a folded header, a `Transfer-Encoding`, a bad
//! `Content-Length` and a version other than HTTP/1.0 and HTTP/1.1.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use procurauth_pep::reply::HttpReply;

/// The largest head of a request: the request line and the headers.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The most headers in one request.
const MAX_HEADERS: usize = 100;
/// The longest request target.
const MAX_TARGET_BYTES: usize = 2048;
/// How often a read that has no data looks at the stop flag.
const POLL: Duration = Duration::from_millis(50);

/// The bounds of one connection.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// The largest body, in bytes.
    pub max_body: usize,
    /// The time to read a whole request after its first byte.
    pub read_timeout: Duration,
    /// The time that an idle connection stays open.
    pub idle_timeout: Duration,
}

/// One request.
#[derive(Clone, Debug)]
pub struct Request {
    /// The method, for example `GET`.
    pub method: String,
    /// The path of the target, as the client sent it, with no query.
    pub path: String,
    /// The query of the target, with no `?`. It is empty when the target has none.
    pub query: String,
    /// The headers, with their names and values as the client sent them.
    pub headers: Vec<(String, String)>,
    /// The body.
    pub body: Vec<u8>,
    /// True when the connection stays open after the reply.
    pub keep_alive: bool,
}

impl Request {
    /// The value of a header. The name has no case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// The headers as name and value pairs, for the check of the identity token.
    pub fn header_pairs(&self) -> impl Iterator<Item = (&str, &str)> {
        self.headers.iter().map(|(n, v)| (n.as_str(), v.as_str()))
    }
}

/// What a read of a connection gives.
pub enum ReadResult {
    /// The client closed the connection, or the service stops.
    Closed,
    /// The request is not valid. Send this reply and close the connection.
    Reject(HttpReply),
    /// A good request.
    Request(Request),
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

fn reject(status: u16) -> ReadResult {
    ReadResult::Reject(HttpReply::empty(status))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn is_token(text: &str) -> bool {
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

    /// Read one request.
    pub fn read_request(&mut self, limits: &Limits) -> ReadResult {
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
                Wait::Closed | Wait::Stop => return ReadResult::Closed,
                Wait::Timeout => {
                    return if started {
                        reject(408)
                    } else {
                        ReadResult::Closed
                    };
                }
            }
        };
        if head_end > MAX_HEAD_BYTES {
            return reject(431);
        }
        let head = self.buf[..head_end].to_vec();
        self.buf.drain(..head_end + 4);
        let Ok(head) = String::from_utf8(head) else {
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
        if !get("transfer-encoding").is_empty() {
            return reject(501);
        }
        let lengths = get("content-length");
        let length = match lengths.first() {
            None => 0,
            Some(first) => {
                if lengths.iter().any(|l| l != first)
                    || first.is_empty()
                    || !first.bytes().all(|b| b.is_ascii_digit())
                {
                    return reject(400);
                }
                match first.parse::<usize>() {
                    Ok(n) => n,
                    Err(_) => return reject(413),
                }
            }
        };
        if length > limits.max_body {
            return reject(413);
        }
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
        if expect_continue && length > 0 && self.buf.is_empty() {
            let _ = self.stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        let body_deadline = Instant::now() + limits.read_timeout;
        while self.buf.len() < length {
            match self.fill(body_deadline) {
                Wait::Data => {}
                Wait::Closed | Wait::Stop => return ReadResult::Closed,
                Wait::Timeout => return reject(408),
            }
        }
        let body: Vec<u8> = self.buf.drain(..length).collect();
        let (path, query) = target.split_once('?').unwrap_or((target, ""));
        ReadResult::Request(Request {
            method: method.to_owned(),
            path: path.to_owned(),
            query: query.to_owned(),
            headers,
            body,
            keep_alive,
        })
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
}

/// The reason phrase of a status that the service uses.
pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        414 => "URI Too Long",
        422 => "Unprocessable Content",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Status",
    }
}

/// Decode the percent-escapes of a path segment or of a query value. The
/// function does not read `+` as a space. It accepts upper-case and lower-case
/// hexadecimal digits.
pub fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = bytes.get(i + 1..i + 3)?;
            let hex = std::str::from_utf8(pair).ok()?;
            if !pair.iter().all(u8::is_ascii_hexdigit) {
                return None;
            }
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

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

    fn read(wire: &[u8]) -> ReadResult {
        let (mut client, mut conn) = pair();
        client.write_all(wire).unwrap();
        conn.read_request(&LIMITS)
    }

    fn status_of(result: ReadResult) -> u16 {
        match result {
            ReadResult::Reject(reply) => reply.status,
            ReadResult::Closed => 0,
            ReadResult::Request(_) => 200,
        }
    }

    #[test]
    fn a_good_request_has_its_parts() {
        let ReadResult::Request(r) = read(
            b"POST /a/b?x=1&y=2 HTTP/1.1\r\nHost: h\r\nX-A:  b \r\nContent-Length: 3\r\n\r\nabc",
        ) else {
            panic!("not a request");
        };
        assert_eq!(
            (r.method.as_str(), r.path.as_str(), r.query.as_str()),
            ("POST", "/a/b", "x=1&y=2")
        );
        assert_eq!(r.header("x-a"), Some("b"));
        assert_eq!(r.body, b"abc");
        assert!(r.keep_alive);
    }

    #[test]
    fn a_bad_request_gets_a_status() {
        assert_eq!(status_of(read(b"GARBAGE\r\n\r\n")), 400);
        assert_eq!(status_of(read(b"GET /a HTTP/2\r\n\r\n")), 505);
        assert_eq!(status_of(read(b"GET a HTTP/1.1\r\n\r\n")), 400);
        assert_eq!(
            status_of(read(b"GET /a HTTP/1.1\r\nA: b\r\n c\r\n\r\n")),
            400
        );
        assert_eq!(
            status_of(read(
                b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n"
            )),
            501
        );
        assert_eq!(
            status_of(read(b"POST /a HTTP/1.1\r\nContent-Length: x\r\n\r\n")),
            400
        );
        assert_eq!(
            status_of(read(
                b"POST /a HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"
            )),
            400
        );
        assert_eq!(
            status_of(read(b"POST /a HTTP/1.1\r\nContent-Length: 65\r\n\r\n")),
            413
        );
    }

    #[test]
    fn a_slow_request_gets_408_and_an_idle_connection_closes() {
        let (mut client, mut conn) = pair();
        client.write_all(b"GET /a HTTP/1.1\r\nHost: h\r\n").unwrap();
        assert_eq!(status_of(conn.read_request(&LIMITS)), 408);
        let (_client, mut conn) = pair();
        assert!(matches!(conn.read_request(&LIMITS), ReadResult::Closed));
    }

    #[test]
    fn keep_alive_follows_the_version_and_the_connection_header() {
        let keep = |wire: &[u8]| match read(wire) {
            ReadResult::Request(r) => r.keep_alive,
            _ => panic!("not a request"),
        };
        assert!(keep(b"GET / HTTP/1.1\r\n\r\n"));
        assert!(!keep(b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"));
        assert!(!keep(b"GET / HTTP/1.0\r\n\r\n"));
        assert!(keep(b"GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n"));
    }

    #[test]
    fn two_requests_on_one_connection_are_read_in_order() {
        let (mut client, mut conn) = pair();
        client
            .write_all(b"GET /one HTTP/1.1\r\n\r\nGET /two HTTP/1.1\r\n\r\n")
            .unwrap();
        let ReadResult::Request(a) = conn.read_request(&LIMITS) else {
            panic!()
        };
        let ReadResult::Request(b) = conn.read_request(&LIMITS) else {
            panic!()
        };
        assert_eq!((a.path.as_str(), b.path.as_str()), ("/one", "/two"));
    }

    #[test]
    fn a_reply_has_the_length_and_the_connection_header() {
        let (mut client, mut conn) = pair();
        let reply =
            HttpReply::json(429, &serde_json::json!({"a": 1})).with_header("Retry-After", "12");
        conn.write_reply(&reply, true).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut got = vec![0_u8; 512];
        let n = client.read(&mut got).unwrap();
        let text = String::from_utf8_lossy(&got[..n]).into_owned();
        assert!(
            text.starts_with("HTTP/1.1 429 Too Many Requests\r\n"),
            "{text}"
        );
        assert!(text.contains("Retry-After: 12\r\n"));
        assert!(text.contains("Content-Length: 7\r\n"));
        assert!(text.contains("Connection: keep-alive\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"a\":1}"));
    }

    #[test]
    fn percent_decoding_is_one_pass_and_keeps_the_plus() {
        assert_eq!(percent_decode("a%2Fb").as_deref(), Some("a/b"));
        assert_eq!(percent_decode("a%2fb").as_deref(), Some("a/b"));
        assert_eq!(percent_decode("a+b").as_deref(), Some("a+b"));
        assert_eq!(percent_decode("a%252Fb").as_deref(), Some("a%2Fb"));
        assert_eq!(percent_decode("%zz"), None);
        assert_eq!(percent_decode("%2"), None);
        assert_eq!(percent_decode("%FF"), None);
    }
}
