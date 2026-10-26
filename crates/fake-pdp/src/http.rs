//! A small HTTP/1.1 server layer on the standard library.
//!
//! The layer reads one request at a time from a connection. It bounds the
//! size of the head and of the body, and it has timeouts. It supports
//! keep-alive and `Expect: 100-continue`. It refuses chunked bodies. The code
//! has its own parser because the tool must control the connection. It must
//! close the connection, or leave it open with no answer, on request (10.6).

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

/// The largest head of a request: the request line and the headers.
pub(crate) const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The most headers in one request.
const MAX_HEADERS: usize = 100;
/// The longest request target.
const MAX_TARGET_BYTES: usize = 2048;
/// How often a read that has no data looks at the stop flag.
const POLL: Duration = Duration::from_millis(50);

/// The bounds of one connection.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// The largest body, in bytes.
    pub max_body: usize,
    /// The time to read a whole request after its first byte.
    pub read_timeout: Duration,
    /// The time that an idle connection stays open.
    pub idle: Duration,
}

/// One request.
#[derive(Debug)]
pub(crate) struct Request {
    pub method: String,
    /// The path, with no query.
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

impl Request {
    /// The value of a header. The name is in lower case.
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }
}

/// One response.
#[derive(Clone, Debug)]
pub(crate) struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// A response with a JSON body.
    pub(crate) fn json(status: u16, body: &serde_json::Value) -> Self {
        Self::raw_json(status, body.to_string().into_bytes())
    }

    /// A response with a body that the caller made, as JSON text or not.
    pub(crate) fn raw_json(status: u16, body: Vec<u8>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body,
        }
    }

    /// A response for an error. The body is a short fixed message and gives no detail.
    pub(crate) fn error(status: u16) -> Self {
        Self::json(status, &serde_json::json!({ "error": reason(status) }))
    }

    /// Add a header.
    #[must_use]
    pub(crate) fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }
}

/// The request id to echo (AuthZEN 1.0, Request Identification): visible ASCII, 256 bytes at most.
/// Any other value gets no echo, so a header never carries a byte that the client did not send as text.
pub(crate) fn valid_request_id(value: &str) -> Option<String> {
    (!value.is_empty() && value.len() <= 256 && value.bytes().all(|b| (0x20..0x7f).contains(&b)))
        .then(|| value.to_owned())
}

/// Add the header `X-Request-ID` to a response, when the request had a good one.
pub(crate) fn echo_request_id(response: Response, id: Option<&str>) -> Response {
    match id {
        Some(id) => response.with_header("X-Request-ID", id),
        None => response,
    }
}

/// The reason phrase of a status that the server uses.
pub(crate) fn reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        413 => "Content Too Large",
        414 => "URI Too Long",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        501 => "Not Implemented",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Error",
    }
}

/// The result of one read.
pub(crate) enum ReadResult {
    /// A whole request.
    Request(Request),
    /// The request is bad. Send this response and close the connection.
    Reject(Response),
    /// The client closed the connection, the connection was idle too long, or the server stops.
    Closed,
}

enum Fill {
    Timeout,
    Stopped,
    Eof,
    Failed,
}

/// A connection with a buffer for the bytes that follow a request.
pub(crate) struct Connection {
    stream: TcpStream,
    buffer: Vec<u8>,
    stop: Arc<AtomicBool>,
}

impl Connection {
    pub(crate) fn new(stream: TcpStream, stop: Arc<AtomicBool>) -> Self {
        let _ = stream.set_nodelay(true);
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        Self {
            stream,
            buffer: Vec::new(),
            stop,
        }
    }

    /// Read more bytes into the buffer, or tell why not.
    fn fill(&mut self, deadline: Instant) -> Result<(), Fill> {
        let mut chunk = [0_u8; 8192];
        loop {
            if self.stop.load(Ordering::SeqCst) {
                return Err(Fill::Stopped);
            }
            let now = Instant::now();
            if now >= deadline {
                return Err(Fill::Timeout);
            }
            let wait = (deadline - now).min(POLL);
            if self.stream.set_read_timeout(Some(wait)).is_err() {
                return Err(Fill::Failed);
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(Fill::Eof),
                Ok(n) => {
                    self.buffer.extend_from_slice(&chunk[..n]);
                    return Ok(());
                }
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) => {}
                Err(_) => return Err(Fill::Failed),
            }
        }
    }

    /// Read the next request.
    pub(crate) fn read_request(&mut self, limits: &Limits) -> ReadResult {
        if self.buffer.is_empty() {
            // Wait for the first byte of the next request, at most the idle time.
            if self.fill(Instant::now() + limits.idle).is_err() {
                return ReadResult::Closed;
            }
        }
        let deadline = Instant::now() + limits.read_timeout;
        let head_end = loop {
            if let Some(position) = find(&self.buffer, b"\r\n\r\n") {
                break position;
            }
            if self.buffer.len() > MAX_HEAD_BYTES {
                return ReadResult::Reject(Response::error(431));
            }
            match self.fill(deadline) {
                Ok(()) => {}
                Err(Fill::Timeout) => return ReadResult::Reject(Response::error(408)),
                Err(_) => return ReadResult::Closed,
            }
        };
        if head_end > MAX_HEAD_BYTES {
            return ReadResult::Reject(Response::error(431));
        }
        let head = match parse_head(&self.buffer[..head_end]) {
            Ok(head) => head,
            Err(status) => return ReadResult::Reject(Response::error(status)),
        };
        let body_start = head_end + 4;
        if head.content_length > limits.max_body as u64 {
            let id = head
                .headers
                .iter()
                .find(|(n, _)| n == "x-request-id")
                .and_then(|(_, v)| valid_request_id(v));
            return ReadResult::Reject(echo_request_id(Response::error(413), id.as_deref()));
        }
        let length = head.content_length as usize;
        if self.buffer.len() < body_start + length && head.expect_continue {
            let _ = self.stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
        }
        while self.buffer.len() < body_start + length {
            match self.fill(deadline) {
                Ok(()) => {}
                Err(Fill::Timeout) => return ReadResult::Reject(Response::error(408)),
                Err(_) => return ReadResult::Closed,
            }
        }
        let body = self.buffer[body_start..body_start + length].to_vec();
        self.buffer.drain(..body_start + length);
        ReadResult::Request(Request {
            method: head.method,
            path: head.path,
            headers: head.headers,
            body,
            keep_alive: head.keep_alive,
        })
    }

    /// Write a response. `keep_alive` tells the client if the connection stays open.
    pub(crate) fn write_response(
        &mut self,
        response: &Response,
        keep_alive: bool,
        idle_seconds: u64,
    ) -> io::Result<()> {
        let mut out = Vec::with_capacity(response.body.len() + 256);
        out.extend_from_slice(
            format!(
                "HTTP/1.1 {} {}\r\n",
                response.status,
                reason(response.status)
            )
            .as_bytes(),
        );
        out.extend_from_slice(b"Content-Type: application/json\r\n");
        out.extend_from_slice(format!("Content-Length: {}\r\n", response.body.len()).as_bytes());
        if keep_alive {
            out.extend_from_slice(
                format!("Connection: keep-alive\r\nKeep-Alive: timeout={idle_seconds}\r\n")
                    .as_bytes(),
            );
        } else {
            out.extend_from_slice(b"Connection: close\r\n");
        }
        for (name, value) in &response.headers {
            out.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        }
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(&response.body);
        self.stream.write_all(&out)?;
        self.stream.flush()
    }

    /// Read and drop bytes until the client closes the connection or the server stops.
    pub(crate) fn hold_open(&mut self) {
        loop {
            self.buffer.clear();
            if self
                .fill(Instant::now() + Duration::from_secs(3600))
                .is_err_and(|e| !matches!(e, Fill::Timeout))
            {
                return;
            }
        }
    }

    /// Close the connection at once, with no bytes.
    pub(crate) fn close(self) {
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

struct Head {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    content_length: u64,
    keep_alive: bool,
    expect_continue: bool,
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

/// Parse the request line and the headers. The error is the status of the response.
fn parse_head(bytes: &[u8]) -> Result<Head, u16> {
    let text = std::str::from_utf8(bytes).map_err(|_| 400_u16)?;
    let mut lines = text.split("\r\n");
    let request_line = lines.next().ok_or(400_u16)?;
    let mut parts = request_line.split(' ');
    let (method, target, version) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(m), Some(t), Some(v), None) => (m, t, v),
        _ => return Err(400),
    };
    if !is_token(method) {
        return Err(400);
    }
    if target.len() > MAX_TARGET_BYTES {
        return Err(414);
    }
    if !target.starts_with('/') || target.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        return Err(400);
    }
    let http11 = match version {
        "HTTP/1.1" => true,
        "HTTP/1.0" => false,
        v if v.starts_with("HTTP/") => return Err(505),
        _ => return Err(400),
    };
    let path = target.split(['?', '#']).next().unwrap_or("/").to_owned();

    let mut headers: Vec<(String, String)> = Vec::new();
    for line in lines {
        if headers.len() >= MAX_HEADERS {
            return Err(431);
        }
        let (name, value) = line.split_once(':').ok_or(400_u16)?;
        if !is_token(name) {
            return Err(400);
        }
        let value = value.trim_matches(|c| c == ' ' || c == '\t');
        if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
            return Err(400);
        }
        headers.push((name.to_ascii_lowercase(), value.to_owned()));
    }
    if headers.iter().any(|(n, _)| n == "transfer-encoding") {
        return Err(501);
    }
    let mut content_length: Option<u64> = None;
    for (_, value) in headers.iter().filter(|(n, _)| n == "content-length") {
        if value.is_empty() || value.len() > 19 || !value.bytes().all(|b| b.is_ascii_digit()) {
            return Err(400);
        }
        let parsed: u64 = value.parse().map_err(|_| 400_u16)?;
        match content_length {
            Some(previous) if previous != parsed => return Err(400),
            _ => content_length = Some(parsed),
        }
    }
    let connection: Vec<String> = headers
        .iter()
        .filter(|(n, _)| n == "connection")
        .flat_map(|(_, v)| v.split(','))
        .map(|t| t.trim().to_ascii_lowercase())
        .collect();
    let keep_alive = if http11 {
        !connection.iter().any(|t| t == "close")
    } else {
        connection.iter().any(|t| t == "keep-alive")
    };
    let expect_continue = headers
        .iter()
        .any(|(n, v)| n == "expect" && v.eq_ignore_ascii_case("100-continue"));
    Ok(Head {
        method: method.to_owned(),
        path,
        headers,
        content_length: content_length.unwrap_or(0),
        keep_alive,
        expect_continue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head(text: &str) -> Result<Head, u16> {
        parse_head(text.as_bytes())
    }

    #[test]
    fn a_good_head_is_read() {
        let h = head("POST /access/v1/evaluation?x=1 HTTP/1.1\r\nHost: a\r\nContent-Length: 12\r\nX-Request-ID: abc").unwrap();
        assert_eq!(h.method, "POST");
        assert_eq!(h.path, "/access/v1/evaluation");
        assert_eq!(h.content_length, 12);
        assert!(h.keep_alive);
        assert!(
            h.headers
                .contains(&("x-request-id".to_owned(), "abc".to_owned()))
        );
    }

    #[test]
    fn keep_alive_follows_the_version_and_the_connection_header() {
        assert!(head("GET / HTTP/1.1\r\nHost: a").unwrap().keep_alive);
        assert!(
            !head("GET / HTTP/1.1\r\nConnection: close")
                .unwrap()
                .keep_alive
        );
        assert!(!head("GET / HTTP/1.0\r\nHost: a").unwrap().keep_alive);
        assert!(
            head("GET / HTTP/1.0\r\nConnection: Keep-Alive")
                .unwrap()
                .keep_alive
        );
    }

    #[test]
    fn a_bad_head_gets_a_status() {
        assert_eq!(head("GET /").err(), Some(400));
        assert_eq!(head("GET / HTTP/1.1 x").err(), Some(400));
        assert_eq!(head("GET x HTTP/1.1").err(), Some(400));
        assert_eq!(head("GET / HTTP/2.0").err(), Some(505));
        assert_eq!(head("GET / FTP/1.1").err(), Some(400));
        assert_eq!(head("GET / HTTP/1.1\r\nNoColon").err(), Some(400));
        assert_eq!(head("GET / HTTP/1.1\r\n folded: x").err(), Some(400));
        assert_eq!(head("GET / HTTP/1.1\r\nA B: x").err(), Some(400));
        assert_eq!(head("GET / HTTP/1.1\r\nA: x\u{1}y").err(), Some(400));
        assert_eq!(head("GE T / HTTP/1.1").err(), Some(400));
    }

    #[test]
    fn the_content_length_is_strict() {
        assert_eq!(
            head("POST / HTTP/1.1\r\nContent-Length: -1").err(),
            Some(400)
        );
        assert_eq!(
            head("POST / HTTP/1.1\r\nContent-Length: 1x").err(),
            Some(400)
        );
        assert_eq!(head("POST / HTTP/1.1\r\nContent-Length: ").err(), Some(400));
        assert_eq!(
            head("POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2").err(),
            Some(400)
        );
        assert!(head("POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2").is_ok());
    }

    #[test]
    fn a_chunked_body_is_not_implemented() {
        assert_eq!(
            head("POST / HTTP/1.1\r\nTransfer-Encoding: chunked").err(),
            Some(501)
        );
    }

    #[test]
    fn a_long_target_and_too_many_headers_get_a_status() {
        let long = format!("GET /{} HTTP/1.1", "a".repeat(MAX_TARGET_BYTES));
        assert_eq!(head(&long).err(), Some(414));
        let many: String = (0..=MAX_HEADERS).map(|i| format!("\r\nH{i}: v")).collect();
        assert_eq!(head(&format!("GET / HTTP/1.1{many}")).err(), Some(431));
    }

    #[test]
    fn an_error_response_gives_a_fixed_message() {
        let r = Response::error(400);
        assert_eq!(r.body, br#"{"error":"Bad Request"}"#);
    }
}
