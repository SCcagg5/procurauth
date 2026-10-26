//! A small HTTP/1.1 layer on the standard library.
//!
//! The client sends one request on one connection and reads the answer. It
//! speaks plain HTTP and does not follow a redirect. The server is for the
//! test listeners: the test PDP and the service behind an edge. It keeps a
//! connection open between requests, and it can hold a connection with no answer.

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The most bytes of the head of a message.
const MAX_HEAD: usize = 64 * 1024;
/// The most bytes of the body of a message.
const MAX_BODY: usize = 16 * 1024 * 1024;
/// The time that the server gives to read a request after its first byte.
const SERVER_READ: Duration = Duration::from_secs(10);

/// A header list. The names keep their case. A lookup ignores the case.
pub(crate) type Headers = Vec<(String, String)>;

/// The value of a header, in a list. When a name occurs more than one time, the values join with a comma.
pub(crate) fn header_value(headers: &[(String, String)], name: &str) -> Option<String> {
    let found: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
        .collect();
    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

/// A host and a port.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Authority {
    /// The host name or the address.
    pub(crate) host: String,
    /// The port.
    pub(crate) port: u16,
}

impl Authority {
    /// The text for the header `Host`.
    pub(crate) fn host_header(&self) -> String {
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
}

/// An `http` URL: an authority and a target (path and query).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpUrl {
    /// The host and the port.
    pub(crate) authority: Authority,
    /// The path with the query. It starts with a slash.
    pub(crate) target: String,
}

impl HttpUrl {
    /// Read an `http` URL.
    ///
    /// # Errors
    /// Returns a message that says what is wrong.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let lower = text.to_ascii_lowercase();
        if lower.starts_with("https://") {
            return Err(
                "the scheme https is not supported, because the tool has no TLS code; expected an http URL"
                    .to_owned(),
            );
        }
        if !lower.starts_with("http://") {
            return Err("expected a URL that starts with http://".to_owned());
        }
        let rest = &text["http://".len()..];
        if rest.contains('#') || rest.contains(char::is_whitespace) {
            return Err("expected a URL with no fragment and no space".to_owned());
        }
        let (authority, target) = match rest.find(['/', '?']) {
            Some(index) => (&rest[..index], &rest[index..]),
            None => (rest, "/"),
        };
        let target = if target.starts_with('?') {
            format!("/{target}")
        } else {
            target.to_owned()
        };
        if authority.is_empty() || authority.contains('@') {
            return Err("expected a host and an optional port, with no user".to_owned());
        }
        let (host, port) = split_authority(authority)?;
        Ok(Self {
            authority: Authority { host, port },
            target,
        })
    }
}

fn split_authority(text: &str) -> Result<(String, u16), String> {
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or_else(|| "expected a closing bracket after the IPv6 address".to_owned())?;
        match after {
            "" => (host.to_owned(), None),
            _ => match after.strip_prefix(':') {
                Some(port) => (host.to_owned(), Some(port)),
                None => return Err("expected a port after the IPv6 address".to_owned()),
            },
        }
    } else {
        match text.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port)),
            None => (text.to_owned(), None),
        }
    };
    if host.is_empty() {
        return Err("expected a host".to_owned());
    }
    let port = match port {
        None => 80,
        Some(text) => match text.parse::<u16>() {
            Ok(number) if number > 0 => number,
            _ => {
                return Err(format!("expected a port from 1 to 65535, found \"{text}\""));
            }
        },
    };
    Ok((host, port))
}

/// What a read of the socket did.
enum Fill {
    Data,
    Eof,
    Timeout,
}

/// A buffer over a stream.
struct Reader<'a> {
    stream: &'a mut TcpStream,
    buf: Vec<u8>,
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(stream: &'a mut TcpStream) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            pos: 0,
        }
    }

    fn pending(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    fn fill(&mut self, until: Instant, tick: Duration) -> io::Result<Fill> {
        let now = Instant::now();
        let left = until.saturating_duration_since(now);
        let wait = tick.min(left).max(Duration::from_millis(1));
        self.stream.set_read_timeout(Some(wait))?;
        let mut chunk = [0_u8; 8192];
        match self.stream.read(&mut chunk) {
            Ok(0) => Ok(Fill::Eof),
            Ok(n) => {
                if self.pos > 0 && self.pos == self.buf.len() {
                    self.buf.clear();
                    self.pos = 0;
                }
                self.buf.extend_from_slice(&chunk[..n]);
                Ok(Fill::Data)
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                Ok(Fill::Timeout)
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => Ok(Fill::Timeout),
            Err(e) => Err(e),
        }
    }

    /// Read until the buffer has at least `count` bytes.
    fn need(&mut self, count: usize, until: Instant) -> Result<(), String> {
        while self.pending().len() < count {
            if Instant::now() >= until {
                return Err("the read took too long".to_owned());
            }
            match self.fill(until, Duration::from_millis(200)) {
                Ok(Fill::Data | Fill::Timeout) => {}
                Ok(Fill::Eof) => return Err("the connection closed too early".to_owned()),
                Err(e) => return Err(format!("read error: {e}")),
            }
        }
        Ok(())
    }

    fn take(&mut self, count: usize) -> Vec<u8> {
        let out = self.buf[self.pos..self.pos + count].to_vec();
        self.pos += count;
        out
    }

    fn line(&mut self, until: Instant) -> Result<String, String> {
        loop {
            if let Some(at) = find(self.pending(), b"\r\n") {
                let line = self.take(at);
                self.pos += 2;
                return String::from_utf8(line).map_err(|_| "a line is not UTF-8".to_owned());
            }
            if self.pending().len() > MAX_HEAD {
                return Err("a line is too long".to_owned());
            }
            let have = self.pending().len();
            self.need(have + 1, until)?;
        }
    }

    /// Read the head: the start line and the headers.
    fn head(&mut self, until: Instant) -> Result<(String, Headers), String> {
        let start = self.line(until)?;
        let mut headers = Vec::new();
        loop {
            let line = self.line(until)?;
            if line.is_empty() {
                break;
            }
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| format!("a header line has no colon: {line}"))?;
            headers.push((name.trim().to_owned(), value.trim().to_owned()));
            if headers.len() > 512 {
                return Err("the message has too many headers".to_owned());
            }
        }
        Ok((start, headers))
    }

    fn body(
        &mut self,
        headers: &[(String, String)],
        until: Instant,
        to_eof: bool,
    ) -> Result<Vec<u8>, String> {
        let chunked = header_value(headers, "transfer-encoding")
            .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"));
        if chunked {
            let mut body = Vec::new();
            loop {
                let line = self.line(until)?;
                let size_text = line.split(';').next().unwrap_or("").trim();
                let size = usize::from_str_radix(size_text, 16)
                    .map_err(|_| format!("a chunk size is not valid: {size_text}"))?;
                if size == 0 {
                    loop {
                        if self.line(until)?.is_empty() {
                            break;
                        }
                    }
                    return Ok(body);
                }
                if body.len() + size > MAX_BODY {
                    return Err("the body is too large".to_owned());
                }
                self.need(size + 2, until)?;
                body.extend(self.take(size));
                self.pos += 2;
            }
        }
        if let Some(length) = header_value(headers, "content-length") {
            let size: usize = length
                .trim()
                .parse()
                .map_err(|_| format!("Content-Length is not valid: {length}"))?;
            if size > MAX_BODY {
                return Err("the body is too large".to_owned());
            }
            self.need(size, until)?;
            return Ok(self.take(size));
        }
        if to_eof {
            loop {
                if self.pending().len() > MAX_BODY {
                    return Err("the body is too large".to_owned());
                }
                if Instant::now() >= until {
                    return Err("the read took too long".to_owned());
                }
                match self.fill(until, Duration::from_millis(200)) {
                    Ok(Fill::Data | Fill::Timeout) => {}
                    Ok(Fill::Eof) => break,
                    Err(e) => return Err(format!("read error: {e}")),
                }
            }
            let rest = self.pending().len();
            return Ok(self.take(rest));
        }
        Ok(Vec::new())
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A request that the client sends.
#[derive(Clone, Debug)]
pub(crate) struct ClientRequest {
    /// The method.
    pub(crate) method: String,
    /// The path with the query.
    pub(crate) target: String,
    /// The headers.
    pub(crate) headers: Headers,
    /// The body.
    pub(crate) body: Option<Vec<u8>>,
}

/// An answer that the client reads.
#[derive(Clone, Debug)]
pub(crate) struct Reply {
    /// The HTTP status.
    pub(crate) status: u16,
    /// The headers.
    pub(crate) headers: Headers,
    /// The body.
    pub(crate) body: Vec<u8>,
}

impl Reply {
    /// The body as text.
    pub(crate) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The value of a header.
    pub(crate) fn header(&self, name: &str) -> Option<String> {
        header_value(&self.headers, name)
    }
}

/// Connect to a host and a port, within the time that is left.
///
/// # Errors
/// Returns a message when the name does not resolve or the connection fails.
pub(crate) fn connect(authority: &Authority, until: Instant) -> Result<TcpStream, String> {
    let addrs: Vec<SocketAddr> = (authority.host.as_str(), authority.port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot resolve {}: {e}", authority.host_header()))?
        .collect();
    let mut last = format!("no address for {}", authority.host_header());
    for addr in addrs {
        let left = until.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("the connection took too long".to_owned());
        }
        match TcpStream::connect_timeout(&addr, left) {
            Ok(stream) => return Ok(stream),
            Err(e) => last = format!("cannot connect to {addr}: {e}"),
        }
    }
    Err(last)
}

/// Send one request and read the answer. The connection closes after the answer.
///
/// # Errors
/// Returns a message when the connection fails, the answer is not valid HTTP, or the time ends.
pub(crate) fn send(
    authority: &Authority,
    request: &ClientRequest,
    until: Instant,
) -> Result<Reply, String> {
    let mut stream = connect(authority, until)?;
    let _ = stream.set_nodelay(true);
    let mut head = format!("{} {} HTTP/1.1\r\n", request.method, request.target);
    let has = |name: &str| {
        request
            .headers
            .iter()
            .any(|(n, _)| n.eq_ignore_ascii_case(name))
    };
    if !has("host") {
        head.push_str(&format!("Host: {}\r\n", authority.host_header()));
    }
    for (name, value) in &request.headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = &request.body
        && !has("content-length")
    {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    if !has("connection") {
        head.push_str("Connection: close\r\n");
    }
    head.push_str("\r\n");
    let mut bytes = head.into_bytes();
    if let Some(body) = &request.body {
        bytes.extend_from_slice(body);
    }
    let left = until.saturating_duration_since(Instant::now());
    stream
        .set_write_timeout(Some(left.max(Duration::from_millis(1))))
        .map_err(|e| format!("socket error: {e}"))?;
    stream
        .write_all(&bytes)
        .map_err(|e| format!("cannot send the request: {e}"))?;
    let mut reader = Reader::new(&mut stream);
    let (start, headers) = reader
        .head(until)
        .map_err(|e| format!("cannot read the answer: {e}"))?;
    let mut parts = start.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let status: u16 = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("the status line is not valid: {start}"))?;
    if !version.starts_with("HTTP/1.") {
        return Err(format!("the status line is not valid: {start}"));
    }
    let no_body =
        request.method == "HEAD" || status == 204 || status == 304 || (100..200).contains(&status);
    let body = if no_body {
        Vec::new()
    } else {
        reader
            .body(&headers, until, true)
            .map_err(|e| format!("cannot read the answer: {e}"))?
    };
    Ok(Reply {
        status,
        headers,
        body,
    })
}

/// A request that the server reads.
#[derive(Clone, Debug)]
pub(crate) struct Request {
    /// The method.
    pub(crate) method: String,
    /// The path, with no query.
    pub(crate) path: String,
    /// The path with the query, as the client wrote it.
    pub(crate) target: String,
    /// The headers.
    pub(crate) headers: Headers,
    /// The body.
    pub(crate) body: Vec<u8>,
    /// The number of the connection that carried the request.
    pub(crate) connection: usize,
}

impl Request {
    /// The value of a header.
    pub(crate) fn header(&self, name: &str) -> Option<String> {
        header_value(&self.headers, name)
    }
}

/// An answer that the server sends.
#[derive(Clone, Debug)]
pub(crate) struct Response {
    /// The status.
    pub(crate) status: u16,
    /// More headers than `Content-Length`.
    pub(crate) headers: Headers,
    /// The body.
    pub(crate) body: Vec<u8>,
}

impl Response {
    /// A JSON answer.
    pub(crate) fn json(status: u16, value: &Value) -> Self {
        Self {
            status,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: value.to_string().into_bytes(),
        }
    }

    /// An answer with an error status and a fixed JSON body.
    pub(crate) fn error(status: u16, message: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": message }))
    }
}

fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

/// What a handler does with a request.
pub(crate) enum Outcome {
    /// Send this answer.
    Respond(Response),
    /// Send nothing, and keep the connection open until the case ends.
    Hold,
}

/// The code that answers the requests of a test listener.
pub(crate) trait Handler: Send + Sync + 'static {
    /// Answer one request.
    fn handle(&self, request: &Request) -> Outcome;
}

struct Shared {
    stop: AtomicBool,
    next_connection: AtomicUsize,
    generation: AtomicU64,
}

/// A test listener on one address.
pub(crate) struct HttpServer {
    #[cfg_attr(not(test), allow(dead_code))]
    addr: SocketAddr,
    shared: Arc<Shared>,
    accept: Option<JoinHandle<()>>,
}

impl HttpServer {
    /// Bind the address and start to serve.
    ///
    /// # Errors
    /// Returns a message when the address cannot open.
    pub(crate) fn start(addr: SocketAddr, handler: Arc<dyn Handler>) -> Result<Self, String> {
        let listener =
            TcpListener::bind(addr).map_err(|e| format!("cannot listen on {addr}: {e}"))?;
        listener
            .set_nonblocking(true)
            .map_err(|e| format!("cannot set up the listener on {addr}: {e}"))?;
        let local = listener
            .local_addr()
            .map_err(|e| format!("cannot read the address of the listener: {e}"))?;
        let shared = Arc::new(Shared {
            stop: AtomicBool::new(false),
            next_connection: AtomicUsize::new(0),
            generation: AtomicU64::new(0),
        });
        let loop_shared = Arc::clone(&shared);
        let accept = thread::spawn(move || {
            while !loop_shared.stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let id = loop_shared.next_connection.fetch_add(1, Ordering::SeqCst) + 1;
                        let shared = Arc::clone(&loop_shared);
                        let handler = Arc::clone(&handler);
                        thread::spawn(move || serve(stream, id, &shared, handler.as_ref()));
                    }
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(20)),
                }
            }
        });
        Ok(Self {
            addr: local,
            shared,
            accept: Some(accept),
        })
    }

    /// The address of the listener.
    #[cfg(test)]
    pub(crate) fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    /// Close the connections that the handler holds.
    pub(crate) fn release_held(&self) {
        self.shared.generation.fetch_add(1, Ordering::SeqCst);
    }

    /// Stop the listener.
    pub(crate) fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        self.shared.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        self.stop();
    }
}

fn serve(mut stream: TcpStream, connection: usize, shared: &Shared, handler: &dyn Handler) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_nonblocking(false);
    let mut reader = Reader::new(&mut stream);
    loop {
        // Wait for the first byte of a request.
        while reader.pending().is_empty() {
            if shared.stop.load(Ordering::SeqCst) {
                return;
            }
            match reader.fill(
                Instant::now() + Duration::from_secs(3600),
                Duration::from_millis(50),
            ) {
                Ok(Fill::Data | Fill::Timeout) => {}
                Ok(Fill::Eof) | Err(_) => return,
            }
        }
        let until = Instant::now() + SERVER_READ;
        let Ok((start, headers)) = reader.head(until) else {
            return;
        };
        let mut parts = start.split(' ');
        let (Some(method), Some(target)) = (parts.next(), parts.next()) else {
            return;
        };
        let Ok(body) = reader.body(&headers, until, false) else {
            return;
        };
        let path = target.split('?').next().unwrap_or(target).to_owned();
        let request = Request {
            method: method.to_owned(),
            path,
            target: target.to_owned(),
            headers,
            body,
            connection,
        };
        let generation = shared.generation.load(Ordering::SeqCst);
        let close = request
            .header("connection")
            .is_some_and(|v| v.to_ascii_lowercase().contains("close"))
            || start.ends_with("HTTP/1.0");
        match handler.handle(&request) {
            Outcome::Respond(response) => {
                let mut head = format!(
                    "HTTP/1.1 {} {}\r\n",
                    response.status,
                    reason(response.status)
                );
                for (name, value) in &response.headers {
                    head.push_str(&format!("{name}: {value}\r\n"));
                }
                head.push_str(&format!("Content-Length: {}\r\n\r\n", response.body.len()));
                let mut bytes = head.into_bytes();
                bytes.extend_from_slice(&response.body);
                if reader.stream.write_all(&bytes).is_err() {
                    return;
                }
                if close {
                    return;
                }
            }
            Outcome::Hold => loop {
                if shared.stop.load(Ordering::SeqCst)
                    || shared.generation.load(Ordering::SeqCst) != generation
                {
                    return;
                }
                match reader.fill(
                    Instant::now() + Duration::from_secs(3600),
                    Duration::from_millis(20),
                ) {
                    Ok(Fill::Data | Fill::Timeout) => {}
                    Ok(Fill::Eof) | Err(_) => return,
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Echo;

    impl Handler for Echo {
        fn handle(&self, request: &Request) -> Outcome {
            match request.path.as_str() {
                "/hold" => Outcome::Hold,
                _ => Outcome::Respond(Response::json(
                    200,
                    &serde_json::json!({
                        "method": request.method,
                        "target": request.target,
                        "body": String::from_utf8_lossy(&request.body),
                        "x": request.header("x-test"),
                        "connection": request.connection,
                    }),
                )),
            }
        }
    }

    fn start() -> HttpServer {
        HttpServer::start("127.0.0.1:0".parse().unwrap(), Arc::new(Echo)).unwrap()
    }

    fn authority(server: &HttpServer) -> Authority {
        Authority {
            host: "127.0.0.1".to_owned(),
            port: server.local_addr().port(),
        }
    }

    fn request(method: &str, target: &str, body: Option<&str>) -> ClientRequest {
        ClientRequest {
            method: method.to_owned(),
            target: target.to_owned(),
            headers: vec![("X-Test".to_owned(), "yes".to_owned())],
            body: body.map(|b| b.as_bytes().to_vec()),
        }
    }

    #[test]
    fn the_client_and_the_server_exchange_a_request() {
        let server = start();
        let reply = send(
            &authority(&server),
            &request("POST", "/a?b=1", Some("hello")),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(reply.status, 200);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["method"], "POST");
        assert_eq!(body["target"], "/a?b=1");
        assert_eq!(body["body"], "hello");
        assert_eq!(body["x"], "yes");
        assert_eq!(
            reply.header("content-type").as_deref(),
            Some("application/json")
        );
        server.shutdown();
    }

    #[test]
    fn a_held_connection_gets_no_answer_and_the_client_times_out() {
        let server = start();
        let started = Instant::now();
        let result = send(
            &authority(&server),
            &request("GET", "/hold", None),
            Instant::now() + Duration::from_millis(300),
        );
        assert!(result.is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
        server.release_held();
        server.shutdown();
    }

    #[test]
    fn a_connection_stays_open_between_requests() {
        let server = start();
        let addr = server.local_addr();
        let mut stream = TcpStream::connect(addr).unwrap();
        let mut numbers = Vec::new();
        for _ in 0..3 {
            stream
                .write_all(b"GET /one HTTP/1.1\r\nHost: x\r\n\r\n")
                .unwrap();
            let mut reader = Reader::new(&mut stream);
            let until = Instant::now() + Duration::from_secs(5);
            let (start_line, headers) = reader.head(until).unwrap();
            assert!(start_line.starts_with("HTTP/1.1 200"));
            let body = reader.body(&headers, until, false).unwrap();
            let seen: Value = serde_json::from_slice(&body).unwrap();
            numbers.push(seen["connection"].as_u64().unwrap());
        }
        // The three requests have the same connection number.
        assert!(numbers.iter().all(|n| *n == numbers[0]), "{numbers:?}");
        server.shutdown();
    }

    #[test]
    fn a_chunked_answer_is_read() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
                .unwrap();
        });
        let reply = send(
            &Authority {
                host: "127.0.0.1".to_owned(),
                port,
            },
            &request("GET", "/", None),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(reply.text(), "abcde");
        handle.join().unwrap();
    }

    #[test]
    fn an_answer_with_no_length_ends_at_the_close() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 1024];
            let _ = stream.read(&mut buf).unwrap();
            stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Bearer\r\n\r\n")
                .unwrap();
        });
        let reply = send(
            &Authority {
                host: "127.0.0.1".to_owned(),
                port,
            },
            &request("GET", "/", None),
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        assert_eq!(reply.status, 401);
        assert_eq!(reply.text(), "");
        assert_eq!(reply.header("www-authenticate").as_deref(), Some("Bearer"));
        handle.join().unwrap();
    }

    #[test]
    fn an_http_url_has_a_host_a_port_and_a_target() {
        let url = HttpUrl::parse("http://127.0.0.1:8000").unwrap();
        assert_eq!(url.authority.host, "127.0.0.1");
        assert_eq!(url.authority.port, 8000);
        assert_eq!(url.target, "/");
        let url = HttpUrl::parse("http://example.org/x/y?z=1").unwrap();
        assert_eq!(url.authority.port, 80);
        assert_eq!(url.target, "/x/y?z=1");
        let url = HttpUrl::parse("http://[::1]:9/a").unwrap();
        assert_eq!(url.authority.host, "::1");
        assert_eq!(url.authority.host_header(), "[::1]:9");
        assert!(HttpUrl::parse("https://x").is_err());
        assert!(HttpUrl::parse("ftp://x").is_err());
        assert!(HttpUrl::parse("http://").is_err());
        assert!(HttpUrl::parse("http://host:0").is_err());
        assert!(HttpUrl::parse("http://host:99999").is_err());
        assert!(HttpUrl::parse("http://user@host").is_err());
    }

    #[test]
    fn a_header_that_occurs_twice_joins_with_a_comma() {
        let headers = vec![
            ("A".to_owned(), "1".to_owned()),
            ("a".to_owned(), "2".to_owned()),
        ];
        assert_eq!(header_value(&headers, "A").as_deref(), Some("1, 2"));
        assert_eq!(header_value(&headers, "b"), None);
    }
}
