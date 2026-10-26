//! A synchronous HTTP/1.1 client over `std::net`, for `http` URLs.
//!
//! This client has no TLS. A deployment needs a secured link to the PDP
//! (10.0, step 4). Use this client for tests on the loopback address, or
//! for a link that another layer secures. For `https`, implement
//! [`PdpTransport`] with a TLS client.
//!
//! # Connections (10.7)
//!
//! The client keeps its connections open between requests. It keeps a small
//! fixed number of connections at most. A request that finds no free connection
//! waits for one until its timeout. The client closes an idle connection when
//! it is older than the idle time that [`PdpTransport::set_idle_close`] gives.
//! It makes this check at each use of the pool. Before the client reuses a
//! connection, it checks that the PDP did not close it.
//!
//! # Failures (10.6)
//!
//! A failure before the first byte of the request is [`TransportError::NotSent`].
//! A failure after it is [`TransportError::Lost`] or [`TransportError::Timeout`].

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::config::PdpConfig;
use crate::transport::{HttpResponse, PdpTransport, TransportError};
use crate::url::{Scheme, Url};

/// The largest head of an answer: the status line and the headers.
const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The most headers in one answer.
const MAX_HEADERS: usize = 100;

/// The bounds of the client.
#[derive(Clone, Copy, Debug)]
pub struct HttpTransportConfig {
    /// The most connections at one time. The value is a small fixed number (10.7).
    pub max_connections: usize,
    /// The longest wait for a new connection.
    pub connect_timeout: Duration,
    /// The longest idle time of a connection, until the PEP gives another value.
    pub idle_close_after: Duration,
    /// The largest body that the client reads, in bytes.
    pub max_response_bytes: u64,
}

impl HttpTransportConfig {
    /// The bounds that the configuration of the link gives. The wait for a
    /// new connection is the request timeout.
    pub fn from_pdp(pdp: &PdpConfig) -> Self {
        Self {
            max_connections: pdp.max_connections,
            connect_timeout: pdp.request_timeout,
            idle_close_after: pdp.idle_close_after,
            max_response_bytes: pdp.max_response_bytes,
        }
    }
}

struct Conn {
    stream: TcpStream,
    authority: String,
    last_used: Instant,
}

#[derive(Default)]
struct Pool {
    idle: Vec<Conn>,
    /// The connections that exist: the idle ones and the ones in use.
    open: usize,
}

/// A synchronous HTTP/1.1 client with a small pool of connections.
pub struct HttpTransport {
    config: HttpTransportConfig,
    idle_close_millis: AtomicU64,
    pool: Mutex<Pool>,
    freed: Condvar,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

/// A connection that the pool lent. It goes back to the pool, or it is closed.
struct Lent<'a> {
    transport: &'a HttpTransport,
    conn: Option<Conn>,
}

impl Lent<'_> {
    fn stream(&mut self) -> Result<&mut TcpStream, TransportError> {
        self.conn
            .as_mut()
            .map(|c| &mut c.stream)
            .ok_or_else(|| TransportError::Lost("the connection is gone".to_owned()))
    }

    fn give_back(mut self) {
        if let Some(mut conn) = self.conn.take() {
            conn.last_used = Instant::now();
            let mut pool = self.transport.lock();
            pool.idle.push(conn);
            drop(pool);
            self.transport.freed.notify_one();
        }
    }
}

impl Drop for Lent<'_> {
    fn drop(&mut self) {
        if self.conn.take().is_some() {
            let mut pool = self.transport.lock();
            pool.open = pool.open.saturating_sub(1);
            drop(pool);
            self.transport.freed.notify_one();
        }
    }
}

impl HttpTransport {
    /// A client with these bounds.
    pub fn new(config: HttpTransportConfig) -> Self {
        Self {
            idle_close_millis: AtomicU64::new(
                u64::try_from(config.idle_close_after.as_millis()).unwrap_or(u64::MAX),
            ),
            config,
            pool: Mutex::new(Pool::default()),
            freed: Condvar::new(),
        }
    }

    /// The number of connections that exist now, idle or in use.
    pub fn open_connections(&self) -> usize {
        self.lock().open
    }

    fn lock(&self) -> MutexGuard<'_, Pool> {
        self.pool.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn idle_close(&self) -> Duration {
        Duration::from_millis(self.idle_close_millis.load(Ordering::SeqCst))
    }

    /// Close the idle connections that are too old.
    fn sweep(&self, pool: &mut Pool) {
        let limit = self.idle_close();
        let before = pool.idle.len();
        pool.idle.retain(|c| c.last_used.elapsed() < limit);
        pool.open = pool.open.saturating_sub(before - pool.idle.len());
    }

    fn checkout(&self, url: &Url, deadline: Instant) -> Result<Lent<'_>, TransportError> {
        let authority = url.authority();
        let mut pool = self.lock();
        loop {
            self.sweep(&mut pool);
            // Take the connection that was used last: the others age and close.
            if let Some(index) = pool.idle.iter().rposition(|c| c.authority == authority) {
                let conn = pool.idle.remove(index);
                if is_alive(&conn.stream) {
                    return Ok(Lent {
                        transport: self,
                        conn: Some(conn),
                    });
                }
                pool.open = pool.open.saturating_sub(1);
                continue;
            }
            if pool.open < self.config.max_connections {
                pool.open += 1;
                drop(pool);
                let remaining = deadline.saturating_duration_since(Instant::now());
                let wait = self.config.connect_timeout.min(remaining);
                return match connect(&authority, wait) {
                    Ok(stream) => Ok(Lent {
                        transport: self,
                        conn: Some(Conn {
                            stream,
                            authority,
                            last_used: Instant::now(),
                        }),
                    }),
                    Err(error) => {
                        let mut pool = self.lock();
                        pool.open = pool.open.saturating_sub(1);
                        drop(pool);
                        self.freed.notify_one();
                        Err(TransportError::NotSent(format!(
                            "no connection to {authority}: {error}"
                        )))
                    }
                };
            }
            // The pool is full. Close the oldest idle connection of another origin, or wait.
            if !pool.idle.is_empty() {
                pool.idle.remove(0);
                pool.open = pool.open.saturating_sub(1);
                continue;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::NotSent(
                    "no free connection before the time ran out".to_owned(),
                ));
            }
            pool = self
                .freed
                .wait_timeout(pool, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
        }
    }

    fn exchange(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        let url = Url::parse(url).map_err(|e| TransportError::Unsupported(e.to_string()))?;
        if url.scheme != Scheme::Http {
            return Err(TransportError::Unsupported(
                "this client has no TLS: give it an `http` URL, or use a transport with TLS"
                    .to_owned(),
            ));
        }
        let head = build_head(
            method,
            &url,
            headers,
            body.map_or(0, <[u8]>::len),
            body.is_some(),
        )?;
        let deadline = Instant::now() + timeout;
        let mut lent = self.checkout(&url, deadline)?;
        let mut request = head;
        if let Some(body) = body {
            request.extend_from_slice(body);
        }
        write_all(lent.stream()?, &request, deadline)?;
        let (response, reusable) =
            read_response(lent.stream()?, deadline, self.config.max_response_bytes)?;
        if reusable {
            lent.give_back();
        }
        Ok(response)
    }
}

impl PdpTransport for HttpTransport {
    fn supports_scheme(&self, scheme: &str) -> bool {
        scheme == "http"
    }

    fn post_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        self.exchange("POST", url, headers, Some(body), timeout)
    }

    fn get_json(
        &self,
        url: &str,
        headers: &[(String, String)],
        timeout: Duration,
    ) -> Result<HttpResponse, TransportError> {
        self.exchange("GET", url, headers, None, timeout)
    }

    fn set_idle_close(&self, idle_close_after: Duration) {
        self.idle_close_millis.store(
            u64::try_from(idle_close_after.as_millis()).unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
    }
}

fn connect(authority: &str, wait: Duration) -> std::io::Result<TcpStream> {
    let wait = wait.max(Duration::from_millis(1));
    let mut last = std::io::Error::new(ErrorKind::NotFound, "the name has no address");
    for address in authority.to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, wait) {
            Ok(stream) => {
                let _ = stream.set_nodelay(true);
                return Ok(stream);
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

/// True when the PDP has not closed the connection, and no stray byte waits on it.
fn is_alive(stream: &TcpStream) -> bool {
    if stream.set_nonblocking(true).is_err() {
        return false;
    }
    let mut byte = [0_u8; 1];
    let alive = matches!(stream.peek(&mut byte), Err(e) if e.kind() == ErrorKind::WouldBlock);
    alive && stream.set_nonblocking(false).is_ok()
}

fn bad_header(name: &str, value: &str) -> bool {
    name.is_empty()
        || name
            .bytes()
            .any(|b| !(0x21..0x7f).contains(&b) || b == b':')
        || value.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0)
}

fn build_head(
    method: &str,
    url: &Url,
    headers: &[(String, String)],
    body_len: usize,
    has_body: bool,
) -> Result<Vec<u8>, TransportError> {
    let path = if url.path.is_empty() {
        "/"
    } else {
        url.path.as_str()
    };
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\nHost: {}\r\nUser-Agent: procurauth-pep\r\nAccept: application/json\r\n",
        url.host_header()
    );
    if has_body {
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {body_len}\r\n"));
    }
    for (name, value) in headers {
        if bad_header(name, value) {
            return Err(TransportError::NotSent(format!(
                "the header `{name}` has a character that a header must not have"
            )));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    Ok(head.into_bytes())
}

/// Write the whole request. A failure before the first byte is `NotSent`.
fn write_all(stream: &mut TcpStream, data: &[u8], deadline: Instant) -> Result<(), TransportError> {
    let mut written = 0;
    while written < data.len() {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(failure_after_write(written, TransportError::Timeout));
        }
        let _ = stream.set_write_timeout(Some(remaining));
        match stream.write(&data[written..]) {
            Ok(0) => {
                return Err(failure_after_write(
                    written,
                    TransportError::Lost("the connection accepts no byte".to_owned()),
                ));
            }
            Ok(n) => written += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(failure_after_write(written, TransportError::Timeout));
            }
            Err(e) => {
                return Err(failure_after_write(
                    written,
                    TransportError::Lost(e.to_string()),
                ));
            }
        }
    }
    let _ = stream.flush();
    Ok(())
}

fn failure_after_write(written: usize, error: TransportError) -> TransportError {
    if written == 0 {
        TransportError::NotSent(format!("the first write failed: {error}"))
    } else {
        error
    }
}

/// A reader of the answer, with a deadline.
struct Reader<'a> {
    stream: &'a mut TcpStream,
    buf: Vec<u8>,
    pos: usize,
    deadline: Instant,
}

impl Reader<'_> {
    /// Read more bytes into the buffer. Returns the number of bytes, 0 at the end.
    fn fill(&mut self) -> Result<usize, TransportError> {
        let mut chunk = [0_u8; 8192];
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(TransportError::Timeout);
            }
            let _ = self.stream.set_read_timeout(Some(remaining));
            match self.stream.read(&mut chunk) {
                Ok(n) => {
                    if self.pos > 0 && self.pos == self.buf.len() {
                        self.buf.clear();
                        self.pos = 0;
                    }
                    self.buf.extend_from_slice(&chunk[..n]);
                    return Ok(n);
                }
                Err(e) if e.kind() == ErrorKind::Interrupted => {}
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    return Err(TransportError::Timeout);
                }
                Err(e) => return Err(TransportError::Lost(e.to_string())),
            }
        }
    }

    fn available(&self) -> &[u8] {
        &self.buf[self.pos..]
    }

    /// Read one line that ends with CRLF. The line has no end marker.
    fn line(&mut self, max: usize) -> Result<Vec<u8>, TransportError> {
        loop {
            if let Some(end) = find(self.available(), b"\r\n") {
                let line = self.available()[..end].to_vec();
                self.pos += end + 2;
                return Ok(line);
            }
            if self.available().len() > max {
                return Err(TransportError::Malformed("a line is too long".to_owned()));
            }
            if self.fill()? == 0 {
                return Err(TransportError::Lost(
                    "the PDP closed the connection in an answer".to_owned(),
                ));
            }
        }
    }

    fn take(&mut self, count: usize, out: &mut Vec<u8>) -> Result<(), TransportError> {
        let mut left = count;
        while left > 0 {
            if self.available().is_empty() && self.fill()? == 0 {
                return Err(TransportError::Lost(
                    "the PDP closed the connection in the body".to_owned(),
                ));
            }
            let part = left.min(self.available().len());
            out.extend_from_slice(&self.available()[..part]);
            self.pos += part;
            left -= part;
        }
        Ok(())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn malformed(text: &str) -> TransportError {
    TransportError::Malformed(text.to_owned())
}

fn header_values<'a>(
    headers: &'a [(String, String)],
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    headers
        .iter()
        .filter(move |(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// Read one answer. The second value is true when the connection can serve another request.
fn read_response(
    stream: &mut TcpStream,
    deadline: Instant,
    max_body: u64,
) -> Result<(HttpResponse, bool), TransportError> {
    let mut reader = Reader {
        stream,
        buf: Vec::new(),
        pos: 0,
        deadline,
    };
    // The head. A connection that closes before the first byte is a lost connection.
    let status_line = match reader.line(MAX_HEAD_BYTES) {
        Err(TransportError::Lost(_)) if reader.buf.is_empty() => {
            return Err(TransportError::Lost(
                "the PDP closed the connection before it answered".to_owned(),
            ));
        }
        other => other?,
    };
    let status_text = String::from_utf8_lossy(&status_line).into_owned();
    let mut parts = status_text.splitn(3, ' ');
    let version = parts.next().unwrap_or("");
    let code = parts.next().unwrap_or("");
    if version != "HTTP/1.1" && version != "HTTP/1.0" {
        return Err(malformed("the status line has no HTTP/1.x version"));
    }
    let status: u16 = match code.parse() {
        Ok(s) if code.len() == 3 && (200..600).contains(&s) => s,
        _ => return Err(malformed("the status code is not a number from 200 to 599")),
    };
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut head_bytes = status_line.len();
    loop {
        let line = reader.line(MAX_HEAD_BYTES)?;
        if line.is_empty() {
            break;
        }
        head_bytes += line.len();
        if head_bytes > MAX_HEAD_BYTES || headers.len() >= MAX_HEADERS {
            return Err(malformed("the head of the answer is too large"));
        }
        if line[0] == b' ' || line[0] == b'\t' {
            return Err(malformed("a header line is folded"));
        }
        let text = String::from_utf8_lossy(&line).into_owned();
        let (name, value) = text
            .split_once(':')
            .ok_or_else(|| malformed("a header line has no colon"))?;
        if name.is_empty() || name.bytes().any(|b| !(0x21..0x7f).contains(&b)) {
            return Err(malformed("a header name is not valid"));
        }
        headers.push((name.to_owned(), value.trim().to_owned()));
    }
    let close = header_values(&headers, "connection")
        .any(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));
    let keep_alive_10 = header_values(&headers, "connection").any(|v| {
        v.split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("keep-alive"))
    });
    let mut reusable = if version == "HTTP/1.1" {
        !close
    } else {
        keep_alive_10 && !close
    };

    let chunked: Vec<&str> = header_values(&headers, "transfer-encoding").collect();
    let lengths: Vec<&str> = header_values(&headers, "content-length").collect();
    let mut body = Vec::new();
    if !chunked.is_empty() {
        if !lengths.is_empty() || chunked.len() != 1 || !chunked[0].eq_ignore_ascii_case("chunked")
        {
            return Err(malformed("the answer has an unsupported transfer coding"));
        }
        read_chunked(&mut reader, &mut body, max_body)?;
    } else if !lengths.is_empty() {
        let first = lengths[0];
        if lengths.iter().any(|l| *l != first)
            || first.is_empty()
            || !first.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(malformed("the header `Content-Length` is not valid"));
        }
        let length: u64 = first
            .parse()
            .map_err(|_| malformed("the header `Content-Length` is too large"))?;
        if length > max_body {
            return Err(TransportError::TooLarge);
        }
        let length = usize::try_from(length).map_err(|_| TransportError::TooLarge)?;
        reader.take(length, &mut body)?;
    } else if status == 204 || status == 304 {
        // No body.
    } else {
        // The body ends when the PDP closes the connection.
        reusable = false;
        loop {
            let available = reader.available().len();
            if u64::try_from(body.len() + available).unwrap_or(u64::MAX) > max_body {
                return Err(TransportError::TooLarge);
            }
            body.extend_from_slice(reader.available());
            reader.pos = reader.buf.len();
            if reader.fill()? == 0 {
                break;
            }
        }
    }
    if !reader.available().is_empty() {
        // A stray byte after the answer: do not reuse this connection.
        reusable = false;
    }
    Ok((
        HttpResponse {
            status,
            headers,
            body,
        },
        reusable,
    ))
}

fn read_chunked(
    reader: &mut Reader<'_>,
    body: &mut Vec<u8>,
    max_body: u64,
) -> Result<(), TransportError> {
    loop {
        let line = reader.line(1024)?;
        let text = String::from_utf8_lossy(&line).into_owned();
        let size_text = text.split(';').next().unwrap_or("").trim();
        if size_text.is_empty() || !size_text.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(malformed("a chunk size is not valid"));
        }
        let size = u64::from_str_radix(size_text, 16)
            .map_err(|_| malformed("a chunk size is too large"))?;
        if size == 0 {
            // The trailers end with an empty line.
            loop {
                if reader.line(MAX_HEAD_BYTES)?.is_empty() {
                    return Ok(());
                }
            }
        }
        if u64::try_from(body.len())
            .unwrap_or(u64::MAX)
            .saturating_add(size)
            > max_body
        {
            return Err(TransportError::TooLarge);
        }
        let size = usize::try_from(size).map_err(|_| TransportError::TooLarge)?;
        reader.take(size, body)?;
        if !reader.line(2)?.is_empty() {
            return Err(malformed("a chunk has no end marker"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::AtomicUsize;
    use std::thread;

    /// A test server. A script function decides what each connection does.
    struct Server {
        url: String,
        accepted: Arc<AtomicUsize>,
    }

    fn read_request(stream: &mut TcpStream) -> Option<Vec<u8>> {
        let mut data = Vec::new();
        let mut chunk = [0_u8; 1024];
        loop {
            if let Some(end) = find(&data, b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&data[..end]).to_lowercase();
                let length = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if data.len() >= end + 4 + length {
                    return Some(data);
                }
            }
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => return None,
                Ok(n) => data.extend_from_slice(&chunk[..n]),
            }
        }
    }

    fn serve<F>(script: F) -> Server
    where
        F: Fn(&mut TcpStream, usize) + Send + Sync + 'static,
    {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let script = Arc::new(script);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let n = count.fetch_add(1, Ordering::SeqCst) + 1;
                let script = Arc::clone(&script);
                thread::spawn(move || script(&mut stream, n));
            }
        });
        Server { url, accepted }
    }

    fn ok_script(stream: &mut TcpStream, _n: usize) {
        while read_request(stream).is_some() {
            let body = br#"{"ok":true}"#;
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            if stream.write_all(head.as_bytes()).is_err() || stream.write_all(body).is_err() {
                return;
            }
        }
    }

    fn client(max: usize) -> HttpTransport {
        HttpTransport::new(HttpTransportConfig {
            max_connections: max,
            connect_timeout: Duration::from_secs(2),
            idle_close_after: Duration::from_secs(30),
            max_response_bytes: 4096,
        })
    }

    const WAIT: Duration = Duration::from_secs(3);

    #[test]
    fn a_post_gets_the_status_the_headers_and_the_body() {
        let server = serve(ok_script);
        let t = client(2);
        let url = format!("{}/x", server.url);
        let reply = t
            .post_json(
                &url,
                &[("Authorization".into(), "Bearer abc".into())],
                b"{}",
                WAIT,
            )
            .unwrap();
        assert_eq!(reply.status, 200);
        assert_eq!(reply.body, br#"{"ok":true}"#);
        assert!(reply.headers.iter().any(|(n, _)| n == "Content-Type"));
    }

    #[test]
    fn p_10_7_the_client_reuses_one_connection_for_requests_one_after_the_other() {
        let server = serve(ok_script);
        let t = client(2);
        for _ in 0..4 {
            t.get_json(&format!("{}/a", server.url), &[], WAIT).unwrap();
        }
        assert_eq!(server.accepted.load(Ordering::SeqCst), 1);
        assert_eq!(t.open_connections(), 1);
    }

    #[test]
    fn p_10_7_the_client_never_opens_more_connections_than_its_bound() {
        let server = serve(|stream, _| {
            while read_request(stream).is_some() {
                thread::sleep(Duration::from_millis(100));
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            }
        });
        let t = Arc::new(client(2));
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let t = Arc::clone(&t);
                let url = format!("{}/a", server.url);
                thread::spawn(move || t.get_json(&url, &[], WAIT).unwrap().status)
            })
            .collect();
        for h in handles {
            assert_eq!(h.join().unwrap(), 200);
        }
        assert!(server.accepted.load(Ordering::SeqCst) <= 2);
        assert!(t.open_connections() <= 2);
    }

    #[test]
    fn p_10_7_a_connection_that_the_pdp_closed_is_not_reused() {
        let server = serve(|stream, _| {
            if read_request(stream).is_some() {
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            }
            // The server closes the connection after one answer, with no `Connection: close`.
        });
        let t = client(2);
        let url = format!("{}/a", server.url);
        assert_eq!(t.get_json(&url, &[], WAIT).unwrap().status, 200);
        thread::sleep(Duration::from_millis(100));
        assert_eq!(t.get_json(&url, &[], WAIT).unwrap().status, 200);
        assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn p_10_7_an_idle_connection_closes_after_the_idle_time() {
        let server = serve(ok_script);
        let t = client(2);
        t.set_idle_close(Duration::from_millis(50));
        let url = format!("{}/a", server.url);
        t.get_json(&url, &[], WAIT).unwrap();
        thread::sleep(Duration::from_millis(120));
        t.get_json(&url, &[], WAIT).unwrap();
        assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_connection_close_header_stops_the_reuse() {
        let server = serve(|stream, _| {
            if read_request(stream).is_some() {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}",
                );
            }
        });
        let t = client(2);
        let url = format!("{}/a", server.url);
        t.get_json(&url, &[], WAIT).unwrap();
        assert_eq!(t.open_connections(), 0);
        t.get_json(&url, &[], WAIT).unwrap();
        assert_eq!(server.accepted.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn a_chunked_answer_is_read() {
        let server = serve(|stream, _| {
            if read_request(stream).is_some() {
                let _ = stream.write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n{\"a\r\n4;ext=1\r\n\":1}\r\n0\r\nX: y\r\n\r\n",
                );
            }
        });
        let t = client(1);
        let reply = t.get_json(&format!("{}/a", server.url), &[], WAIT).unwrap();
        assert_eq!(reply.body, br#"{"a":1}"#);
    }

    #[test]
    fn p_10_6_a_refused_connection_is_a_failure_before_the_request() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/a", listener.local_addr().unwrap());
        drop(listener);
        let error = client(1).post_json(&url, &[], b"{}", WAIT).unwrap_err();
        assert!(error.request_was_not_sent(), "{error}");
    }

    #[test]
    fn p_10_6_a_connection_that_closes_after_the_request_is_a_lost_answer() {
        let server = serve(|stream, _| {
            let _ = read_request(stream);
            // Close with no byte.
        });
        let error = client(1)
            .post_json(&format!("{}/a", server.url), &[], b"{}", WAIT)
            .unwrap_err();
        assert!(matches!(error, TransportError::Lost(_)), "{error}");
        assert!(!error.request_was_not_sent());
    }

    #[test]
    fn p_10_6_a_silent_server_gives_a_timeout() {
        let server = serve(|stream, _| {
            let _ = read_request(stream);
            thread::sleep(Duration::from_secs(2));
        });
        let started = Instant::now();
        let error = client(1)
            .post_json(
                &format!("{}/a", server.url),
                &[],
                b"{}",
                Duration::from_millis(200),
            )
            .unwrap_err();
        assert_eq!(error, TransportError::Timeout);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn a_wrong_answer_is_malformed() {
        for wire in [
            &b"garbage\r\n\r\n"[..],
            b"HTTP/1.1 99 X\r\nContent-Length: 0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab",
            b"HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\nContent-Length: 0\r\n\r\n",
        ] {
            let server = serve(move |stream, _| {
                let _ = read_request(stream);
                let _ = stream.write_all(wire);
            });
            let error = client(1)
                .get_json(&format!("{}/a", server.url), &[], WAIT)
                .unwrap_err();
            assert!(
                matches!(error, TransportError::Malformed(_)),
                "{error} for {wire:?}"
            );
        }
    }

    #[test]
    fn a_body_above_the_bound_is_refused_before_it_is_read() {
        let server = serve(|stream, _| {
            let _ = read_request(stream);
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 99999\r\n\r\n");
            thread::sleep(Duration::from_millis(300));
        });
        let error = client(1)
            .get_json(&format!("{}/a", server.url), &[], WAIT)
            .unwrap_err();
        assert_eq!(error, TransportError::TooLarge);
    }

    #[test]
    fn a_header_with_a_line_end_is_not_sent() {
        let server = serve(ok_script);
        let error = client(1)
            .get_json(
                &format!("{}/a", server.url),
                &[("X-A".into(), "b\r\nX-Evil: 1".into())],
                WAIT,
            )
            .unwrap_err();
        assert!(error.request_was_not_sent());
        assert_eq!(server.accepted.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_secured_url_needs_another_transport() {
        let t = client(1);
        assert!(t.supports_scheme("http"));
        assert!(!t.supports_scheme("https"));
        let error = t.get_json("https://pdp.example/a", &[], WAIT).unwrap_err();
        assert!(matches!(error, TransportError::Unsupported(_)));
    }

    #[test]
    fn a_request_has_the_head_that_a_pdp_expects() {
        let seen = Arc::new(Mutex::new(String::new()));
        let copy = Arc::clone(&seen);
        let server = serve(move |stream, _| {
            if let Some(data) = read_request(stream) {
                *copy.lock().unwrap() = String::from_utf8_lossy(&data).into_owned();
                let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}");
            }
        });
        let url = format!("{}/access/v1/evaluation", server.url);
        client(1)
            .post_json(
                &url,
                &[("Authorization".into(), "Bearer tok".into())],
                br#"{"a":1}"#,
                WAIT,
            )
            .unwrap();
        let text = seen.lock().unwrap().clone();
        assert!(
            text.starts_with("POST /access/v1/evaluation HTTP/1.1\r\n"),
            "{text}"
        );
        assert!(text.contains("\r\nAuthorization: Bearer tok\r\n"), "{text}");
        assert!(
            text.contains("\r\nContent-Type: application/json\r\n"),
            "{text}"
        );
        assert!(text.contains("\r\nContent-Length: 7\r\n"), "{text}");
        assert!(text.ends_with("\r\n\r\n{\"a\":1}"), "{text}");
        assert!(text.contains(&format!(
            "\r\nHost: {}\r\n",
            server.url.trim_start_matches("http://")
        )));
    }
}
