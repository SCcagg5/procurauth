//! A small HTTP client for one GET request, with the standard library only.
//!
//! The client reads at most a fixed number of bytes and stops after a fixed time.
//! It follows a redirect only to the same host and port. It speaks plain HTTP.
//! It has no TLS code, so it refuses an `https` URL.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

/// The bounds of one fetch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// The most bytes of the body. A larger body is an error.
    pub max_body: usize,
    /// The time for the whole fetch, with each redirect.
    pub timeout: Duration,
    /// The most redirects to the same host.
    pub max_redirects: usize,
}

/// The bounds that the tool uses: 64 KiB (protocol 5.3c), 10 seconds and 3 redirects.
pub const DEFAULT_LIMITS: Limits = Limits {
    max_body: 64 * 1024,
    timeout: Duration::from_secs(10),
    max_redirects: 3,
};

/// The most bytes of the head of a response.
const MAX_HEAD: usize = 16 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
struct Url {
    host: String,
    port: u16,
    target: String,
}

impl Url {
    fn authority(&self) -> String {
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

/// True when the text is an HTTP or HTTPS URL, so that the tool fetches it.
pub fn is_url(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn parse_url(text: &str) -> Result<Url, String> {
    let lower = text.to_ascii_lowercase();
    if lower.starts_with("https://") {
        return Err(format!(
            "URL {text}: the scheme https is not supported, because the tool has no TLS code. Use an http URL, or save the document in a file"
        ));
    }
    if !lower.starts_with("http://") {
        return Err(format!("URL {text}: the scheme must be http"));
    }
    let rest = &text["http://".len()..];
    let rest = rest.split('#').next().unwrap_or(rest);
    let (authority, target) = match rest.find(['/', '?']) {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/"),
    };
    let target = if target.starts_with('?') {
        format!("/{target}")
    } else {
        target.to_owned()
    };
    if authority.contains('@') {
        return Err(format!("URL {text}: a user name in a URL is not supported"));
    }
    if target.bytes().any(|b| b <= b' ' || b == 0x7f) {
        return Err(format!(
            "URL {text}: a space or a control character is not valid"
        ));
    }
    let (host, port) = split_authority(authority).map_err(|why| format!("URL {text}: {why}"))?;
    Ok(Url { host, port, target })
}

fn split_authority(authority: &str) -> Result<(String, u16), String> {
    let (host, port_text) = if let Some(inner) = authority.strip_prefix('[') {
        let (host, after) = inner
            .split_once(']')
            .ok_or_else(|| "an IPv6 address has no closing bracket".to_owned())?;
        match after {
            "" => (host, None),
            _ => (
                host,
                Some(
                    after
                        .strip_prefix(':')
                        .ok_or_else(|| "text follows the IPv6 address".to_owned())?,
                ),
            ),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return Err("the host is empty".to_owned());
    }
    let port = match port_text {
        None => 80,
        Some(text) => text
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| format!("the port {text:?} is not a number from 1 to 65535"))?,
    };
    Ok((host.to_ascii_lowercase(), port))
}

/// A stream that fails with `TimedOut` after a fixed time.
struct Timed {
    stream: TcpStream,
    deadline: Instant,
}

impl Read for Timed {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self
            .deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "the time is over"))?;
        self.stream.set_read_timeout(Some(left))?;
        self.stream.read(buf)
    }
}

/// Fetch a URL with GET. Give the body, or a message that tells why the fetch failed.
///
/// # Errors
/// Returns a message for a bad URL, a failed connection or a status other than 200.
/// It also returns a message for a redirect to another host, a body above the bound and a timeout.
pub fn get(url: &str, limits: Limits) -> Result<Vec<u8>, String> {
    let deadline = Instant::now() + limits.timeout;
    let mut current = parse_url(url)?;
    let first = current.clone();
    for _ in 0..=limits.max_redirects {
        match fetch_once(&current, limits, deadline).map_err(|why| format!("URL {url}: {why}"))? {
            Answer::Body(body) => return Ok(body),
            Answer::Redirect(location) => {
                current = redirect_target(&first, &current, &location)
                    .map_err(|why| format!("URL {url}: {why}"))?;
            }
        }
    }
    Err(format!(
        "URL {url}: more than {} redirects",
        limits.max_redirects
    ))
}

fn redirect_target(first: &Url, current: &Url, location: &str) -> Result<Url, String> {
    if location.starts_with("//") {
        return Err("the redirect has a network path, which the tool does not follow".to_owned());
    }
    if location.starts_with('/') {
        if location.bytes().any(|b| b <= b' ' || b == 0x7f) {
            return Err("the redirect has a space or a control character".to_owned());
        }
        return Ok(Url {
            host: current.host.clone(),
            port: current.port,
            target: location.to_owned(),
        });
    }
    let next = parse_url(location)?;
    if next.host != first.host || next.port != first.port {
        return Err(format!(
            "the redirect goes to another host, {}. The tool does not follow it",
            next.authority()
        ));
    }
    Ok(next)
}

enum Answer {
    Body(Vec<u8>),
    Redirect(String),
}

fn fetch_once(url: &Url, limits: Limits, deadline: Instant) -> Result<Answer, String> {
    let left = |what: &str| {
        deadline
            .checked_duration_since(Instant::now())
            .filter(|left| !left.is_zero())
            .ok_or_else(|| format!("no answer in {} seconds ({what})", limits.timeout.as_secs()))
    };
    let addresses = (url.host.as_str(), url.port)
        .to_socket_addrs()
        .map_err(|e| format!("cannot find the host {}: {e}", url.host))?;
    let mut stream = None;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, left("connect")?) {
            Ok(connected) => {
                stream = Some(connected);
                break;
            }
            Err(e) => last_error = Some(e),
        }
    }
    let Some(stream) = stream else {
        let why = last_error.map_or_else(|| "no address".to_owned(), |e| e.to_string());
        return Err(format!("cannot connect to {}: {why}", url.authority()));
    };
    stream
        .set_write_timeout(Some(left("write")?))
        .map_err(|e| e.to_string())?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nAccept: application/json\r\nUser-Agent: access-lint/{}\r\nConnection: close\r\n\r\n",
        url.target,
        url.authority(),
        env!("CARGO_PKG_VERSION")
    );
    let mut writer = &stream;
    writer
        .write_all(request.as_bytes())
        .map_err(|e| format!("cannot send the request: {e}"))?;
    let mut reader = BufReader::new(Timed { stream, deadline });
    read_answer(&mut reader, limits).map_err(|e| e.to_string())
}

/// What can go wrong while the client reads an answer.
#[derive(Debug)]
enum ReadError {
    Io(io::Error),
    Text(String),
}

impl std::fmt::Display for ReadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                f.write_str("no answer in time")
            }
            Self::Io(e) => write!(f, "cannot read the answer: {e}"),
            Self::Text(text) => f.write_str(text),
        }
    }
}

impl From<io::Error> for ReadError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

fn fail<T>(message: impl Into<String>) -> Result<T, ReadError> {
    Err(ReadError::Text(message.into()))
}

/// Read one line, with its end, up to a bound.
fn read_line(reader: &mut impl BufRead, budget: &mut usize) -> Result<String, ReadError> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        if reader.read(&mut byte)? == 0 {
            return fail("the answer ends too early");
        }
        if *budget == 0 {
            return fail(format!(
                "the head of the answer is longer than {MAX_HEAD} bytes"
            ));
        }
        *budget -= 1;
        if byte[0] == b'\n' {
            break;
        }
        line.push(byte[0]);
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).or_else(|_| fail("the head of the answer is not text"))
}

fn read_answer(reader: &mut impl BufRead, limits: Limits) -> Result<Answer, ReadError> {
    let mut budget = MAX_HEAD;
    let status_line = read_line(reader, &mut budget)?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let status: u16 = match (version.starts_with("HTTP/1."), parts.next()) {
        (true, Some(code)) => match code.parse() {
            Ok(status) => status,
            Err(_) => return fail(format!("the status line {status_line:?} is not valid")),
        },
        _ => return fail(format!("the status line {status_line:?} is not valid")),
    };
    let mut length: Option<u64> = None;
    let mut chunked = false;
    let mut location = None;
    loop {
        let line = read_line(reader, &mut budget)?;
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return fail(format!("the header {line:?} is not valid"));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => {
                length = Some(
                    value
                        .parse()
                        .or_else(|_| fail(format!("Content-Length {value:?} is not a number")))?,
                );
            }
            "transfer-encoding" => chunked = value.eq_ignore_ascii_case("chunked"),
            "content-encoding" if !value.eq_ignore_ascii_case("identity") => {
                return fail(format!("the content coding {value:?} is not supported"));
            }
            "location" => location = Some(value.to_owned()),
            _ => {}
        }
    }
    if matches!(status, 301 | 302 | 303 | 307 | 308) {
        return match location {
            Some(location) => Ok(Answer::Redirect(location)),
            None => fail(format!("HTTP status {status} has no Location header")),
        };
    }
    if status != 200 {
        return fail(format!("HTTP status {status}, expected 200 (protocol 5.3)"));
    }
    let max = limits.max_body;
    let too_large = || {
        fail(format!(
            "the body is larger than {max} bytes, the bound of protocol 5.3c"
        ))
    };
    let mut body = Vec::new();
    if chunked {
        loop {
            let line = read_line(reader, &mut 1024)?;
            let size_text = line.split(';').next().unwrap_or_default().trim();
            let size = usize::from_str_radix(size_text, 16)
                .or_else(|_| fail(format!("the chunk size {size_text:?} is not valid")))?;
            if size == 0 {
                break;
            }
            if body.len().saturating_add(size) > max {
                return too_large();
            }
            let start = body.len();
            body.resize(start + size, 0);
            reader.read_exact(&mut body[start..])?;
            read_line(reader, &mut 1024)?;
        }
    } else if let Some(length) = length {
        if length > max as u64 {
            return too_large();
        }
        body.resize(usize::try_from(length).unwrap_or(max), 0);
        reader.read_exact(&mut body)?;
    } else {
        (&mut *reader).take(max as u64 + 1).read_to_end(&mut body)?;
        if body.len() > max {
            return too_large();
        }
    }
    Ok(Answer::Body(body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    /// Start a server that answers each connection with the next text of `answers`.
    fn serve(answers: Vec<Vec<u8>>) -> (u16, thread::JoinHandle<Vec<String>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for answer in answers {
                let (mut stream, _) = listener.accept().unwrap();
                let mut head = Vec::new();
                let mut byte = [0_u8; 1];
                while !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).unwrap() == 0 {
                        break;
                    }
                    head.push(byte[0]);
                }
                requests.push(String::from_utf8_lossy(&head).into_owned());
                let _ = stream.write_all(&answer);
            }
            requests
        });
        (port, handle)
    }

    fn limits() -> Limits {
        Limits {
            max_body: 100,
            timeout: Duration::from_secs(5),
            max_redirects: 2,
        }
    }

    #[test]
    fn p_5_1_a_get_with_a_length_gives_the_body() {
        let (port, handle) = serve(vec![
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec(),
        ]);
        let body = get(
            &format!("http://127.0.0.1:{port}/.well-known/procurauth/actions"),
            limits(),
        )
        .unwrap();
        assert_eq!(body, b"hello");
        let requests = handle.join().unwrap();
        assert!(requests[0].starts_with("GET /.well-known/procurauth/actions HTTP/1.1\r\n"));
        assert!(requests[0].contains(&format!("Host: 127.0.0.1:{port}\r\n")));
    }

    #[test]
    fn p_5_1_a_chunked_body_is_decoded() {
        let (port, _handle) = serve(vec![
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2;x=1\r\nde\r\n0\r\n\r\n"
                .to_vec(),
        ]);
        let body = get(&format!("http://127.0.0.1:{port}/a"), limits()).unwrap();
        assert_eq!(body, b"abcde");
    }

    #[test]
    fn p_5_1_a_body_to_the_end_of_the_stream_is_read() {
        let (port, _handle) = serve(vec![b"HTTP/1.0 200 OK\r\n\r\n{}".to_vec()]);
        assert_eq!(
            get(&format!("http://127.0.0.1:{port}/"), limits()).unwrap(),
            b"{}"
        );
    }

    #[test]
    fn p_5_3_a_status_other_than_200_is_an_error() {
        let (port, _handle) = serve(vec![
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
        ]);
        let error = get(&format!("http://127.0.0.1:{port}/a"), limits()).unwrap_err();
        assert!(error.contains("HTTP status 404"), "{error}");
    }

    #[test]
    fn p_5_3c_a_body_above_the_bound_is_an_error() {
        let big = "x".repeat(101);
        let (port, _h1) = serve(vec![
            format!("HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n{big}").into_bytes(),
        ]);
        assert!(
            get(&format!("http://127.0.0.1:{port}/a"), limits())
                .unwrap_err()
                .contains("larger than 100")
        );
        let (port, _h2) = serve(vec![format!("HTTP/1.0 200 OK\r\n\r\n{big}").into_bytes()]);
        assert!(
            get(&format!("http://127.0.0.1:{port}/a"), limits())
                .unwrap_err()
                .contains("larger than 100")
        );
        let (port, _h3) = serve(vec![
            format!(
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n65\r\n{big}\r\n0\r\n\r\n"
            )
            .into_bytes(),
        ]);
        assert!(
            get(&format!("http://127.0.0.1:{port}/a"), limits())
                .unwrap_err()
                .contains("larger than 100")
        );
    }

    #[test]
    fn p_5_3c_a_body_of_the_bound_is_good() {
        let exact = "x".repeat(100);
        let (port, _h) = serve(vec![
            format!("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n{exact}").into_bytes(),
        ]);
        assert_eq!(
            get(&format!("http://127.0.0.1:{port}/a"), limits())
                .unwrap()
                .len(),
            100
        );
    }

    #[test]
    fn p_5_1_a_redirect_to_the_same_host_is_followed() {
        let (port, handle) = serve(vec![
            b"HTTP/1.1 301 Moved\r\nLocation: /b\r\nContent-Length: 0\r\n\r\n".to_vec(),
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec(),
        ]);
        assert_eq!(
            get(&format!("http://127.0.0.1:{port}/a"), limits()).unwrap(),
            b"ok"
        );
        assert!(handle.join().unwrap()[1].starts_with("GET /b "));
    }

    #[test]
    fn p_5_1_a_redirect_to_another_host_is_refused() {
        let (port, _handle) = serve(vec![
            b"HTTP/1.1 302 Found\r\nLocation: http://example.org/a\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        ]);
        let error = get(&format!("http://127.0.0.1:{port}/a"), limits()).unwrap_err();
        assert!(error.contains("another host"), "{error}");
        let (port, _handle) = serve(vec![
            b"HTTP/1.1 302 Found\r\nLocation: https://127.0.0.1/a\r\nContent-Length: 0\r\n\r\n"
                .to_vec(),
        ]);
        assert!(get(&format!("http://127.0.0.1:{port}/a"), limits()).is_err());
    }

    #[test]
    fn p_5_1_too_many_redirects_are_an_error() {
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: /a\r\nContent-Length: 0\r\n\r\n".to_vec();
        let (port, _handle) = serve(vec![redirect.clone(), redirect.clone(), redirect]);
        let error = get(&format!("http://127.0.0.1:{port}/a"), limits()).unwrap_err();
        assert!(error.contains("more than 2 redirects"), "{error}");
    }

    #[test]
    fn p_5_3_no_answer_in_time_is_an_error() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = thread::spawn(move || {
            let (_stream, _) = listener.accept().unwrap();
            thread::sleep(Duration::from_millis(600));
        });
        let short = Limits {
            timeout: Duration::from_millis(200),
            ..limits()
        };
        let started = Instant::now();
        let error = get(&format!("http://127.0.0.1:{port}/a"), short).unwrap_err();
        assert!(error.contains("no answer"), "{error}");
        assert!(started.elapsed() < Duration::from_millis(550));
        handle.join().unwrap();
    }

    #[test]
    fn p_5_1_https_is_not_supported() {
        let error = get("https://example.org/a", limits()).unwrap_err();
        assert!(error.contains("https is not supported"), "{error}");
    }

    #[test]
    fn p_5_1_a_url_is_read_with_care() {
        let url = parse_url("http://Example.ORG:8080/a/b?x=1#frag").unwrap();
        assert_eq!(url.host, "example.org");
        assert_eq!(url.port, 8080);
        assert_eq!(url.target, "/a/b?x=1");
        assert_eq!(parse_url("http://h").unwrap().target, "/");
        assert_eq!(parse_url("http://h?x=1").unwrap().target, "/?x=1");
        assert_eq!(parse_url("http://[::1]:81/").unwrap().host, "::1");
        for bad in [
            "http://",
            "http://h:0/",
            "http://h:x/",
            "http://u@h/",
            "http://h/a b",
            "ftp://h/",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn p_5_1_a_redirect_with_a_network_path_or_a_space_is_refused() {
        let first = parse_url("http://h/a").unwrap();
        assert!(redirect_target(&first, &first, "//other/a").is_err());
        assert!(redirect_target(&first, &first, "/a b").is_err());
        assert!(redirect_target(&first, &first, "/a\tb").is_err());
        assert_eq!(
            redirect_target(&first, &first, "/b?x=1").unwrap().target,
            "/b?x=1"
        );
    }

    #[test]
    fn p_5_1_the_text_of_a_url_is_known() {
        assert!(is_url("http://a"));
        assert!(is_url("HTTPS://a"));
        assert!(!is_url("actions.json"));
    }
}
