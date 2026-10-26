//! Helpers for the integration tests: a small HTTP client on `std::net::TcpStream`,
//! the data of section 13 and a capture of the text log.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fake_pdp::{Options, RunningServer, Server};
use serde_json::{Value, json};

pub const NOW: u64 = 1_792_569_648;
pub const KEY_ALICE: &str = "key:9b1c04e2aa71f0c3";
pub const KEY_BOB: &str = "key:4d2e8f6a10b37c95";

/// The data of protocol section 13, with Bob and his key.
pub fn datastore() -> Value {
    let text = include_str!("../../../../conformance/directories/datastore.json");
    serde_json::from_str(text).unwrap()
}

/// A writer that a test can read.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Start a server on a free port with the default options.
pub fn start(data: &Value) -> RunningServer {
    start_with(data, Options::default())
}

/// Start a server on a free port.
pub fn start_with(data: &Value, options: Options) -> RunningServer {
    Server::from_value(data, options)
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap()
}

/// Start a server with the admin endpoints on.
pub fn start_admin(data: &Value) -> RunningServer {
    start_with(
        data,
        Options {
            admin: true,
            ..Options::default()
        },
    )
}

/// What a connection does in a short time.
#[derive(Debug, PartialEq, Eq)]
pub enum Probe {
    Closed,
    Silent,
    Data,
}

/// An answer of the server.
#[derive(Debug, Clone)]
pub struct Reply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Reply {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("the body is not JSON ({e}): {}", self.text()))
    }
}

/// A connection that stays open between requests.
pub struct Client {
    pub stream: TcpStream,
    buffer: Vec<u8>,
}

impl Client {
    pub fn connect(addr: SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        Self {
            stream,
            buffer: Vec::new(),
        }
    }

    pub fn write_raw(&mut self, bytes: &[u8]) {
        self.stream.write_all(bytes).unwrap();
    }

    /// Send a request and read the answer.
    pub fn send(
        &mut self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
    ) -> Reply {
        let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\n");
        for (name, value) in headers {
            head.push_str(&format!("{name}: {value}\r\n"));
        }
        if let Some(body) = body {
            head.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        head.push_str("\r\n");
        self.write_raw(head.as_bytes());
        if let Some(body) = body {
            self.write_raw(body);
        }
        self.read_reply().expect("an answer")
    }

    pub fn post_json(&mut self, path: &str, body: &Value) -> Reply {
        self.post_json_with(path, &[], body)
    }

    pub fn post_json_with(&mut self, path: &str, headers: &[(&str, &str)], body: &Value) -> Reply {
        let mut all = vec![("Content-Type", "application/json")];
        all.extend_from_slice(headers);
        self.send("POST", path, &all, Some(body.to_string().as_bytes()))
    }

    pub fn get(&mut self, path: &str) -> Reply {
        self.send("GET", path, &[], None)
    }

    /// Read one answer. The result is `None` when the server closes the connection first.
    pub fn read_reply(&mut self) -> Option<Reply> {
        loop {
            if let Some(end) = self.buffer.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8(self.buffer[..end].to_vec()).unwrap();
                let mut lines = head.split("\r\n");
                let status: u16 = lines
                    .next()
                    .unwrap()
                    .split(' ')
                    .nth(1)
                    .unwrap()
                    .parse()
                    .unwrap();
                let headers: Vec<(String, String)> = lines
                    .map(|l| {
                        let (n, v) = l.split_once(':').unwrap();
                        (n.to_owned(), v.trim().to_owned())
                    })
                    .collect();
                let length: usize = headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                    .map_or(0, |(_, v)| v.parse().unwrap());
                let start = end + 4;
                while self.buffer.len() < start + length {
                    if !self.fill() {
                        return None;
                    }
                }
                let body = self.buffer[start..start + length].to_vec();
                self.buffer.drain(..start + length);
                return Some(Reply {
                    status,
                    headers,
                    body,
                });
            }
            if !self.fill() {
                return None;
            }
        }
    }

    /// Wait up to `millis` for the server to close the connection or to send bytes.
    pub fn probe(&mut self, millis: u64) -> Probe {
        self.stream
            .set_read_timeout(Some(Duration::from_millis(millis)))
            .unwrap();
        let mut chunk = [0_u8; 64];
        let result = match self.stream.read(&mut chunk) {
            Ok(0) => Probe::Closed,
            Ok(_) => Probe::Data,
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                Probe::Silent
            }
            Err(_) => Probe::Closed,
        };
        self.stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        result
    }

    fn fill(&mut self) -> bool {
        let mut chunk = [0_u8; 4096];
        match self.stream.read(&mut chunk) {
            Ok(0) | Err(_) => false,
            Ok(n) => {
                self.buffer.extend_from_slice(&chunk[..n]);
                true
            }
        }
    }
}

/// One request on a new connection.
pub fn once(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Reply {
    Client::connect(addr).send(method, path, headers, body)
}

pub const EVALUATION: &str = "/access/v1/evaluation";
pub const EVALUATIONS: &str = "/access/v1/evaluations";

/// A question as the PEP sends it. `below` is the path below the service, for example `host:prod/database:test1`.
pub fn question(subject: &str, action: &str, below: &str, usage: bool) -> Value {
    let nodes: Vec<(&str, &str)> = if below.is_empty() {
        Vec::new()
    } else {
        below
            .split('/')
            .map(|s| s.split_once(':').unwrap())
            .collect()
    };
    let mut body = match nodes.split_last() {
        None => json!({
            "subject": {"type": "user", "id": subject},
            "action": {"name": action},
            "resource": {"type": "service", "id": "datastore"},
        }),
        Some(((kind, id), above)) => {
            let mut chain = vec![json!({"type": "service", "id": "datastore"})];
            chain.extend(above.iter().map(|(t, i)| json!({"type": t, "id": i})));
            json!({
                "subject": {"type": "user", "id": subject},
                "action": {"name": action},
                "resource": {"type": kind, "id": id, "properties": {"ancestors": chain}},
            })
        }
    };
    if usage {
        body["context"] = json!({"usage": {"units": 1}});
    }
    body
}

pub const TEST1: &str = "host:prod/database:test1";
pub const TEST2: &str = "host:prod/database:test2";

/// The answer to one question on a new connection.
pub fn ask(server: &RunningServer, body: &Value) -> Value {
    let reply = once_json(server.local_addr(), EVALUATION, body);
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply.json()
}

pub fn once_json(addr: SocketAddr, path: &str, body: &Value) -> Reply {
    Client::connect(addr).post_json(path, body)
}
