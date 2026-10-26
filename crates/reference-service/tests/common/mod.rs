//! Helpers for the tests of the service: a test PDP, the service in the same
//! process, tokens from an edge, and a small HTTP client.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use access_token::make::{Shape, make_token};
use fake_pdp::{Options, RunningServer, Server};
use procurauth_core::jws::SigningKey;
use reference_service::config::{Sources, load};
use reference_service::service::{RunningService, build_app};
use serde_json::{Value, json};

pub const SERVICE: &str = "datastore";
pub const KEY_ALICE: &str = "key:9b1c04e2aa71f0c3";
pub const CREDENTIAL: &str = "the-credential-of-the-service";

/// The data of the test PDP: the document of the service and the grants of the examples.
pub fn pdp_data() -> Value {
    serde_json::from_str(include_str!("../../examples/pdp-data.json")).unwrap()
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub struct Edge {
    key: SigningKey,
}

impl Edge {
    pub fn new() -> Self {
        Self {
            key: SigningKey::from_ed25519_seed(&[7; 32]),
        }
    }

    pub fn jwks(&self) -> Value {
        self.key.public_jwks(Some("edge-ed25519"))
    }

    pub fn claims(&self, sub: &str, owner: Option<&str>) -> Value {
        let mut claims = json!({
            "iss": "https://edge.example", "sub": sub, "aud": SERVICE,
            "iat": now() - 10, "exp": now() + 290,
        });
        if let Some(owner) = owner {
            claims["owner"] = json!(owner);
        }
        claims
    }

    pub fn token(&self, sub: &str) -> String {
        self.sign(&self.claims(sub, None))
    }

    pub fn key_token(&self, sub: &str, owner: &str) -> String {
        self.sign(&self.claims(sub, Some(owner)))
    }

    pub fn sign(&self, claims: &Value) -> String {
        let shape = Shape {
            alg: None,
            typ: None,
            kid: Some("edge-ed25519".into()),
            crit: None,
            bad_signature: false,
        };
        make_token(&shape, claims, &self.key).token
    }

    pub fn sign_with(&self, shape: &Shape, claims: &Value) -> String {
        make_token(shape, claims, &self.key).token
    }
}

pub fn no_sources() -> (
    impl Fn(&str) -> Option<String>,
    impl Fn(&std::path::Path) -> Result<String, String>,
) {
    (
        |name: &str| (name == "TEST_PDP_CREDENTIAL").then(|| CREDENTIAL.to_owned()),
        |path: &std::path::Path| Err(format!("no file {}", path.display())),
    )
}

/// The configuration of the service for a PDP at this URL, as a JSON value.
pub fn config_value(pdp_url: &str, edge: &Edge) -> Value {
    let mut config = json!({
        "listen": "127.0.0.1:0",
        "issuer": "https://edge.example",
        "jwks": edge.jwks(),
        "workers": 4,
        "pdp": {
            "url": pdp_url,
            "credential_env": "TEST_PDP_CREDENTIAL",
            "allow_insecure_pdp_link": true,
            "request_timeout_ms": 2000,
            "usage_wait_margin_ms": 200
        }
    });
    if cfg!(feature = "mcp") {
        config["mcp_path"] = json!("/mcp");
    }
    config
}

/// A test PDP and a service that uses it.
pub struct Stack {
    pub pdp: RunningServer,
    pub service: RunningService,
    pub edge: Edge,
    pub log: Log,
}

/// A log that a test can read.
#[derive(Clone, Default)]
pub struct Log(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl Log {
    pub fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

impl Write for Log {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn start_pdp(data: &Value, options: Options) -> RunningServer {
    Server::from_value(data, options)
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap()
}

pub fn stack() -> Stack {
    stack_with(&pdp_data(), Options::default(), |_| {})
}

pub fn stack_with(data: &Value, options: Options, tweak: impl FnOnce(&mut Value)) -> Stack {
    let options = Options {
        credential: Some(
            fake_pdp::config::Credential::from_file_text(CREDENTIAL, "file:/test").unwrap(),
        ),
        ..options
    };
    let pdp = start_pdp(data, options);
    let edge = Edge::new();
    let mut config = config_value(&pdp.url(), &edge);
    tweak(&mut config);
    let (env, file) = no_sources();
    let loaded = load(
        &config.to_string(),
        &Sources {
            env: &env,
            file: &file,
        },
    )
    .unwrap();
    let log = Log::default();
    let app = build_app(
        loaded.settings.pep,
        loaded.settings.mcp_path,
        Box::new(log.clone()),
    )
    .unwrap();
    let service = reference_service::service::start(
        std::sync::Arc::new(app),
        loaded.settings.listen,
        loaded.settings.workers,
        loaded.settings.limits,
    )
    .unwrap();
    Stack {
        pdp,
        service,
        edge,
        log,
    }
}

/// An answer of the service.
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

/// Send one request on a new connection, and read the whole answer.
pub fn send(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Reply {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    stream.write_all(head.as_bytes()).unwrap();
    if let Some(body) = body {
        stream.write_all(body).unwrap();
    }
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).unwrap();
    parse_reply(&raw)
}

pub fn parse_reply(raw: &[u8]) -> Reply {
    let end = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .unwrap_or_else(|| panic!("no head in {:?}", String::from_utf8_lossy(raw)));
    let head = String::from_utf8_lossy(&raw[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let status: u16 = lines
        .next()
        .unwrap()
        .split(' ')
        .nth(1)
        .unwrap()
        .parse()
        .unwrap();
    let headers = lines
        .map(|l| {
            let (n, v) = l.split_once(':').unwrap();
            (n.to_owned(), v.trim().to_owned())
        })
        .collect();
    Reply {
        status,
        headers,
        body: raw[end + 4..].to_vec(),
    }
}

impl Stack {
    pub fn get(&self, path: &str, token: Option<&str>) -> Reply {
        let headers: Vec<(&str, &str)> =
            token.map(|t| ("X-Identity-Token", t)).into_iter().collect();
        send(self.service.local_addr(), "GET", path, &headers, None)
    }

    pub fn post(&self, path: &str, token: Option<&str>, body: &Value) -> Reply {
        let headers: Vec<(&str, &str)> =
            token.map(|t| ("X-Identity-Token", t)).into_iter().collect();
        send(
            self.service.local_addr(),
            "POST",
            path,
            &headers,
            Some(body.to_string().as_bytes()),
        )
    }

    /// A request to the MCP endpoint.
    pub fn mcp(&self, token: Option<&str>, request: &Value) -> Reply {
        let mut headers = vec![
            ("Content-Type", "application/json"),
            ("Accept", "application/json, text/event-stream"),
            ("MCP-Protocol-Version", "2026-07-28"),
        ];
        if let Some(token) = token {
            headers.push(("X-Identity-Token", token));
        }
        send(
            self.service.local_addr(),
            "POST",
            "/mcp",
            &headers,
            Some(request.to_string().as_bytes()),
        )
    }

    pub fn used(&self, subject: &str, window: &str) -> u64 {
        self.pdp
            .counters()
            .iter()
            .filter(|c| c.subject == subject && c.window.as_str() == window)
            .map(|c| c.used)
            .sum()
    }
}

pub const ORDERS: &str = "/hosts/prod/databases/test2/tables/orders";

pub fn rpc(id: u64, method: &str, params: Value) -> Value {
    let mut params = params;
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28"});
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}
