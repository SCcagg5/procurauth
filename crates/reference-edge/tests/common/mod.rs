//! Helpers for the tests of the edge. They give a test PDP, a tiny service behind the edge,
//! the edge in the same process, and a small HTTP client. All the traffic is real HTTP
//! on the loopback address.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use fake_pdp::{Options, RunningServer, Server};
use procurauth_core::jws::{KeySet, SigningKey};
use procurauth_pep::clock::ManualClock;
use procurauth_pep::config::PdpConfig;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
use reference_edge::config::{Loaded, Sources, load};
use reference_edge::edge::Edge;
use reference_edge::server::{RunningEdge, start};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const SERVICE: &str = "datastore";
pub const ISSUER: &str = "https://edge.example";
pub const HEADER: &str = "X-Identity-Token";
/// The key of Ann that has `access`.
pub const KEY_OK: &str = "pk_live_0000000000000000000000000000000000000000001";
/// The key of Ann that has no `access`.
pub const KEY_NO_ACCESS: &str = "pk_live_0000000000000000000000000000000000000000002";
/// A key with a good form that the edge does not know.
pub const KEY_UNKNOWN: &str = "pk_live_0000000000000000000000000000000000000000003";
/// A text for a person.
pub const PERSON_TEXT: &str = "pk_live_0000000000000000000000000000000000000000004";
/// A text for a person that has no `access`.
pub const PERSON_NO_ACCESS: &str = "pk_live_0000000000000000000000000000000000000000005";
pub const CREDENTIAL: &str = "the-credential-of-the-edge";
/// The time of the tests, in seconds since the Unix epoch.
pub const NOW: u64 = 1_792_569_648;

pub const ED25519_PEM: &str = include_str!("../../../access-token/examples/test-edge-ed25519.pem");
pub const ES256_PEM: &str = include_str!("../../../access-token/examples/test-edge-es256.pem");

pub fn digest(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// The data of the test PDP: the file `access.json` of the conformance data.
pub fn pdp_data() -> Value {
    serde_json::from_str(include_str!(
        "../../../../conformance/directories/access.json"
    ))
    .unwrap()
}

pub fn start_pdp() -> RunningServer {
    start_pdp_with(&pdp_data())
}

pub fn start_pdp_with(data: &Value) -> RunningServer {
    let credential = fake_pdp::config::Credential::from_file_text(CREDENTIAL, "test").unwrap();
    Server::from_value(
        data,
        Options {
            credential: Some(credential),
            ..Options::default()
        },
    )
    .unwrap()
    .start("127.0.0.1:0")
    .unwrap()
}

/// The keys file of the tests.
pub fn keys_file() -> Value {
    json!({"keys": [
        {"sha256": digest(KEY_OK), "subject": "key:ann-k1", "owner": "ann"},
        {"sha256": digest(KEY_NO_ACCESS), "subject": "key:ann-k2", "owner": "ann"},
        {"sha256": digest(PERSON_TEXT), "subject": "ann"},
        {"sha256": digest(PERSON_NO_ACCESS), "subject": "ben"},
    ]})
}

/// A configuration that is good. The tests change it.
pub fn base_config(pdp: SocketAddr, upstream: SocketAddr) -> Value {
    json!({
        "listen": "127.0.0.1:0",
        "workers": 8,
        "service_id": SERVICE,
        "issuer": ISSUER,
        "token_life_seconds": 60,
        "max_token_age_seconds": 300,
        "key_format": {"prefix": "pk_live_", "length": 51, "alphabet": "0-9"},
        "keys": keys_file(),
        "upstream": {"url": format!("http://{upstream}"), "connect_timeout_ms": 1000, "response_timeout_seconds": 5},
        "signing": {"key_env": "SIGNING_KEY", "kid": "edge-ed25519"},
        "pdp": {"url": format!("http://{pdp}"), "credential_env": "PDP_CREDENTIAL", "allow_insecure_pdp_link": true, "request_timeout_ms": 2000}
    })
}

pub fn load_config(value: &Value, signing_pem: &str) -> Result<Loaded, Vec<String>> {
    let env: BTreeMap<&str, String> = BTreeMap::from([
        ("SIGNING_KEY", signing_pem.to_owned()),
        ("PDP_CREDENTIAL", CREDENTIAL.to_owned()),
    ]);
    let read_env = |name: &str| env.get(name).cloned();
    let read_file = |path: &Path| std::fs::read_to_string(path).map_err(|e| e.to_string());
    load(
        &value.to_string(),
        &Sources {
            env: &read_env,
            file: &read_file,
        },
    )
}

/// A log that a test can read.
#[derive(Clone, Default)]
pub struct Capture(Arc<Mutex<Vec<u8>>>);

impl Capture {
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
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

/// What the service behind the edge received.
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub target: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Seen {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn headers_named(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}

/// A tiny service. The function gives the whole answer as bytes for a request.
pub struct Service {
    pub addr: SocketAddr,
    pub seen: Arc<Mutex<Vec<Seen>>>,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

type Answer = dyn Fn(&Seen, &mut TcpStream) + Send + Sync;

pub fn read_request(stream: &mut TcpStream) -> Option<Seen> {
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok()?;
    let mut data = Vec::new();
    let mut chunk = [0_u8; 4096];
    let end = loop {
        if let Some(i) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            break i;
        }
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        data.extend_from_slice(&chunk[..n]);
    };
    let head = String::from_utf8_lossy(&data[..end]).into_owned();
    let mut lines = head.split("\r\n");
    let mut first = lines.next()?.split(' ');
    let method = first.next()?.to_owned();
    let target = first.next()?.to_owned();
    let headers: Vec<(String, String)> = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.to_owned(), v.trim().to_owned()))
        .collect();
    let length = headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse::<usize>().ok())
        .unwrap_or(0);
    let mut body = data[end + 4..].to_vec();
    while body.len() < length {
        let n = stream.read(&mut chunk).ok()?;
        if n == 0 {
            return None;
        }
        body.extend_from_slice(&chunk[..n]);
    }
    body.truncate(length);
    Some(Seen {
        method,
        target,
        headers,
        body,
    })
}

impl Service {
    pub fn start(answer: impl Fn(&Seen, &mut TcpStream) + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let answer: Arc<Answer> = Arc::new(answer);
        let accept = {
            let (seen, stop) = (Arc::clone(&seen), Arc::clone(&stop));
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            let (seen, answer) = (Arc::clone(&seen), Arc::clone(&answer));
                            thread::spawn(move || {
                                if let Some(request) = read_request(&mut stream) {
                                    seen.lock().unwrap().push(request.clone());
                                    answer(&request, &mut stream);
                                }
                            });
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            addr,
            seen,
            stop,
            accept: Some(accept),
        }
    }

    /// A service that answers 200 with a JSON body that has the method and the target.
    pub fn echo() -> Self {
        Self::start(|request, stream| {
            let body = json!({"method": request.method, "target": request.target}).to_string();
            let reply = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(reply.as_bytes());
        })
    }

    pub fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    pub fn count(&self) -> usize {
        self.seen.lock().unwrap().len()
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(handle) = self.accept.take() {
            let _ = handle.join();
        }
    }
}

/// The edge, the test PDP and the service, with the clock of the edge.
pub struct Rig {
    pub edge: RunningEdge,
    pub inner: Arc<Edge>,
    pub pdp: RunningServer,
    pub service: Service,
    pub clock: ManualClock,
    pub log: Capture,
    pub settings_keys: KeySet,
}

pub fn rig() -> Rig {
    rig_with(Service::echo(), |_| {}, ED25519_PEM)
}

/// Build the rig. `tweak` changes the configuration before the edge reads it.
pub fn rig_with(service: Service, tweak: impl FnOnce(&mut Value), pem: &str) -> Rig {
    let pdp = start_pdp();
    rig_on(pdp, service, tweak, pem)
}

pub fn rig_on(
    pdp: RunningServer,
    service: Service,
    tweak: impl FnOnce(&mut Value),
    pem: &str,
) -> Rig {
    let mut config = base_config(pdp.local_addr(), service.addr);
    tweak(&mut config);
    let loaded = load_config(&config, pem).unwrap_or_else(|e| panic!("{e:?}"));
    let settings = loaded.settings;
    let kid = config["signing"]["kid"].as_str();
    let keys = SigningKey::from_pkcs8_pem(pem).unwrap().public_key(kid);
    let (listen, workers, limits) = (settings.listen, settings.workers, settings.limits);
    let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(
        &settings.pdp,
    )));
    let clock = ManualClock::at_seconds(NOW);
    let log = Capture::default();
    let inner = Arc::new(
        Edge::new(
            settings,
            transport,
            Arc::new(clock.clone()),
            Box::new(log.clone()),
        )
        .unwrap(),
    );
    let edge = start(Arc::clone(&inner), listen, workers, limits).unwrap();
    Rig {
        edge,
        inner,
        pdp,
        service,
        clock,
        log,
        settings_keys: KeySet::from_keys(vec![keys]),
    }
}

impl Rig {
    pub fn addr(&self) -> SocketAddr {
        self.edge.local_addr()
    }

    pub fn get(&self, target: &str, headers: &[(&str, &str)]) -> Reply {
        send(self.addr(), "GET", target, headers, None)
    }

    pub fn with_key(&self, target: &str) -> Reply {
        let auth = format!("Bearer {KEY_OK}");
        send(
            self.addr(),
            "GET",
            target,
            &[("Authorization", &auth)],
            None,
        )
    }

    /// The questions that the PDP received, as `(subject, action, resource)`.
    /// The resource has the notation of section 13, for example `service:datastore`.
    pub fn questions(&self) -> Vec<(String, String, String)> {
        self.pdp
            .log()
            .into_iter()
            .filter(|e| e.endpoint != "metadata")
            .map(|e| (e.subject, e.action, e.resource))
            .collect()
    }
}

// ---- A client ----------------------------------------------------------------------------------------------

#[derive(Debug)]
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
        serde_json::from_slice(&self.body).unwrap()
    }
}

/// Send one request on a new connection, and read the answer until the connection ends.
pub fn send(
    addr: SocketAddr,
    method: &str,
    target: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> Reply {
    let mut stream = TcpStream::connect(addr).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let mut head =
        format!("{method} {target} HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n");
    for (name, value) in headers {
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    // A write can fail when the edge closes at once after a refusal. The answer is still there.
    let _ = stream.write_all(head.as_bytes());
    if let Some(body) = body {
        let _ = stream.write_all(body);
    }
    read_reply(&mut stream, method == "HEAD")
}

fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    data.windows(needle.len()).position(|w| w == needle)
}

/// Read one answer: the head, and the body that its headers describe.
pub fn read_reply(stream: &mut TcpStream, head_only: bool) -> Reply {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 8192];
    let end = loop {
        if let Some(i) = find(&data, b"\r\n\r\n") {
            break i;
        }
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => panic!("no answer: {:?}", String::from_utf8_lossy(&data)),
            Ok(n) => data.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&data[..end]).into_owned();
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
        .filter_map(|l| l.split_once(':'))
        .map(|(n, v)| (n.to_owned(), v.trim().to_owned()))
        .collect();
    let mut rest = data[end + 4..].to_vec();
    let get = |name: &str| {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };
    let body = if head_only || status == 204 || status == 304 {
        Vec::new()
    } else if get("transfer-encoding").is_some_and(|v| v.contains("chunked")) {
        let mut body = Vec::new();
        loop {
            while find(&rest, b"\r\n").is_none() {
                let n = stream.read(&mut chunk).unwrap_or(0);
                assert!(n > 0, "the chunked body ended too early");
                rest.extend_from_slice(&chunk[..n]);
            }
            let i = find(&rest, b"\r\n").unwrap();
            let size = usize::from_str_radix(std::str::from_utf8(&rest[..i]).unwrap(), 16).unwrap();
            rest.drain(..i + 2);
            if size == 0 {
                break;
            }
            while rest.len() < size + 2 {
                let n = stream.read(&mut chunk).unwrap_or(0);
                assert!(n > 0, "the chunk ended too early");
                rest.extend_from_slice(&chunk[..n]);
            }
            body.extend_from_slice(&rest[..size]);
            rest.drain(..size + 2);
        }
        body
    } else if let Some(length) = get("content-length") {
        let length: usize = length.parse().unwrap();
        while rest.len() < length {
            let n = stream.read(&mut chunk).unwrap_or(0);
            if n == 0 {
                break;
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        rest.truncate(length);
        rest
    } else {
        while let Ok(n) = stream.read(&mut chunk) {
            if n == 0 {
                break;
            }
            rest.extend_from_slice(&chunk[..n]);
        }
        rest
    };
    Reply {
        status,
        headers,
        body,
    }
}

/// The three parts of a token, decoded.
pub fn decode_token(token: &str) -> (Value, Value) {
    use base64::Engine as _;
    let part = |i: usize| -> Value {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.split('.').nth(i).unwrap())
            .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    };
    (part(0), part(1))
}

pub fn pdp_config_for(pdp: &RunningServer) -> PdpConfig {
    let mut config = PdpConfig::new(pdp.url(), procurauth_pep::config::Secret::new(CREDENTIAL));
    config.allow_insecure_pdp_link = true;
    config
}
