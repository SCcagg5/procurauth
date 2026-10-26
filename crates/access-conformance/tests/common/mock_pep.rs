//! A scripted mock of a PEP: a tiny service `datastore`. It behaves like a
//! correct PEP for the cases with no MCP and no options route.
//! The flags of [`Defects`] make it wrong in one way each.
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

use procurauth_core::authzen::{Decision, Reason};
use procurauth_core::identity::{CheckName, Outcome, TokenPolicy, inspect};
use procurauth_core::jws::{KeySet, SigningKey};
use serde_json::{Value, json};

use super::http::{Req, Resp, Server, call};
use super::{examples, system_now};

/// The ways in which the mock is wrong. The default is a correct PEP.
#[derive(Clone, Default)]
pub struct Defects {
    /// A `budget_exceeded` answer gives HTTP 403, not 429.
    pub budget_as_403: bool,
    /// The PEP sends no credential to the PDP.
    pub no_credential: bool,
    /// The PEP does not check the signature of the token.
    pub accept_bad_signature: bool,
    /// An error of the PDP lets the use run.
    pub fail_open: bool,
    /// The PEP keeps each true answer for a subject, an action and a resource.
    pub cache_true_answers: bool,
    /// The refusal shows the reason of the PDP.
    pub leak_reason: bool,
    /// The PEP also reads the identity token from the header `Authorization`.
    pub token_from_authorization: bool,
    /// The PEP opens a new connection to the PDP for each question.
    pub new_connection_each_time: bool,
}

pub struct MockPep {
    pub addr: SocketAddr,
    server: Server,
}

struct State {
    connection: Mutex<Option<TcpStream>>,
    pdp: SocketAddr,
    credential: String,
    keys: KeySet,
    defects: Defects,
    cache: Mutex<Vec<String>>,
}

/// The identity token header of the mock.
pub const TOKEN_HEADER: &str = "X-Identity-Token";
/// The credential of the mock for its PDP.
pub const CREDENTIAL: &str = "mock-pep-credential";

fn policy() -> TokenPolicy {
    TokenPolicy {
        issuer: "https://edge.example".to_owned(),
        service_id: "datastore".to_owned(),
        max_age_seconds: 300,
        skew_seconds: 30,
    }
}

fn keys() -> KeySet {
    let ed = SigningKey::from_pkcs8_pem(
        &std::fs::read_to_string(examples().join("test-edge-ed25519.pem")).unwrap(),
    )
    .unwrap();
    let es = SigningKey::from_pkcs8_pem(
        &std::fs::read_to_string(examples().join("test-edge-es256.pem")).unwrap(),
    )
    .unwrap();
    KeySet::from_keys(vec![
        ed.public_key(Some("edge-ed25519")),
        es.public_key(Some("edge-es256")),
    ])
}

/// The action document of the mock.
pub fn document() -> Value {
    json!({
        "server": "datastore",
        "resource_types": [
            {"name": "host", "parent": "service", "description": "One database server."},
            {"name": "database", "parent": "host", "description": "One database."},
            {"name": "table", "parent": "database", "description": "One table."}
        ],
        "actions": [
            {"name": "data.read", "resource_types": ["service", "host", "database", "table"],
             "description": "Read data.", "limits": ["requests", "max_rows"]},
            {"name": "data.write", "resource_types": ["service", "host", "database", "table"],
             "description": "Change data."},
            {"name": "data.query", "resource_types": ["table"],
             "description": "Query data.", "limits": ["max_rows"]}
        ],
        "resources": [{"path": "host:prod", "label": "Production"}],
        "limits": [
            {"name": "requests", "label": "Requests", "description": "Requests that run.",
             "unit": "request", "kind": "budget"},
            {"name": "max_rows", "label": "Most rows", "description": "The most rows that one read gives.",
             "unit": "row", "kind": "ceiling", "min": 1, "max": 1000000}
        ]
    })
}

/// Why a read of an answer failed.
#[derive(PartialEq, Eq)]
enum Failed {
    /// The peer closed the connection.
    Closed,
    /// The time ended before the answer.
    Silent,
}

/// Read an answer with a Content-Length from a connection that stays open.
fn read_answer(stream: &mut TcpStream) -> Result<(u16, Vec<u8>), Failed> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 4096];
    let split = loop {
        if let Some(at) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break at;
        }
        match stream.read(&mut chunk) {
            Ok(0) => return Err(Failed::Closed),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Err(Failed::Silent);
            }
            Err(_) => return Err(Failed::Closed),
            Ok(n) => raw.extend_from_slice(&chunk[..n]),
        }
    };
    let head = String::from_utf8_lossy(&raw[..split]).into_owned();
    let status: u16 = head
        .lines()
        .next()
        .and_then(|l| l.split(' ').nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or(Failed::Closed)?;
    let length: usize = head
        .lines()
        .find_map(|l| {
            l.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap_or(0))
        })
        .unwrap_or(0);
    let mut body = raw[split + 4..].to_vec();
    while body.len() < length {
        match stream.read(&mut chunk) {
            Ok(0) | Err(_) => return Err(Failed::Closed),
            Ok(n) => body.extend_from_slice(&chunk[..n]),
        }
    }
    body.truncate(length);
    Ok((status, body))
}

fn chain() -> Value {
    json!([
        {"type": "service", "id": "datastore"},
        {"type": "host", "id": "prod"},
        {"type": "database", "id": "test1"}
    ])
}

fn node(table: &str) -> Value {
    json!({"type": "table", "id": table, "properties": {"ancestors": chain()}})
}

fn empty(status: u16) -> Resp {
    Resp::new(status)
}

impl State {
    fn subject_of(&self, req: &Req) -> Result<String, Resp> {
        let raw = req.header(TOKEN_HEADER).or_else(|| {
            self.defects
                .token_from_authorization
                .then(|| req.header("Authorization"))
                .flatten()
        });
        let Some(raw) = raw else {
            return Err(empty(401));
        };
        let token = raw.strip_prefix("Bearer ").unwrap_or(raw);
        let inspection = inspect(token, &self.keys, &policy(), system_now());
        let failed: Vec<_> = inspection
            .checks
            .iter()
            .filter(|c| c.outcome == Outcome::Fail)
            .filter(|c| !(self.defects.accept_bad_signature && c.name == CheckName::Signature))
            .collect();
        // Protocol 9.5: a service does not use `owner`, so it also accepts an owner that is not a text.
        let only_owner = failed.len() == 1
            && failed[0].name == CheckName::Claims
            && failed[0].detail.contains("owner");
        if only_owner {
            let payload = token.split('.').nth(1).unwrap_or("");
            let bytes = procurauth_core::jws::b64url_decode(payload).unwrap_or_default();
            let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
            return value["sub"]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| empty(401));
        }
        if !failed.is_empty() {
            return Err(empty(401));
        }
        match inspection.claims {
            Some(claims) => Ok(claims.sub),
            None => Err(empty(401)),
        }
    }

    fn ask(&self, question: &Value) -> Result<Value, ()> {
        let body = question.to_string();
        let auth = format!("Bearer {}", self.credential);
        let mut headers = vec![("Content-Type", "application/json")];
        if !self.defects.no_credential {
            headers.push(("Authorization", auth.as_str()));
        }
        let reply = if self.defects.new_connection_each_time {
            call(
                self.pdp,
                "POST",
                "/access/v1/evaluation",
                &headers,
                Some(body.as_bytes()),
                Duration::from_millis(1500),
            )
            .map(|r| (r.status, r.body))
        } else {
            self.call_kept(
                &headers,
                body.as_bytes(),
                question.pointer("/context/usage").is_some(),
            )
        }
        .ok_or(())?;
        if reply.0 != 200 {
            return Err(());
        }
        serde_json::from_slice(&reply.1).map_err(|_| ())
    }

    /// One request on a connection that stays open between questions.
    ///
    /// A question with usage is never sent again (protocol 10.6). Another question is sent
    /// again one time, when a connection that the mock reused was closed by the PDP.
    fn call_kept(
        &self,
        headers: &[(&str, &str)],
        body: &[u8],
        usage: bool,
    ) -> Option<(u16, Vec<u8>)> {
        let mut slot = self.connection.lock().unwrap();
        for attempt in 0..2 {
            let reused = slot.is_some();
            if slot.is_none() {
                let stream =
                    TcpStream::connect_timeout(&self.pdp, Duration::from_millis(1500)).ok()?;
                stream
                    .set_read_timeout(Some(Duration::from_millis(1500)))
                    .ok()?;
                *slot = Some(stream);
            }
            let stream = slot.as_mut()?;
            let mut head = format!(
                "POST /access/v1/evaluation HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n",
                self.pdp,
                body.len()
            );
            for (n, v) in headers {
                head.push_str(&format!("{n}: {v}\r\n"));
            }
            head.push_str("\r\n");
            let sent = stream
                .write_all(head.as_bytes())
                .and_then(|()| stream.write_all(body));
            let answer = match sent {
                Ok(()) => read_answer(stream),
                Err(_) => Err(Failed::Closed),
            };
            match answer {
                Ok(answer) => return Some(answer),
                Err(why) => {
                    *slot = None;
                    let again = reused && why == Failed::Closed && !usage && attempt == 0;
                    if !again {
                        return None;
                    }
                }
            }
        }
        None
    }

    fn use_flow(
        &self,
        req: &Req,
        action: &str,
        resource: Value,
        usage: bool,
        ceilings: &[&str],
    ) -> Resp {
        let sub = match self.subject_of(req) {
            Ok(sub) => sub,
            Err(response) => return response,
        };
        let key = format!("{sub}|{action}|{resource}");
        if self.defects.cache_true_answers && self.cache.lock().unwrap().contains(&key) {
            return Resp::json(200, &json!({"ok": true}));
        }
        let mut question = json!({
            "subject": {"type": "user", "id": sub},
            "action": {"name": action},
            "resource": resource,
        });
        if usage {
            question["context"] = json!({"usage": {"units": 1}});
        }
        let answer = match self.ask(&question) {
            Ok(answer) => answer,
            Err(()) => {
                return if self.defects.fail_open {
                    Resp::json(200, &json!({"ok": true}))
                } else {
                    empty(503)
                };
            }
        };
        let Ok(decision) = Decision::from_value(&answer) else {
            return empty(503);
        };
        let unknown_ceiling = decision
            .context
            .limits
            .keys()
            .any(|name| !ceilings.contains(&name.as_str()));
        if decision.allows(usage) && !unknown_ceiling {
            if self.defects.cache_true_answers {
                self.cache.lock().unwrap().push(key);
            }
            return Resp::json(200, &json!({"ok": true}));
        }
        if !decision.decision {
            if decision.context.reason == Some(Reason::BudgetExceeded)
                && let Some(seconds) = decision.context.retry_after
            {
                return if self.defects.budget_as_403 {
                    empty(403)
                } else {
                    Resp::new(429)
                        .header("Retry-After", &seconds.to_string())
                        .header("Content-Type", "application/json")
                };
            }
            if self.defects.leak_reason {
                let reason = decision
                    .context
                    .reason
                    .map(|r| r.as_str().to_owned())
                    .unwrap_or_default();
                return Resp::json(403, &json!({"error": "forbidden", "reason": reason}));
            }
        }
        Resp::json(403, &json!({"error": "forbidden"}))
    }

    fn handle(&self, req: Req) -> Resp {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/.well-known/procurauth/actions") => Resp::json(200, &document()),
            ("GET", "/write/orders") => {
                self.use_flow(&req, "data.write", node("orders"), false, &[])
            }
            ("GET", "/read/orders") => {
                self.use_flow(&req, "data.read", node("orders"), true, &["max_rows"])
            }
            ("GET", "/query/orders") => {
                self.use_flow(&req, "data.query", node("orders"), false, &["max_rows"])
            }
            ("GET", "/service") => self.use_flow(
                &req,
                "data.write",
                json!({"type": "service", "id": "datastore"}),
                false,
                &[],
            ),
            ("POST", "/__reset") => {
                self.cache.lock().unwrap().clear();
                Resp::json(200, &json!({"reset": true}))
            }
            _ => Resp::json(404, &json!({"error": "not found"})),
        }
    }
}

impl MockPep {
    /// Start the mock. It calls the PDP at `pdp`.
    pub fn start(pdp: SocketAddr, defects: Defects) -> Self {
        let state = Arc::new(State {
            connection: Mutex::new(None),
            pdp,
            credential: CREDENTIAL.to_owned(),
            keys: keys(),
            defects,
            cache: Mutex::new(Vec::new()),
        });
        let server = Server::start("127.0.0.1:0", move |req| state.handle(req));
        Self {
            addr: server.addr,
            server,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn stop(&self) {
        self.server.stop();
    }
}

/// The profile of the mock, as JSON. The PDP listens on `pdp_port`.
pub fn profile(pdp_port: u16, credential_file: Option<&str>, with_reset: bool) -> Value {
    let ed = examples()
        .join("test-edge-ed25519.pem")
        .display()
        .to_string();
    let es = examples().join("test-edge-es256.pem").display().to_string();
    let mut pep = json!({
        "service": "datastore",
        "token": {
            "header": TOKEN_HEADER,
            "iss": "https://edge.example",
            "max_age_seconds": 300,
            "skew_seconds": 30,
            "keys": [
                {"alg": "Ed25519", "kid": "edge-ed25519", "file": ed},
                {"alg": "ES256", "kid": "edge-es256", "file": es}
            ]
        },
        "pdp": {"listen": format!("127.0.0.1:{pdp_port}")},
        "operations": {
            "use_plain": {
                "method": "GET", "path": "/write/orders", "action": "data.write",
                "resource_type": "table", "resource_id": "orders", "ancestors": chain()
            },
            "use_budget": {
                "method": "GET", "path": "/read/orders", "action": "data.read",
                "resource_type": "table", "resource_id": "orders", "ancestors": chain()
            },
            "use_ceiling": {
                "method": "GET", "path": "/query/orders", "action": "data.query",
                "resource_type": "table", "resource_id": "orders", "ancestors": chain(),
                "ceiling": "max_rows", "ceiling_value": 100
            },
            "use_service": {
                "method": "GET", "path": "/service", "action": "data.write"
            }
        }
    });
    if let Some(file) = credential_file {
        pep["pdp"]["credential_file"] = json!(file);
    }
    if with_reset {
        pep["reset"] = json!({"method": "POST", "path": "/__reset"});
    }
    json!({"pep": pep, "timeouts": {"request_seconds": 5, "case_seconds": 60, "settle_ms": 25}})
}
