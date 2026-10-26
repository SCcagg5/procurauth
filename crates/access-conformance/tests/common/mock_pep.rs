//! A scripted mock of a PEP: a tiny service `datastore`. It behaves like a
//! correct PEP, with the options route and an MCP endpoint.
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
    /// The action `mcp.session` lists a budget. It is a feature of the service, not a defect.
    pub session_budget: bool,
    /// A request to the options route with a bad parameter gets HTTP 200, not 400.
    pub options_accept_bad_parameters: bool,
    /// A `tools/call` of a refused tool gets a different error from an unknown tool.
    pub refused_tool_differs: bool,
    /// The PEP asks the PDP with usage before it asks the other permission.
    pub usage_before_other_permission: bool,
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
    approvals: Mutex<Vec<(String, String, String, Value)>>,
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
             "description": "Query data.", "limits": ["max_rows"]},
            {"name": "data.copy", "resource_types": ["table"],
             "description": "Copy a table.", "limits": ["requests"]},
            {"name": "data.drop", "resource_types": ["table"],
             "description": "Drop a table.", "limits": ["requests"]},
            {"name": "mcp.session", "resource_types": ["service"],
             "description": "Use an MCP session."}
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

    /// Ask the PDP and apply the answer, as a PEP does (protocol 10.2, 10.3, 6.12, 7.5).
    fn decide(
        &self,
        sub: &str,
        action: &str,
        resource: &Value,
        usage: bool,
        ceilings: &[&str],
    ) -> Decided {
        let key = format!("{sub}|{action}|{resource}|{usage}");
        if self.defects.cache_true_answers && self.cache.lock().unwrap().contains(&key) {
            return Decided::Allowed;
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
                    Decided::Allowed
                } else {
                    Decided::Unavailable
                };
            }
        };
        let Ok(decision) = Decision::from_value(&answer) else {
            return Decided::Unavailable;
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
            return Decided::Allowed;
        }
        if !decision.decision {
            if decision.context.reason == Some(Reason::BudgetExceeded)
                && let Some(seconds) = decision.context.retry_after
            {
                return Decided::Budget(seconds);
            }
            return Decided::Denied(decision.context.reason.map(|r| r.as_str().to_owned()));
        }
        Decided::Denied(None)
    }

    /// Ask a question with `context.match` equal to `subtree`, for a display (protocol 4.4).
    fn visible(&self, sub: &str, action: &str, resource: &Value) -> Option<bool> {
        let question = json!({
            "subject": {"type": "user", "id": sub},
            "action": {"name": action},
            "resource": resource,
            "context": {"match": "subtree"},
        });
        let answer = self.ask(&question).ok()?;
        Decision::from_value(&answer).ok().map(|d| d.decision)
    }

    fn http_answer(&self, decided: Decided) -> Resp {
        match decided {
            Decided::Allowed => Resp::json(200, &json!({"ok": true})),
            Decided::Budget(seconds) => {
                if self.defects.budget_as_403 {
                    empty(403)
                } else {
                    Resp::new(429)
                        .header("Retry-After", &seconds.to_string())
                        .header("Content-Type", "application/json")
                }
            }
            Decided::Denied(reason) => {
                if self.defects.leak_reason {
                    Resp::json(
                        403,
                        &json!({"error": "forbidden", "reason": reason.unwrap_or_default()}),
                    )
                } else {
                    Resp::json(403, &json!({"error": "forbidden"}))
                }
            }
            Decided::Unavailable => empty(503),
        }
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
        self.http_answer(self.decide(&sub, action, &resource, usage, ceilings))
    }

    /// A use that needs a second permission (protocol 5.5a, 10.1a).
    fn multi(&self, sub: &str, resource: &Value) -> Decided {
        if self.defects.usage_before_other_permission {
            match self.decide(sub, "data.copy", resource, true, &[]) {
                Decided::Allowed => {}
                other => return other,
            }
            return self.decide(sub, "data.read", resource, false, &["max_rows"]);
        }
        match self.decide(sub, "data.read", resource, false, &["max_rows"]) {
            Decided::Allowed => {}
            other => return other,
        }
        self.decide(sub, "data.copy", resource, true, &[])
    }

    // ----- The options route (protocol 5.6 to 5.8) -----

    fn options(&self, req: &Req) -> Resp {
        let sub = match self.subject_of(req) {
            Ok(sub) => sub,
            Err(response) => return response,
        };
        let bad = || {
            if self.defects.options_accept_bad_parameters {
                None
            } else {
                Some(Resp::json(400, &json!({"error": "bad request"})))
            }
        };
        let query = req.target.split_once('?').map_or("", |(_, q)| q);
        let mut params: std::collections::BTreeMap<String, String> =
            std::collections::BTreeMap::new();
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if !["parent", "type", "q", "limit", "after"].contains(&name) {
                continue;
            }
            let Some(value) = percent_decode(value) else {
                if let Some(response) = bad() {
                    return response;
                }
                continue;
            };
            if params.insert(name.to_owned(), value).is_some()
                && let Some(response) = bad()
            {
                return response;
            }
        }
        let Some(kind) = params.get("type").cloned() else {
            if let Some(response) = bad() {
                return response;
            }
            return Resp::json(200, &json!({"items": [], "next": null}));
        };
        let mut limit = 50_usize;
        if let Some(text) = params.get("limit") {
            match text.parse::<usize>() {
                Ok(n) if n >= 1 => limit = n.min(50),
                _ => {
                    if let Some(response) = bad() {
                        return response;
                    }
                }
            }
        }
        // The parent path: `type:id/type:id`, each id encoded again (protocol 5.2, 5.7).
        let mut parents: Vec<(String, String)> = Vec::new();
        if let Some(path) = params.get("parent") {
            for segment in path.split('/') {
                let parsed = segment
                    .split_once(':')
                    .and_then(|(t, id)| percent_decode(id).map(|id| (t.to_owned(), id)));
                match parsed {
                    Some(pair) => parents.push(pair),
                    None => {
                        if let Some(response) = bad() {
                            return response;
                        }
                    }
                }
            }
        }
        let parent_type = parents.last().map_or("service", |(t, _)| t.as_str());
        let expected_parent = match kind.as_str() {
            "host" => "service",
            "database" => "host",
            "table" => "database",
            _ => "",
        };
        if expected_parent != parent_type {
            if let Some(response) = bad() {
                return response;
            }
            return Resp::json(200, &json!({"items": [], "next": null}));
        }
        let ids: &[&str] = match (kind.as_str(), parents.last().map(|(_, id)| id.as_str())) {
            ("host", _) => &["prod", "staging"],
            ("database", Some("prod")) => &["test1", "test2"],
            ("table", Some("test1")) => &["orders", "items"],
            _ => &[],
        };
        let mut chain = vec![json!({"type": "service", "id": "datastore"})];
        chain.extend(parents.iter().map(|(t, id)| json!({"type": t, "id": id})));
        let after: usize = params
            .get("after")
            .and_then(|a| a.strip_prefix("after:"))
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        let needle = params.get("q").cloned().unwrap_or_default();
        let mut items = Vec::new();
        let mut next = Value::Null;
        for (index, id) in ids.iter().enumerate().skip(after) {
            if !id.contains(&needle) {
                continue;
            }
            if items.len() >= limit {
                next = json!(format!("after:{index}"));
                break;
            }
            let resource = json!({"type": kind, "id": id, "properties": {"ancestors": chain}});
            match self.visible(&sub, "data.read", &resource) {
                Some(true) => items.push(json!({
                    "id": id,
                    "label": id,
                    "has_children": kind != "table",
                })),
                Some(false) => {}
                None => return empty(503),
            }
        }
        Resp::json(200, &json!({"items": items, "next": next}))
    }

    // ----- The MCP endpoint (binding sections 3 to 5) -----

    fn rpc_error(status: u16, id: &Value, code: i64, message: &str, data: Option<Value>) -> Resp {
        let mut error = json!({"code": code, "message": message});
        if let Some(data) = data {
            error["data"] = data;
        }
        Resp::json(status, &json!({"jsonrpc": "2.0", "id": id, "error": error}))
    }

    fn rpc_result(id: &Value, result: &Value) -> Resp {
        Resp::json(200, &json!({"jsonrpc": "2.0", "id": id, "result": result}))
    }

    fn tool_answer(&self, id: &Value, decided: Decided, success: Value) -> Resp {
        match decided {
            Decided::Allowed => Self::rpc_result(id, &success),
            Decided::Denied(reason) => {
                if self.defects.refused_tool_differs && reason.is_none() {
                    return Self::rpc_error(200, id, -32001, "forbidden", None);
                }
                Self::rpc_error(200, id, -32602, "Invalid params", None)
            }
            Decided::Budget(seconds) => {
                let structured = json!({"error": {
                    "code": "budget_exceeded",
                    "message": "The budget of this action is spent.",
                    "retryable": true,
                    "retry_after": seconds,
                }});
                Self::rpc_result(
                    id,
                    &json!({
                        "resultType": "complete",
                        "content": [{"type": "text", "text": structured.to_string()}],
                        "structuredContent": structured,
                        "isError": true,
                    }),
                )
            }
            Decided::Unavailable => Self::rpc_error(503, id, -32603, "Internal error", None),
        }
    }

    fn mcp(&self, req: &Req) -> Resp {
        let sub = match self.subject_of(req) {
            Ok(sub) => sub,
            Err(response) => return response,
        };
        let Ok(body) = serde_json::from_slice::<Value>(&req.body) else {
            return Self::rpc_error(400, &Value::Null, -32700, "Parse error", None);
        };
        let id = body.get("id").cloned().unwrap_or(Value::Null);
        let header_version = req.header("MCP-Protocol-Version");
        let meta_version = body
            .pointer("/params/_meta/io.modelcontextprotocol~1protocolVersion")
            .and_then(Value::as_str);
        if let (Some(header), Some(meta)) = (header_version, meta_version)
            && header != meta
        {
            return Self::rpc_error(400, &id, -32020, "Unsupported protocol version", None);
        }
        let ok_result = json!({
            "resultType": "complete",
            "content": [{"type": "text", "text": "ok"}],
            "isError": false,
        });
        let method = body.get("method").and_then(Value::as_str).unwrap_or("");
        let service = json!({"type": "service", "id": "datastore"});
        match method {
            "tools/list" => {
                let mut tools = Vec::new();
                let mut seen: Vec<(&str, bool)> = Vec::new();
                for (name, action, _) in TOOLS {
                    let known = seen.iter().find(|(a, _)| **a == *action).map(|(_, v)| *v);
                    let visible = match known {
                        Some(visible) => visible,
                        None => {
                            let Some(visible) = self.visible(&sub, action, &service) else {
                                return Self::rpc_error(503, &id, -32603, "Internal error", None);
                            };
                            seen.push((action, visible));
                            visible
                        }
                    };
                    if visible {
                        tools.push(json!({"name": name, "description": "A tool.", "inputSchema": {"type": "object"}}));
                    }
                }
                Self::rpc_result(&id, &json!({"tools": tools}))
            }
            "tools/call" => {
                let name = body
                    .pointer("/params/name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let Some((_, action, kind)) = TOOLS.iter().find(|(n, _, _)| *n == name) else {
                    return Self::rpc_error(200, &id, -32602, "Invalid params", None);
                };
                let resource = node("orders");
                match kind {
                    ToolKind::Budget => self.tool_answer(
                        &id,
                        self.decide(&sub, action, &resource, true, &["max_rows"]),
                        ok_result,
                    ),
                    ToolKind::Plain => self.tool_answer(
                        &id,
                        self.decide(&sub, action, &resource, false, &[]),
                        ok_result,
                    ),
                    ToolKind::Input => {
                        let decided = self.decide(&sub, action, &resource, false, &[]);
                        let result = json!({
                            "resultType": "input_required",
                            "inputRequests": {"confirm": {"type": "confirmation"}},
                        });
                        self.tool_answer(&id, decided, result)
                    }
                    ToolKind::Multi => {
                        self.tool_answer(&id, self.multi(&sub, &resource), ok_result)
                    }
                    ToolKind::Approval => {
                        let decided = self.decide(&sub, action, &resource, false, &[]);
                        let mut approvals = self.approvals.lock().unwrap();
                        let approval = format!("A{}", approvals.len() + 1);
                        approvals.push((
                            approval.clone(),
                            sub.clone(),
                            (*action).to_owned(),
                            resource,
                        ));
                        let result = json!({
                            "resultType": "complete",
                            "content": [{"type": "text", "text": "waiting for an approval"}],
                            "structuredContent": {"approval_id": approval, "status": "pending"},
                            "isError": false,
                        });
                        drop(approvals);
                        self.tool_answer(&id, decided, result)
                    }
                }
            }
            "approvals/decide" => {
                let approval = body
                    .pointer("/params/approval_id")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let approve = body.pointer("/params/approve") == Some(&json!(true));
                let found = {
                    let mut approvals = self.approvals.lock().unwrap();
                    approvals
                        .iter()
                        .position(|(a, _, _, _)| a == approval)
                        .map(|index| approvals.remove(index))
                };
                let Some((_, owner, action, resource)) = found else {
                    return Self::rpc_error(200, &id, -32602, "Invalid params", None);
                };
                if owner != sub || !approve {
                    return Self::rpc_result(
                        &id,
                        &json!({"resultType": "complete", "content": [{"type": "text", "text": "refused"}], "isError": false}),
                    );
                }
                self.tool_answer(
                    &id,
                    self.decide(&sub, &action, &resource, true, &[]),
                    ok_result,
                )
            }
            _ => {
                // A method with no tool asks the action `mcp.session` on the service (binding 3.6a).
                match self.decide(
                    &sub,
                    "mcp.session",
                    &service,
                    self.defects.session_budget,
                    &[],
                ) {
                    Decided::Allowed => Self::rpc_result(&id, &json!({})),
                    Decided::Denied(_) => Self::rpc_error(403, &id, -32001, "forbidden", None),
                    Decided::Budget(seconds) => {
                        let mut response = Self::rpc_error(
                            429,
                            &id,
                            -31429,
                            "rate_limited",
                            Some(json!({"retry_after": seconds})),
                        );
                        response = response.header("Retry-After", &seconds.to_string());
                        response
                    }
                    Decided::Unavailable => {
                        Self::rpc_error(503, &id, -32603, "Internal error", None)
                    }
                }
            }
        }
    }

    fn handle(&self, req: Req) -> Resp {
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/.well-known/procurauth/actions") => Resp::json(200, &document()),
            ("GET", "/.well-known/procurauth/resources") => self.options(&req),
            ("GET", "/write/orders") => {
                self.use_flow(&req, "data.write", node("orders"), false, &[])
            }
            ("GET", "/read/orders") => {
                self.use_flow(&req, "data.read", node("orders"), true, &["max_rows"])
            }
            ("GET", "/query/orders") => {
                self.use_flow(&req, "data.query", node("orders"), false, &["max_rows"])
            }
            ("GET", "/copy/orders") => {
                let sub = match self.subject_of(&req) {
                    Ok(sub) => sub,
                    Err(response) => return response,
                };
                self.http_answer(self.multi(&sub, &node("orders")))
            }
            ("GET", "/service") => self.use_flow(
                &req,
                "data.write",
                json!({"type": "service", "id": "datastore"}),
                false,
                &[],
            ),
            ("POST", "/mcp") => self.mcp(&req),
            ("POST", "/__reset") => {
                self.cache.lock().unwrap().clear();
                self.approvals.lock().unwrap().clear();
                Resp::json(200, &json!({"reset": true}))
            }
            _ => Resp::json(404, &json!({"error": "not found"})),
        }
    }
}

/// What the PDP decided, as the PEP applies it.
enum Decided {
    Allowed,
    Denied(Option<String>),
    Budget(u64),
    Unavailable,
}

#[derive(Clone, Copy)]
enum ToolKind {
    Plain,
    Budget,
    Input,
    Multi,
    Approval,
}

/// The tools of the mock: the name, the action and the kind.
const TOOLS: [(&str, &str, ToolKind); 6] = [
    ("read_rows", "data.read", ToolKind::Budget),
    ("write_rows", "data.write", ToolKind::Plain),
    ("confirm", "data.write", ToolKind::Input),
    ("copy_table", "data.copy", ToolKind::Multi),
    ("drop_table", "data.drop", ToolKind::Approval),
    ("query_rows", "data.query", ToolKind::Plain),
];

/// Decode a percent-encoded text. A bad escape gives `None`. A plus is a plus (protocol 5.7).
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
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
            approvals: Mutex::new(Vec::new()),
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

/// The parts of the mock that the profile names.
#[derive(Clone, Copy)]
pub struct Features {
    pub options: bool,
    pub mcp: bool,
    pub multi: bool,
    pub session_budget: bool,
}

impl Features {
    /// A service with no options route, no MCP endpoint and no use with two permissions.
    pub const fn basic() -> Self {
        Self {
            options: false,
            mcp: false,
            multi: false,
            session_budget: false,
        }
    }

    /// A service with each part.
    pub const fn full() -> Self {
        Self {
            options: true,
            mcp: true,
            multi: true,
            session_budget: false,
        }
    }
}

/// The profile of the mock, as JSON. The PDP listens on `pdp_port`.
pub fn profile(pdp_port: u16, credential_file: Option<&str>, with_reset: bool) -> Value {
    profile_with(pdp_port, credential_file, with_reset, Features::basic())
}

/// The profile of the mock with the parts that `features` names.
pub fn profile_with(
    pdp_port: u16,
    credential_file: Option<&str>,
    with_reset: bool,
    features: Features,
) -> Value {
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
    if features.options {
        pep["options_type"] = json!("host");
    }
    if features.multi {
        pep["operations"]["use_multi"] = json!({
            "method": "GET", "path": "/copy/orders", "action": "data.copy",
            "resource_type": "table", "resource_id": "orders", "ancestors": chain()
        });
    }
    if features.mcp {
        pep["mcp"] = json!({"path": "/mcp", "session_budget": features.session_budget});
        let table = |tool: &str, action: &str| {
            json!({
                "tool": tool, "action": action, "arguments": {"table": "orders"},
                "resource_type": "table", "resource_id": "orders", "ancestors": chain()
            })
        };
        let ops = pep["operations"].as_object_mut().unwrap();
        ops.insert("mcp_call_plain".into(), table("write_rows", "data.write"));
        ops.insert("mcp_call_budget".into(), table("read_rows", "data.read"));
        ops.insert("mcp_call_input".into(), table("confirm", "data.write"));
        ops.insert("mcp_call_approval".into(), table("drop_table", "data.drop"));
        if features.multi {
            ops.insert("mcp_call_multi".into(), table("copy_table", "data.copy"));
        }
        let decide = |approve: bool| {
            json!({
                "body": {
                    "jsonrpc": "2.0", "id": 7, "method": "approvals/decide",
                    "params": {
                        "approval_id": "{{approval_id}}", "approve": approve,
                        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}
                    }
                },
                "capture": {"approval_id": "/result/structuredContent/approval_id"}
            })
        };
        ops.insert("mcp_approve".into(), decide(true));
        ops.insert("mcp_refuse".into(), decide(false));
    }
    json!({"pep": pep, "timeouts": {"request_seconds": 5, "case_seconds": 60, "settle_ms": 25}})
}
