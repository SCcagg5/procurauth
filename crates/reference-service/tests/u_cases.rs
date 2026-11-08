//! The cases of the series U of `conformance/cases/U/`, run against the reference service.
//!
//! The runner `access-conformance` does this work for any service. This test is a small
//! local runner for the reference service only. It follows `PROFILE.md` and the rules of
//! `conformance/README.md`. The rules cover the identity tokens, the script of the test PDP,
//! the operations, the variables, the matchers and the conditions to skip. A case that fails
//! here shows a difference between the service and the cases.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use access_token::cli::AlgName;
use access_token::make::{Shape, make_token};
use common::{Reply, now, send};
use procurauth_core::jws::SigningKey;
use reference_service::config::{Sources, load};
use reference_service::service::build_app;
use regex::Regex;
use serde_json::{Map, Value, json};

const SERVICE: &str = "datastore";
const ED_KID: &str = "edge-ed25519";
const ES_KID: &str = "edge-es256";

// ---- The test PDP with a script -------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Question {
    body: Value,
    headers: Vec<(String, String)>,
}

/// A request that the test PDP received on its approval API.
#[derive(Clone, Debug)]
struct ApprovalReq {
    route: &'static str,
    json: Value,
    query: BTreeMap<String, String>,
}

struct PdpState {
    script: Vec<Value>,
    approval_script: Vec<Value>,
    questions: Vec<Question>,
    approvals: Vec<ApprovalReq>,
}

struct ScriptedPdp {
    state: Arc<Mutex<PdpState>>,
    connections: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    accept: Option<thread::JoinHandle<()>>,
    workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>>,
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// The method, the path, the headers and the body of a request.
type RawRequest = (String, String, Vec<(String, String)>, Vec<u8>);

fn read_request(stream: &mut TcpStream, stop: &AtomicBool) -> Option<RawRequest> {
    let mut data = Vec::new();
    let mut chunk = [0_u8; 4096];
    stream
        .set_read_timeout(Some(Duration::from_millis(50)))
        .ok()?;
    loop {
        if let Some(end) = find(&data, b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&data[..end]).into_owned();
            let mut lines = head.split("\r\n");
            let mut first = lines.next()?.split(' ');
            let method = first.next()?.to_owned();
            let path = first.next()?.to_owned();
            let headers: Vec<(String, String)> = lines
                .filter_map(|l| l.split_once(':'))
                .map(|(n, v)| (n.to_owned(), v.trim().to_owned()))
                .collect();
            let length = headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("content-length"))
                .and_then(|(_, v)| v.parse::<usize>().ok())
                .unwrap_or(0);
            if data.len() >= end + 4 + length {
                return Some((
                    method,
                    path,
                    headers,
                    data[end + 4..end + 4 + length].to_vec(),
                ));
            }
        }
        match stream.read(&mut chunk) {
            Ok(0) => return None,
            Ok(n) => data.extend_from_slice(&chunk[..n]),
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if stop.load(Ordering::SeqCst) {
                    return None;
                }
            }
            Err(_) => return None,
        }
    }
}

fn respond(stream: &mut TcpStream, status: u16, body: &Value) {
    let text = body.to_string();
    let reply = format!(
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{text}",
        text.len()
    );
    let _ = stream.write_all(reply.as_bytes());
}

fn text_of(value: &Value) -> String {
    match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

fn rule_matches(when: &Value, question: &Value) -> bool {
    let Some(map) = when.as_object() else {
        return false;
    };
    map.iter().all(|(key, expected)| match key.as_str() {
        "subject" => question.pointer("/subject/id") == Some(expected),
        "action" => question.pointer("/action/name") == Some(expected),
        "usage" => question.pointer("/context/usage").is_some() == expected.as_bool().unwrap(),
        "match" => {
            question
                .pointer("/context/match")
                .map_or("node", |m| m.as_str().unwrap_or("node"))
                == expected.as_str().unwrap()
        }
        "effect" => question.pointer("/context/approval/effect") == Some(expected),
        other => panic!("the runner does not know the member `when.{other}`"),
    })
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && i + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(&text[i + 1..i + 3], 16)
        {
            out.push(byte);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}

/// The route and the id of a request to the approval API.
fn approval_route(method: &str, path: &str) -> Option<(&'static str, Option<String>)> {
    let target = path.split('?').next().unwrap();
    if target == "/approval/v1/requests" {
        return (method == "POST").then_some(("submit", None));
    }
    let tail = target.strip_prefix("/approval/v1/requests/")?;
    match tail.split_once('/') {
        None if method == "GET" => Some(("status", Some(percent_decode(tail)))),
        Some((id, "keepalive")) if method == "POST" => {
            Some(("keepalive", Some(percent_decode(id))))
        }
        _ => None,
    }
}

/// Answer a request of the approval API with the first rule that matches, or with 404.
fn approval_answer(script: &[Value], route: &str, request_id: Option<&str>) -> (u16, Value) {
    for rule in script {
        let when = &rule["when"];
        let route_ok = when.get("route").is_none_or(|r| r == route);
        let id_ok = when
            .get("request_id")
            .is_none_or(|i| i.as_str() == request_id);
        if route_ok && id_ok {
            let status = rule["respond"]
                .get("status")
                .and_then(Value::as_u64)
                .unwrap_or(200);
            return (
                u16::try_from(status).unwrap(),
                rule["respond"]["body"].clone(),
            );
        }
    }
    (404, json!({"error": "not_found"}))
}

/// The answer of the script to one question: a status and a body, or `None` for no answer.
fn answer_for(script: &[Value], question: &Value) -> Option<(u16, Value)> {
    for rule in script {
        if rule_matches(&rule["when"], question) {
            let respond = &rule["respond"];
            if respond.get("no_answer") == Some(&json!(true)) {
                return None;
            }
            if let Some(ms) = respond.get("delay_ms").and_then(Value::as_u64) {
                thread::sleep(Duration::from_millis(ms));
            }
            let status = respond.get("status").and_then(Value::as_u64).unwrap_or(200);
            return Some((u16::try_from(status).unwrap(), respond["body"].clone()));
        }
    }
    panic!("no rule of the script matches the question {question}");
}

fn serve_connection(mut stream: TcpStream, state: &Mutex<PdpState>, stop: &AtomicBool) {
    while let Some((method, path, headers, body)) = read_request(&mut stream, stop) {
        if let Some((route, request_id)) = approval_route(&method, &path) {
            let query: BTreeMap<String, String> = path
                .split_once('?')
                .map(|(_, q)| q)
                .unwrap_or("")
                .split('&')
                .filter(|p| !p.is_empty())
                .map(|p| {
                    let (n, v) = p.split_once('=').unwrap_or((p, ""));
                    (percent_decode(n), percent_decode(v))
                })
                .collect();
            let json = serde_json::from_slice(&body).unwrap_or(Value::Null);
            let (status, answer) = {
                let mut guard = state.lock().unwrap();
                guard.approvals.push(ApprovalReq { route, json, query });
                approval_answer(&guard.approval_script, route, request_id.as_deref())
            };
            respond(&mut stream, status, &answer);
            continue;
        }
        if method == "GET" {
            respond(&mut stream, 404, &json!({}));
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&body) else {
            respond(&mut stream, 400, &json!({}));
            continue;
        };
        let (questions, script) = {
            let mut guard = state.lock().unwrap();
            let script = guard.script.clone();
            let questions: Vec<Value> =
                if path.ends_with("/evaluations") && value.get("evaluations").is_some() {
                    if value.to_string().contains("\"usage\"") {
                        // 6.11: a request with items and `context.usage` gets HTTP 400.
                        guard.questions.push(Question {
                            body: value.clone(),
                            headers: headers.clone(),
                        });
                        drop(guard);
                        respond(&mut stream, 400, &json!({}));
                        continue;
                    }
                    value["evaluations"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|item| {
                            let mut q = item.clone();
                            for key in ["subject", "action", "resource"] {
                                if q.get(key).is_none() && value.get(key).is_some() {
                                    q[key] = value[key].clone();
                                }
                            }
                            if q.get("context").is_none() && value.get("context").is_some() {
                                q["context"] = value["context"].clone();
                            }
                            q
                        })
                        .collect()
                } else {
                    vec![value.clone()]
                };
            for q in &questions {
                guard.questions.push(Question {
                    body: q.clone(),
                    headers: headers.clone(),
                });
            }
            (questions, script)
        };
        let is_batch = path.ends_with("/evaluations") && value.get("evaluations").is_some();
        let mut answers = Vec::new();
        let mut silent = false;
        for q in &questions {
            match answer_for(&script, q) {
                None => {
                    silent = true;
                    break;
                }
                Some(a) => answers.push(a),
            }
        }
        if silent {
            // No answer: hold the connection until the service gives up.
            let until = Instant::now() + Duration::from_secs(4);
            while Instant::now() < until && !stop.load(Ordering::SeqCst) {
                thread::sleep(Duration::from_millis(50));
            }
            return;
        }
        if is_batch {
            let status = answers
                .iter()
                .map(|(s, _)| *s)
                .find(|s| *s != 200)
                .unwrap_or(200);
            respond(
                &mut stream,
                status,
                &json!({"evaluations": answers.iter().map(|(_, b)| b.clone()).collect::<Vec<_>>()}),
            );
        } else {
            let (status, body) = answers.remove(0);
            // A body that is a text is sent as a JSON text.
            respond(&mut stream, status, &body);
        }
    }
}

impl ScriptedPdp {
    fn start(addr: SocketAddr, script: Vec<Value>, approval_script: Vec<Value>) -> Self {
        let listener = (0..50)
            .find_map(|_| match TcpListener::bind(addr) {
                Ok(l) => Some(l),
                Err(_) => {
                    thread::sleep(Duration::from_millis(100));
                    None
                }
            })
            .expect("the port of the test PDP");
        listener.set_nonblocking(true).unwrap();
        let state = Arc::new(Mutex::new(PdpState {
            script,
            approval_script,
            questions: Vec::new(),
            approvals: Vec::new(),
        }));
        let connections = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let workers: Arc<Mutex<Vec<thread::JoinHandle<()>>>> = Arc::default();
        let accept = {
            let (state, connections, stop) = (
                Arc::clone(&state),
                Arc::clone(&connections),
                Arc::clone(&stop),
            );
            let workers = Arc::clone(&workers);
            thread::spawn(move || {
                while !stop.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream.set_nonblocking(false).unwrap();
                            connections.fetch_add(1, Ordering::SeqCst);
                            let (state, stop) = (Arc::clone(&state), Arc::clone(&stop));
                            let handle =
                                thread::spawn(move || serve_connection(stream, &state, &stop));
                            workers.lock().unwrap().push(handle);
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            })
        };
        Self {
            state,
            connections,
            stop,
            accept: Some(accept),
            workers,
        }
    }

    fn questions(&self) -> Vec<Question> {
        self.state.lock().unwrap().questions.clone()
    }

    fn clear_questions(&self) {
        let mut state = self.state.lock().unwrap();
        state.questions.clear();
        state.approvals.clear();
    }

    fn approvals(&self) -> Vec<ApprovalReq> {
        self.state.lock().unwrap().approvals.clone()
    }
}

impl Drop for ScriptedPdp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
        // Each connection ends and closes its socket before the next case starts.
        let handles: Vec<_> = self.workers.lock().unwrap().drain(..).collect();
        for h in handles {
            let _ = h.join();
        }
    }
}

// ---- The tokens ---------------------------------------------------------------------------------------------------

struct Keys {
    ed: SigningKey,
    es: SigningKey,
}

fn make_case_token(keys: &Keys, spec: &Value) -> String {
    let es = spec.get("alg").and_then(Value::as_str) == Some("ES256");
    let key = if es { &keys.es } else { &keys.ed };
    let mut claims = json!({
        "iss": "https://edge.example", "sub": spec["subject"], "aud": SERVICE,
        "iat": now() - 10, "exp": now() + 290,
    });
    if let Some(owner) = spec.get("owner") {
        claims["owner"] = owner.clone();
    }
    let mut shape = Shape {
        alg: None,
        typ: None,
        kid: Some(if es { ES_KID } else { ED_KID }.to_owned()),
        crit: None,
        bad_signature: false,
    };
    let mut header_overrides = Map::new();
    match spec.get("defect").and_then(Value::as_str) {
        None => {}
        Some("bad_signature") => shape.bad_signature = true,
        Some("expired") => {
            claims["iat"] = json!(now() - 200);
            claims["exp"] = json!(now() - 100);
        }
        Some("future_iat") => {
            claims["iat"] = json!(now() + 100);
            claims["exp"] = json!(now() + 300);
        }
        Some("long_life") => claims["exp"] = json!(now() + 3600),
        Some("at_jwt") => shape.typ = Some("at+jwt".into()),
        Some("alg_none") => shape.alg = Some(AlgName::None),
        Some("alg_hs256") => shape.alg = Some(AlgName::Hs256),
        Some("alg_eddsa") => shape.alg = Some(AlgName::EdDsa),
        Some("wrong_issuer") => claims["iss"] = json!("https://other.example"),
        Some("wrong_audience") => claims["aud"] = json!("other-service"),
        Some("unknown_kid") => shape.kid = Some("unknown-kid".into()),
        Some(other) => panic!("unknown defect {other}"),
    }
    if let Some(map) = spec.get("claims").and_then(Value::as_object) {
        for (k, v) in map {
            if v.is_null() {
                claims.as_object_mut().unwrap().remove(k);
            } else {
                claims[k] = v.clone();
            }
        }
    }
    if let Some(map) = spec.get("header").and_then(Value::as_object) {
        for (k, v) in map {
            header_overrides.insert(k.clone(), v.clone());
        }
    }
    // A header member that the case sets replaces the member of the shape.
    for (k, v) in &header_overrides {
        match (k.as_str(), v) {
            ("typ", Value::Null) => shape.typ = Some(String::new()),
            ("typ", Value::String(t)) => shape.typ = Some(t.clone()),
            ("kid", Value::String(t)) => shape.kid = Some(t.clone()),
            ("kid", Value::Null) => shape.kid = None,
            other => panic!("the runner does not set the header member {other:?}"),
        }
    }
    let token = make_token(&shape, &claims, key).token;
    if header_overrides.get("typ") == Some(&Value::Null) {
        return without_typ(&token);
    }
    token
}

/// Make a token whose header has no `typ`: sign again with a header that the case chose.
fn without_typ(token: &str) -> String {
    use base64::Engine as _;
    let parts: Vec<&str> = token.split('.').collect();
    let header = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(parts[0])
        .unwrap();
    let mut header: Value = serde_json::from_slice(&header).unwrap();
    header.as_object_mut().unwrap().remove("typ");
    let payload: Value = serde_json::from_slice(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .unwrap(),
    )
    .unwrap();
    // The signing key is the Ed25519 key of the test edge.
    let key = SigningKey::from_ed25519_seed(&[7; 32]);
    procurauth_core::jws::sign_compact(&header, &payload, &key)
}

// ---- Variables and matchers ----------------------------------------------------------------------------------------------------------------

type Vars = BTreeMap<String, Value>;

fn subst_text(text: &str, vars: &Vars, escape: bool) -> Value {
    let re = Regex::new(r"\{\{([a-z_0-9]+)\}\}").unwrap();
    if let Some(c) = re.captures(text)
        && c.get(0).unwrap().as_str() == text
        && !escape
    {
        return vars
            .get(&c[1])
            .unwrap_or_else(|| panic!("unknown variable {}", &c[1]))
            .clone();
    }
    let out = re.replace_all(text, |c: &regex::Captures<'_>| {
        let v = vars
            .get(&c[1])
            .unwrap_or_else(|| panic!("unknown variable {}", &c[1]));
        let t = text_of(v);
        if escape { regex::escape(&t) } else { t }
    });
    Value::String(out.into_owned())
}

fn subst(value: &Value, vars: &Vars, escape: bool) -> Value {
    match value {
        Value::String(s) => subst_text(s, vars, escape),
        Value::Array(items) => Value::Array(items.iter().map(|v| subst(v, vars, escape)).collect()),
        Value::Object(map) => {
            let mut out = Map::new();
            for (k, v) in map {
                let key = text_of(&subst_text(k, vars, false));
                let esc = escape || k == "regex" || k == "not_regex";
                out.insert(key, subst(v, vars, esc));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

fn matches(matcher: &Value, actual: Option<&Value>) -> bool {
    let map = matcher.as_object().unwrap();
    assert_eq!(map.len(), 1, "a matcher has one member");
    let (kind, arg) = map.iter().next().unwrap();
    match kind.as_str() {
        "equals" => actual == Some(arg),
        "absent" => actual.is_none(),
        "present" => actual.is_some(),
        "regex" => actual.is_some_and(|a| {
            Regex::new(arg.as_str().unwrap())
                .unwrap()
                .is_match(&text_of(a))
        }),
        "not_regex" => actual.is_none_or(|a| {
            !Regex::new(arg.as_str().unwrap())
                .unwrap()
                .is_match(&text_of(a))
        }),
        "one_of" => actual.is_some_and(|a| arg.as_array().unwrap().contains(a)),
        other => panic!("unknown matcher {other}"),
    }
}

// ---- The profile -------------------------------------------------------------------------------------------------------------------------------

fn ancestors(path: &[(&str, &str)]) -> Value {
    json!(
        path.iter()
            .map(|(t, i)| json!({"type": t, "id": i}))
            .collect::<Vec<_>>()
    )
}

fn table_chain() -> Value {
    ancestors(&[
        ("service", SERVICE),
        ("host", "prod"),
        ("database", "test2"),
    ])
}

/// The operation `mcp_call_approval` of the profile of the service. The profile gives the tool,
/// the arguments, the node and the `op` of each call, as `PROFILE.md` says.
fn approval_profile() -> Value {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/conformance-profile.json");
    let profile: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    profile["pep"]["operations"]["mcp_call_approval"].clone()
}

/// The effects of the base call and of the two variants (protocol 17.3).
fn approval_effects(def: &Value) -> [String; 3] {
    use procurauth_core::effect::{effect_hash, resource_text};
    use procurauth_core::path::{NodePath, NodeRef};
    let mut nodes: Vec<NodeRef> = def["ancestors"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| NodeRef::new(a["type"].as_str().unwrap(), a["id"].as_str().unwrap()))
        .collect();
    nodes.push(NodeRef::new(
        def["resource_type"].as_str().unwrap(),
        def["resource_id"].as_str().unwrap(),
    ));
    let resource = resource_text(&NodePath::from_nodes(nodes).unwrap());
    let effect =
        |op: &Value| effect_hash(SERVICE, def["action"].as_str().unwrap(), &resource, op).unwrap();
    [
        effect(&def["approval"]["op"]),
        effect(&def["approval"]["variants"]["effect_2"]["op"]),
        effect(&def["approval"]["variants"]["effect_3"]["op"]),
    ]
}

fn operation_vars(op: &str) -> Vars {
    let mut v = Vars::new();
    let mut set = |k: &str, val: Value| {
        v.insert(k.to_owned(), val);
    };
    match op {
        "use_plain" => {
            set("action", json!("data.inspect"));
            set("resource_type", json!("table"));
            set("resource_id", json!("orders"));
            set("ancestors", table_chain());
        }
        "use_budget" | "use_ceiling" => {
            set("action", json!("data.read"));
            set("resource_type", json!("table"));
            set("resource_id", json!("orders"));
            set("ancestors", table_chain());
            set("ceiling", json!("max_rows"));
            set("ceiling_value", json!(100));
        }
        "use_service" => {
            set("action", json!("data.inspect"));
            set("resource_type", json!("service"));
            set("resource_id", json!(SERVICE));
        }
        "use_multi" | "mcp_call_multi" => {
            set("action", json!("data.write"));
            set("resource_type", json!("database"));
            set("resource_id", json!("test2"));
            set(
                "ancestors",
                ancestors(&[("service", SERVICE), ("host", "prod")]),
            );
            if op == "mcp_call_multi" {
                set("tool", json!("copy_table"));
            }
        }
        "mcp_call_plain" => {
            set("tool", json!("list_tables"));
            set("action", json!("data.inspect"));
            set("resource_type", json!("database"));
            set("resource_id", json!("test2"));
            set(
                "ancestors",
                ancestors(&[("service", SERVICE), ("host", "prod")]),
            );
        }
        "mcp_call_budget" => {
            set("tool", json!("read_rows"));
            set("action", json!("data.read"));
            set("resource_type", json!("table"));
            set("resource_id", json!("orders"));
            set("ancestors", table_chain());
        }
        "mcp_call_input" => {
            set("tool", json!("query_table"));
            set("action", json!("data.read"));
            set("resource_type", json!("database"));
            set("resource_id", json!("test2"));
            set(
                "ancestors",
                ancestors(&[("service", SERVICE), ("host", "prod")]),
            );
        }
        "mcp_call_approval" => {
            let def = approval_profile();
            for name in [
                "tool",
                "action",
                "resource_type",
                "resource_id",
                "ancestors",
            ] {
                set(name, def[name].clone());
            }
            let [base, second, third] = approval_effects(&def);
            set("effect", json!(base));
            set("effect_2", json!(second));
            set("effect_3", json!(third));
        }
        _ => {}
    }
    v
}

struct Built {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

fn mcp_headers() -> Vec<(String, String)> {
    vec![
        ("Content-Type".into(), "application/json".into()),
        (
            "Accept".into(),
            "application/json, text/event-stream".into(),
        ),
        ("MCP-Protocol-Version".into(), "2026-07-28".into()),
    ]
}

fn tools_call(name: &str, arguments: Value, extra: Value) -> Vec<u8> {
    let mut params = json!({"name": name, "arguments": arguments,
        "_meta": {"io.modelcontextprotocol/protocolVersion": "2026-07-28"}});
    if let Some(map) = extra.as_object() {
        for (k, v) in map {
            params[k] = v.clone();
        }
    }
    json!({"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": params})
        .to_string()
        .into_bytes()
}

/// The call of `mcp_call_approval`, with the control arguments of the base call and a variant.
fn approval_call(variant: Option<&str>) -> Vec<u8> {
    let def = approval_profile();
    let mut arguments = match variant {
        Some("effect_2" | "effect_3") => {
            def["approval"]["variants"][variant.unwrap()]["arguments"].clone()
        }
        _ => def["arguments"].clone(),
    };
    if variant == Some("approval_ref") {
        arguments["approval_ref"] = json!("ref_conformance_0001");
    } else {
        arguments["lease_s"] = json!(900);
    }
    if variant == Some("wait") {
        arguments["wait_s"] = json!(1);
    }
    tools_call(def["tool"].as_str().unwrap(), arguments, json!({}))
}

fn build_operation(op: &str, variant: Option<&str>) -> Built {
    let table = "/hosts/prod/databases/test2/tables/orders";
    let get = |path: String| Built {
        method: "GET".into(),
        path,
        headers: vec![],
        body: None,
    };
    let orders = json!({"host": "prod", "database": "test2", "table": "orders"});
    let copy = json!({"from": {"host": "prod", "database": "test1", "table": "orders"}, "to": {"host": "prod", "database": "test2"}});
    let mcp = |body: Vec<u8>| Built {
        method: "POST".into(),
        path: "/mcp".into(),
        headers: mcp_headers(),
        body: Some(body),
    };
    match op {
        "use_plain" => get(format!("{table}/schema")),
        "use_budget" | "use_ceiling" => get(format!("{table}/rows?limit=1")),
        "use_service" => get("/hosts".into()),
        "use_multi" => Built {
            method: "POST".into(),
            path: "/copy".into(),
            headers: vec![],
            body: Some(copy.to_string().into_bytes()),
        },
        "read_actions" => get("/.well-known/procurauth/actions".into()),
        "list_options" => get("/.well-known/procurauth/resources?type=host".into()),
        "mcp_call_plain" => mcp(tools_call(
            "list_tables",
            json!({"host": "prod", "database": "test2"}),
            json!({}),
        )),
        "mcp_call_budget" => mcp(tools_call(
            "read_rows",
            {
                let mut a = orders.clone();
                a["limit"] = json!(1);
                a
            },
            json!({}),
        )),
        "mcp_call_input" => mcp(tools_call(
            "query_table",
            json!({"host": "prod", "database": "test2"}),
            json!({}),
        )),
        "mcp_call_multi" => mcp(tools_call("copy_table", copy, json!({}))),
        "mcp_call_approval" => mcp(approval_call(variant)),
        other => panic!("the profile has no operation {other}"),
    }
}

fn skipped(conditions: Option<&Value>) -> bool {
    let Some(list) = conditions.and_then(Value::as_array) else {
        return false;
    };
    list.iter().any(|c| match c.as_str().unwrap() {
        "no_answer_cache" | "no_budget_session" => true,
        "no_mcp_endpoint" => !cfg!(feature = "mcp"),
        "no_budget_action"
        | "no_ceiling_action"
        | "no_options_route"
        | "no_input_tool"
        | "no_approval_tool"
        | "no_multi_action"
        | "no_token_cache"
        | "single_key_set"
        | "no_approval_support" => false,
        other => panic!("unknown condition {other}"),
    })
}

// ---- The run -----------------------------------------------------------------------------------------------------------------------------------------------

struct Suite {
    service_addr: SocketAddr,
    pdp_addr: SocketAddr,
    keys: Keys,
    _service: reference_service::service::RunningService,
}

fn suite() -> Suite {
    let keys = Keys {
        ed: SigningKey::from_ed25519_seed(&[7; 32]),
        es: SigningKey::from_es256_scalar(&[9; 32]).unwrap(),
    };
    // The port of the test PDP is free now. Each case starts its own PDP on this port.
    let probe = TcpListener::bind("127.0.0.1:0").unwrap();
    let pdp_addr = probe.local_addr().unwrap();
    drop(probe);
    let mut set = keys.ed.public_jwks(Some(ED_KID));
    let es = keys.es.public_jwks(Some(ES_KID));
    set["keys"]
        .as_array_mut()
        .unwrap()
        .push(es["keys"][0].clone());
    let mut config = json!({
        "listen": "127.0.0.1:0", "issuer": "https://edge.example", "jwks": set,
        "pdp": {"url": format!("http://{pdp_addr}"), "credential_env": "CRED", "allow_insecure_pdp_link": true,
                "request_timeout_ms": 1000, "usage_wait_margin_ms": 500}
    });
    if cfg!(feature = "mcp") {
        config["mcp_path"] = json!("/mcp");
    }
    let env = |name: &str| (name == "CRED").then(|| "the-credential".to_owned());
    let file = |_: &Path| -> Result<String, String> { Err("no file".into()) };
    let loaded = load(
        &config.to_string(),
        &Sources {
            env: &env,
            file: &file,
        },
    )
    .unwrap();
    let app = build_app(
        loaded.settings.pep,
        loaded.settings.mcp_path,
        Box::new(std::io::sink()),
    )
    .unwrap();
    let service = reference_service::service::start(
        Arc::new(app),
        loaded.settings.listen,
        8,
        loaded.settings.limits,
    )
    .unwrap();
    Suite {
        service_addr: service.local_addr(),
        pdp_addr,
        keys,
        _service: service,
    }
}

fn check_step(
    case: &str,
    step: &Value,
    vars: &Vars,
    reply: &Reply,
    pdp: &ScriptedPdp,
) -> Vec<String> {
    let mut failures = Vec::new();
    let expect = subst(&step["expect"], vars, false);
    let mut fail = |what: &str| {
        failures.push(format!(
            "{case} ({}): {what}",
            step.get("name").and_then(Value::as_str).unwrap_or("")
        ))
    };
    if let Some(m) = expect.get("status")
        && !matches(m, Some(&json!(reply.status)))
    {
        fail(&format!("status {} does not match {m}", reply.status));
    }
    if let Some(headers) = expect.get("headers").and_then(Value::as_object) {
        for (name, m) in headers {
            let actual = reply.header(name).map(|v| json!(v));
            if !matches(m, actual.as_ref()) {
                fail(&format!("header {name} = {actual:?} does not match {m}"));
            }
        }
    }
    if let Some(m) = expect.get("body_text")
        && !matches(m, Some(&json!(reply.text())))
    {
        fail(&format!("body {:?} does not match {m}", reply.text()));
    }
    if let Some(pointers) = expect.get("json").and_then(Value::as_object) {
        let body: Option<Value> = serde_json::from_slice(&reply.body).ok();
        for (pointer, m) in pointers {
            let actual = body.as_ref().and_then(|b| b.pointer(pointer));
            if !matches(m, actual) {
                fail(&format!(
                    "json {pointer:?} = {actual:?} does not match {m}; body {}",
                    reply.text()
                ));
            }
        }
    }
    if let Some(kind) = expect.get("valid_as").and_then(Value::as_str) {
        let text = reply.text();
        let no_warning = kind.ends_with("_no_warning");
        let report = if kind.starts_with("action_document") {
            procurauth_core::action_document::analyze_str(&text).report
        } else {
            procurauth_core::options::analyze_str(&text).1
        };
        if report.has_errors() || (no_warning && !report.findings().is_empty()) {
            fail(&format!(
                "body is not a good {kind}: {:?}",
                report
                    .findings()
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            ));
        }
    }
    if let Some(list) = expect.get("pdp_questions").and_then(Value::as_array) {
        let questions = pdp.questions();
        for entry in list {
            let count = questions
                .iter()
                .filter(|q| {
                    entry["json"]
                        .as_object()
                        .unwrap()
                        .iter()
                        .all(|(p, m)| matches(m, q.body.pointer(p)))
                        && entry
                            .get("headers")
                            .and_then(Value::as_object)
                            .is_none_or(|hs| {
                                hs.iter().all(|(n, m)| {
                                    let actual = q
                                        .headers
                                        .iter()
                                        .find(|(h, _)| h.eq_ignore_ascii_case(n))
                                        .map(|(_, v)| json!(v));
                                    matches(m, actual.as_ref())
                                })
                            })
                })
                .count();
            let ok = match entry.get("count") {
                Some(m) => matches(m, Some(&json!(count))),
                None => count == 1,
            };
            if !ok {
                fail(&format!(
                    "{count} questions match {} (count {:?}); all questions: {}",
                    entry["json"],
                    entry.get("count"),
                    questions
                        .iter()
                        .map(|q| q.body.to_string())
                        .collect::<Vec<_>>()
                        .join(" | ")
                ));
            }
        }
    }
    if let Some(list) = expect.get("pdp_approvals").and_then(Value::as_array) {
        let requests = pdp.approvals();
        for entry in list {
            let count = requests
                .iter()
                .filter(|r| {
                    r.route == entry["route"].as_str().unwrap()
                        && entry
                            .get("json")
                            .and_then(Value::as_object)
                            .is_none_or(|j| j.iter().all(|(p, m)| matches(m, r.json.pointer(p))))
                        && entry
                            .get("query")
                            .and_then(Value::as_object)
                            .is_none_or(|q| {
                                q.iter().all(|(n, m)| {
                                    matches(m, r.query.get(n).map(|v| json!(v)).as_ref())
                                })
                            })
                })
                .count();
            let ok = match entry.get("count") {
                Some(m) => matches(m, Some(&json!(count))),
                None => count == 1,
            };
            if !ok {
                fail(&format!(
                    "{count} requests of the approval API match {entry}; all: {requests:?}"
                ));
            }
        }
    }
    if let Some(m) = expect.get("pdp_connections") {
        let n = pdp.connections.load(Ordering::SeqCst);
        if !matches(m, Some(&json!(n))) {
            fail(&format!("{n} connections do not match {m}"));
        }
    }
    failures
}

/// Run one case. It returns the failures, or `None` when the case is skipped.
fn run_case(suite: &Suite, case: &Value) -> Option<Vec<String>> {
    let id = case["id"].as_str().unwrap();
    if skipped(case.get("skip_if")) {
        return None;
    }
    let given = case.get("given").cloned().unwrap_or(json!({}));
    let steps = case["steps"].as_array().unwrap();
    // The variables: the operation of the step, or of the first step that has one.
    let mut default_vars: Vars = BTreeMap::new();
    for step in steps {
        if let Some(op) = step["request"].get("operation").and_then(Value::as_str) {
            for (k, v) in operation_vars(op) {
                default_vars.entry(k).or_insert(v);
            }
        }
    }
    for (k, v) in [
        ("service", json!(SERVICE)),
        ("mcp_path", json!("/mcp")),
        ("options_type", json!("host")),
        ("token_header", json!("X-Identity-Token")),
        ("approval_ref", json!("ref_conformance_0001")),
    ] {
        default_vars.insert(k.to_owned(), v);
    }
    let mut tokens = BTreeMap::new();
    if let Some(map) = given.get("tokens").and_then(Value::as_object) {
        for (name, spec) in map {
            let spec = subst(spec, &default_vars, false);
            let token = make_case_token(&suite.keys, &spec);
            default_vars.insert(format!("token_{name}"), json!(token));
            tokens.insert(name.clone(), token);
        }
    }
    let script: Vec<Value> = given
        .get("pdp_script")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .map(|r| subst(r, &default_vars, false))
                .collect()
        })
        .unwrap_or_default();
    let approval_script: Vec<Value> = given
        .get("approval_script")
        .and_then(Value::as_array)
        .map(|rules| {
            rules
                .iter()
                .map(|r| subst(r, &default_vars, false))
                .collect()
        })
        .unwrap_or_default();
    let pdp = ScriptedPdp::start(suite.pdp_addr, script, approval_script);
    let mut failures = Vec::new();
    for step in steps {
        if skipped(step.get("skip_if")) {
            continue;
        }
        pdp.clear_questions();
        let request = &step["request"];
        let mut vars = default_vars.clone();
        let built = if let Some(op) = request.get("operation").and_then(Value::as_str) {
            vars.extend(operation_vars(op));
            let mut built = build_operation(op, request.get("variant").and_then(Value::as_str));
            if let Some(extra) = request.get("headers").and_then(Value::as_object) {
                for (k, v) in extra {
                    built
                        .headers
                        .push((k.clone(), text_of(&subst(v, &vars, false))));
                }
            }
            built
        } else {
            let method = request["method"].as_str().unwrap().to_owned();
            let path = text_of(&subst(&request["path"], &vars, false));
            let mut headers = Vec::new();
            if let Some(map) = request.get("headers").and_then(Value::as_object) {
                for (k, v) in map {
                    headers.push((k.clone(), text_of(&subst(v, &vars, false))));
                }
            }
            let body = if let Some(b) = request.get("body") {
                Some(subst(b, &vars, false).to_string().into_bytes())
            } else {
                request
                    .get("body_text")
                    .map(|t| t.as_str().unwrap().as_bytes().to_vec())
            };
            Built {
                method,
                path,
                headers,
                body,
            }
        };
        let mut headers = built.headers.clone();
        if let Some(name) = request.get("token").and_then(Value::as_str) {
            headers.push(("X-Identity-Token".to_owned(), tokens[name].clone()));
        }
        let refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let reply = send(
            suite.service_addr,
            &built.method,
            &built.path,
            &refs,
            built.body.as_deref(),
        );
        // The questions can still be in flight when the reply is short: the PDP records them first.
        failures.extend(check_step(id, step, &vars, &reply, &pdp));
    }
    Some(failures)
}

fn cases() -> Vec<Value> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../conformance/cases/U");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    files
        .iter()
        .map(|p| serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap())
        .collect()
}

#[test]
fn the_reference_service_passes_the_cases_of_the_series_u() {
    let suite = suite();
    let mut failures = Vec::new();
    let mut skipped_ids = Vec::new();
    let mut ran = 0;
    for case in cases() {
        match run_case(&suite, &case) {
            None => skipped_ids.push(case["id"].as_str().unwrap().to_owned()),
            Some(f) => {
                ran += 1;
                failures.extend(f);
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} failures in {ran} cases (skipped: {skipped_ids:?})\n{}",
        failures.len(),
        failures.join("\n")
    );
    if cfg!(feature = "mcp") {
        // The case U95 needs a budget on the action `mcp.session`. The service lists none.
        // U30 and U100 to U110 are the cases of the approval profile: they run.
        assert_eq!(ran, 109, "the number of cases that ran");
        skipped_ids.sort();
        assert_eq!(skipped_ids, ["U95"]);
    }
}
