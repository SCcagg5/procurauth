//! The routes of the server: the PDP endpoints, the metadata and the shared state.
//!
//! One `Shared` value holds the state of the PDP. All the worker threads
//! use it. A lock makes each decision and its count one atomic step (6.5, 6.8).
//! The admin routes are in the module `admin`.

use std::io::Write;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread;
use std::time::{Duration, Instant};

use procurauth_core::authzen::{
    Decision, EvaluationRequest, EvaluationsRequest, Reason, RequestContext, check_usage_placement,
    evaluations_answer_to_value,
};
use procurauth_core::directory::Endpoint;
use procurauth_core::finding::{Finding, JsonPath, Severity};
use procurauth_core::json::parse_slice;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::clock::Clock;
use crate::config::{ADMIN_PREFIX, EVALUATION_PATH, EVALUATIONS_PATH, METADATA_PATH, Settings};
use crate::counters::CounterView;
use crate::faults::{Facts, FaultKind, FaultSet};
use crate::http::{Request, Response, echo_request_id, valid_request_id};
use crate::log::{EntryLog, LogEntry};
use crate::pdp::{Caller, Pdp};

/// What a worker does after it handled a request.
pub(crate) enum Action {
    /// Write this response.
    Respond(Response),
    /// Close the connection with no bytes.
    Close,
    /// Keep the connection open and never answer.
    Hold,
}

/// The state that the lock protects.
pub(crate) struct State {
    pub pdp: Pdp,
    pub faults: FaultSet,
    pub entries: EntryLog,
    pub seq: u64,
    pub out: Option<Box<dyn Write + Send>>,
}

impl State {
    /// Number the entry, write its text and keep it.
    fn record(&mut self, mut entry: LogEntry) {
        self.seq += 1;
        entry.seq = self.seq;
        if let Some(out) = &mut self.out {
            let _ = out.write_all(entry.to_text().as_bytes());
            let _ = out.flush();
        }
        self.entries.push(entry);
    }
}

/// The credentials of the PEPs, as SHA-256 digests (12).
pub(crate) struct Auth {
    pub global: Option<[u8; 32]>,
    pub services: Vec<(String, [u8; 32])>,
}

impl Auth {
    fn required(&self) -> bool {
        self.global.is_some() || !self.services.is_empty()
    }

    /// Find who owns a bearer value. Each comparison takes the same time.
    fn identify(&self, token: &str) -> Option<Caller> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found = None;
        if let Some(global) = &self.global
            && same(global, &digest)
        {
            found = Some(Caller::Any);
        }
        for (id, expected) in &self.services {
            if same(expected, &digest) && found.is_none() {
                found = Some(Caller::Service(id.clone()));
            }
        }
        found
    }
}

fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0_u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// The state that all the threads share.
pub(crate) struct Shared {
    pub state: Mutex<State>,
    pub diagnostics: Mutex<Option<Box<dyn Write + Send>>>,
    pub clock: Clock,
    pub settings: Settings,
    pub auth: Mutex<Auth>,
    pub stop: Arc<AtomicBool>,
    pub addr: SocketAddr,
}

/// One question, ready to decide.
struct Item {
    request: EvaluationRequest,
    /// `None` when the item has a bad member of this protocol: the answer is `invalid_request` (11.1).
    context: Option<RequestContext>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Semantic {
    ExecuteAll,
    DenyOnFirstDeny,
    PermitOnFirstPermit,
}

struct Prepared {
    items: Vec<Item>,
    /// True when the answer has the form of one Access Evaluation answer.
    single: bool,
    semantic: Semantic,
}

fn finding(path: JsonPath, rule: &'static str, code: &'static str, message: String) -> Finding {
    Finding {
        severity: Severity::Error,
        path,
        rule,
        code,
        message,
    }
}

impl Shared {
    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(crate) fn now_seconds(&self) -> u64 {
        self.clock.now_seconds()
    }

    /// Write a line to the diagnostics, when the server has a sink for them.
    pub(crate) fn diagnostic(&self, line: &str) {
        let mut guard = self
            .diagnostics
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(out) = guard.as_mut() {
            let _ = writeln!(out, "{line}");
            let _ = out.flush();
        }
    }

    /// Note a request that the transport layer refused.
    pub(crate) fn note_transport_reject(&self, status: u16) {
        self.diagnostic(&format!("rejected {status}"));
    }

    /// Wait, and stop early when the server stops.
    pub(crate) fn pause(&self, millis: u64) {
        let end = Instant::now() + Duration::from_millis(millis);
        while !self.stop.load(Ordering::SeqCst) {
            let now = Instant::now();
            if now >= end {
                return;
            }
            thread::sleep((end - now).min(Duration::from_millis(20)));
        }
    }

    /// Handle one request.
    pub(crate) fn handle(&self, request: &Request) -> Action {
        let id = request.header("x-request-id").and_then(valid_request_id);
        match self.route(request, id.as_deref()) {
            Action::Respond(response) => Action::Respond(echo_request_id(response, id.as_deref())),
            other => other,
        }
    }

    fn route(&self, request: &Request, id: Option<&str>) -> Action {
        let path = request.path.as_str();
        if path.starts_with(ADMIN_PREFIX) && self.settings.admin {
            return self.admin(request);
        }
        let allowed = match path {
            METADATA_PATH => "GET",
            EVALUATION_PATH | EVALUATIONS_PATH => "POST",
            _ => return Action::Respond(Response::error(404)),
        };
        if request.method != allowed {
            return Action::Respond(Response::error(405).with_header("Allow", allowed));
        }
        match path {
            METADATA_PATH => self.metadata(request),
            EVALUATION_PATH => self.question(request, Endpoint::Evaluation, id),
            _ => self.question(request, Endpoint::Evaluations, id),
        }
    }

    /// Check the credential of the caller (12). The metadata needs none.
    pub(crate) fn authenticate(&self, request: &Request) -> Result<Caller, Response> {
        let auth = self.auth.lock().unwrap_or_else(PoisonError::into_inner);
        if !auth.required() {
            return Ok(Caller::Any);
        }
        let token = request.header("authorization").and_then(|value| {
            let (scheme, token) = value.split_once(' ')?;
            let token = token.trim_matches(' ');
            (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token)
        });
        match token.and_then(|t| auth.identify(t)) {
            Some(caller) => Ok(caller),
            None => {
                self.diagnostic(&format!("rejected 401 {} {}", request.method, request.path));
                Err(Response::error(401).with_header("WWW-Authenticate", "Bearer"))
            }
        }
    }

    fn reject(&self, request: &Request, status: u16, findings: &[Finding]) -> Action {
        let mut line = format!("rejected {status} {} {}", request.method, request.path);
        for finding in findings {
            line.push_str(&format!(
                "  {} rule {} {}",
                finding.path, finding.rule, finding.code
            ));
        }
        self.diagnostic(&line);
        Action::Respond(Response::error(status))
    }

    fn base_url(&self, request: &Request) -> String {
        let host = request
            .header("host")
            .filter(|h| {
                !h.is_empty()
                    && h.len() <= 255
                    && h.bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"._-:[]".contains(&b))
            })
            .map_or_else(|| self.addr.to_string(), str::to_owned);
        format!("http://{host}")
    }

    fn metadata(&self, request: &Request) -> Action {
        let fault = self
            .state()
            .faults
            .take(&[Facts::for_endpoint(Endpoint::Metadata)]);
        match fault {
            Some(FaultKind::Error503) => return Action::Respond(Response::error(503)),
            Some(FaultKind::Delay(ms)) => self.pause(ms),
            Some(FaultKind::NoAnswer) => return Action::Hold,
            Some(FaultKind::Close) => return Action::Close,
            Some(FaultKind::InvalidJson) => return Action::Respond(invalid_json_response()),
            Some(FaultKind::NoUnits) | None => {}
        }
        let base = self.base_url(request);
        let s = &self.settings;
        Action::Respond(Response::json(
            200,
            &json!({
                "policy_decision_point": base,
                "access_evaluation_endpoint": format!("{base}{EVALUATION_PATH}"),
                "access_evaluations_endpoint": format!("{base}{EVALUATIONS_PATH}"),
                "procurauth_usage_max_seconds": s.usage_max_seconds,
                "procurauth_idle_max_seconds": s.idle_max_seconds,
                "procurauth_evaluations_max_bytes": s.evaluations_max_bytes,
                "procurauth_evaluations_max_items": s.evaluations_max_items,
            }),
        ))
    }

    fn prepare(&self, value: &Value, endpoint: Endpoint) -> Result<Prepared, Vec<Finding>> {
        if endpoint == Endpoint::Evaluation {
            let request = EvaluationRequest::from_value(value)?;
            return single(request);
        }
        let findings = check_usage_placement(value);
        if !findings.is_empty() {
            return Err(findings);
        }
        let mut parsed = EvaluationsRequest::from_value(value)?;
        if !parsed.has_items {
            let request = parsed.items.remove(0);
            return single(request);
        }
        if parsed.items.len() as u64 > self.settings.evaluations_max_items {
            return Err(vec![finding(
                JsonPath::root().key("evaluations"),
                "10.7a",
                "too_many_items",
                format!(
                    "Member `evaluations`: expected {} items at most, found {}.",
                    self.settings.evaluations_max_items,
                    parsed.items.len()
                ),
            )]);
        }
        let semantic = match parsed
            .options
            .as_ref()
            .and_then(|o| o.get("evaluations_semantic"))
        {
            None => Semantic::ExecuteAll,
            Some(Value::String(s)) if s == "execute_all" => Semantic::ExecuteAll,
            Some(Value::String(s)) if s == "deny_on_first_deny" => Semantic::DenyOnFirstDeny,
            Some(Value::String(s)) if s == "permit_on_first_permit" => {
                Semantic::PermitOnFirstPermit
            }
            Some(other) => {
                return Err(vec![finding(
                    JsonPath::root().key("options").key("evaluations_semantic"),
                    "authzen",
                    "bad_semantic",
                    format!(
                        "Member `evaluations_semantic`: expected `execute_all`, `deny_on_first_deny` or `permit_on_first_permit`, found {other}."
                    ),
                )]);
            }
        };
        let items = parsed
            .items
            .into_iter()
            .map(|request| {
                // An item with a bad member of this protocol gets `invalid_request` (11.1).
                let context = if request.resource.ancestors().is_ok() {
                    request.request_context().ok()
                } else {
                    None
                };
                Item { request, context }
            })
            .collect();
        Ok(Prepared {
            items,
            single: false,
            semantic,
        })
    }

    fn question(&self, request: &Request, endpoint: Endpoint, id: Option<&str>) -> Action {
        let caller = match self.authenticate(request) {
            Ok(caller) => caller,
            Err(response) => return Action::Respond(response),
        };
        let json_type = request.header("content-type").is_some_and(|value| {
            value
                .split(';')
                .next()
                .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
        });
        if !json_type {
            return self.reject(request, 415, &[]);
        }
        let value = match parse_slice(&request.body) {
            Ok(value) => value,
            Err(error) => {
                let findings = [finding(
                    error.path.clone(),
                    "authzen",
                    "bad_json",
                    String::new(),
                )];
                return self.reject(request, 400, &findings);
            }
        };
        let prepared = match self.prepare(&value, endpoint) {
            Ok(prepared) => prepared,
            Err(findings) => return self.reject(request, 400, &findings),
        };
        let endpoint_name = match endpoint {
            Endpoint::Evaluation => "evaluation",
            _ => "evaluations",
        };
        let facts: Vec<Facts> = prepared
            .items
            .iter()
            .map(|item| facts_of(endpoint, &item.request))
            .collect();

        // A failure of the test, chosen before the decision.
        let fault = self.state().faults.take(&facts);
        let mut note: Option<String> = None;
        let mut after: Option<FaultKind> = None;
        match fault {
            Some(FaultKind::Error503) => {
                let now = self.now_seconds();
                let mut state = self.state();
                for item in &prepared.items {
                    let entry = entry_of(
                        item,
                        endpoint_name,
                        id,
                        None,
                        Some("error_503".to_owned()),
                        Vec::new(),
                        now,
                    );
                    state.record(entry);
                }
                return Action::Respond(Response::error(503));
            }
            Some(FaultKind::Delay(ms)) => {
                note = Some(format!("delay {ms}"));
                self.pause(ms);
            }
            Some(kind) => {
                note = Some(kind.name().to_owned());
                after = Some(kind);
            }
            None => {}
        }

        // The decisions, with the counting, in one atomic step for all the items.
        let now_millis = self.clock.now_millis();
        let mut answers: Vec<Decision> = Vec::new();
        {
            let mut state = self.state();
            for item in &prepared.items {
                let (decision, counters) = match &item.context {
                    None => (Decision::deny(Some(Reason::InvalidRequest)), Vec::new()),
                    Some(context) => {
                        let outcome = state
                            .pdp
                            .decide(&caller, &item.request, context, now_millis);
                        (outcome.decision, outcome.counters)
                    }
                };
                let entry = entry_of(
                    item,
                    endpoint_name,
                    id,
                    Some(&decision),
                    note.clone(),
                    counters,
                    now_millis / 1000,
                );
                state.record(entry);
                let stop_here = match prepared.semantic {
                    Semantic::ExecuteAll => false,
                    Semantic::DenyOnFirstDeny => !decision.decision,
                    Semantic::PermitOnFirstPermit => decision.decision,
                };
                answers.push(decision);
                if stop_here {
                    break;
                }
            }
        }

        let mut body = if prepared.single {
            answers[0].to_value()
        } else {
            evaluations_answer_to_value(&answers)
        };
        match after {
            Some(FaultKind::NoAnswer) => Action::Hold,
            Some(FaultKind::Close) => Action::Close,
            Some(FaultKind::InvalidJson) => Action::Respond(invalid_json_response()),
            Some(FaultKind::NoUnits) => {
                remove_units(&mut body);
                Action::Respond(Response::json(200, &body))
            }
            _ => Action::Respond(Response::json(200, &body)),
        }
    }

    /// The counters of the current windows.
    pub(crate) fn counter_view(&self) -> Vec<CounterView> {
        let now = self.now_seconds();
        self.state().pdp.counter_view(now)
    }
}

/// The body of the failure `invalid_json`: it is not valid JSON.
fn invalid_json_response() -> Response {
    Response::raw_json(200, b"{\"decision\": tr".to_vec())
}

/// Remove `context.usage` from each `true` answer, for the failure `no_units` (6.12).
fn remove_units(body: &mut Value) {
    fn strip(answer: &mut Value) {
        if answer["decision"] != Value::Bool(true) {
            return;
        }
        if let Some(context) = answer.get_mut("context").and_then(Value::as_object_mut) {
            context.remove("usage");
            if context.is_empty()
                && let Some(map) = answer.as_object_mut()
            {
                map.remove("context");
            }
        }
    }
    if let Some(items) = body.get_mut("evaluations").and_then(Value::as_array_mut) {
        items.iter_mut().for_each(strip);
    } else {
        strip(body);
    }
}

/// Check one evaluation as a single question: a bad member of this protocol gives HTTP 400 (11.1).
fn single(request: EvaluationRequest) -> Result<Prepared, Vec<Finding>> {
    let context = request.request_context()?;
    if let Err(error) = request.resource.ancestors() {
        return Err(vec![finding(
            JsonPath::root()
                .key("resource")
                .key("properties")
                .key("ancestors"),
            "4.1",
            "bad_chain",
            format!("The chain is not valid: {error}."),
        )]);
    }
    Ok(Prepared {
        items: vec![Item {
            request,
            context: Some(context),
        }],
        single: true,
        semantic: Semantic::ExecuteAll,
    })
}

fn facts_of(endpoint: Endpoint, request: &EvaluationRequest) -> Facts {
    Facts {
        endpoint,
        subject: Some(request.subject.id.clone()),
        action: Some(request.action.name.clone()),
        resource: request.resource.node_path().ok(),
        usage: request
            .context
            .as_ref()
            .is_some_and(|c| c.contains_key("usage")),
    }
}

fn entry_of(
    item: &Item,
    endpoint: &'static str,
    request_id: Option<&str>,
    decision: Option<&Decision>,
    fault: Option<String>,
    counters: Vec<CounterView>,
    time: u64,
) -> LogEntry {
    let request = &item.request;
    let resource = request.resource.node_path().map_or_else(
        |_| format!("{}:{}", request.resource.resource_type, request.resource.id),
        |path| path.to_string(),
    );
    LogEntry {
        seq: 0,
        endpoint,
        request_id: request_id.map(str::to_owned),
        subject: request.subject.id.clone(),
        action: request.action.name.clone(),
        resource,
        usage: request
            .context
            .as_ref()
            .is_some_and(|c| c.contains_key("usage")),
        answer: decision.map(Decision::to_value),
        fault,
        counters,
        time,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(text: &str) -> [u8; 32] {
        Sha256::digest(text.as_bytes()).into()
    }

    #[test]
    fn p_12_the_credential_finds_its_owner() {
        let auth = Auth {
            global: Some(digest("global")),
            services: vec![
                ("one".to_owned(), digest("t1")),
                ("two".to_owned(), digest("t2")),
            ],
        };
        assert!(auth.required());
        assert_eq!(auth.identify("global"), Some(Caller::Any));
        assert_eq!(auth.identify("t1"), Some(Caller::Service("one".to_owned())));
        assert_eq!(auth.identify("t2"), Some(Caller::Service("two".to_owned())));
        assert_eq!(auth.identify("t3"), None);
        assert_eq!(auth.identify(""), None);
        let open = Auth {
            global: None,
            services: Vec::new(),
        };
        assert!(!open.required());
    }

    #[test]
    fn p_6_12_the_failure_no_units_removes_the_units_of_a_true_answer_only() {
        let mut one = json!({"decision": true, "context": {"limits": {"max_rows": 1}, "usage": {"units": 1}}});
        remove_units(&mut one);
        assert_eq!(
            one,
            json!({"decision": true, "context": {"limits": {"max_rows": 1}}})
        );
        let mut bare = json!({"decision": true, "context": {"usage": {"units": 0}}});
        remove_units(&mut bare);
        assert_eq!(bare, json!({"decision": true}));
        let mut denied =
            json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 3}});
        let before = denied.clone();
        remove_units(&mut denied);
        assert_eq!(denied, before);
        let mut list = json!({"evaluations": [
            {"decision": true, "context": {"usage": {"units": 1}}}, {"decision": false}]});
        remove_units(&mut list);
        assert_eq!(
            list,
            json!({"evaluations": [{"decision": true}, {"decision": false}]})
        );
    }

    #[test]
    fn the_invalid_json_body_is_not_json() {
        assert!(serde_json::from_slice::<Value>(&invalid_json_response().body).is_err());
    }
}
