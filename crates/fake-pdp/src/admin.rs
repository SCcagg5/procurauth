//! The admin endpoints, under the prefix `/__fake/`.
//!
//! The server serves them only when the option `admin` is on. Without it,
//! each path below the prefix gets HTTP 404, as an unknown path does. They
//! share the listener of the PDP. They use the same credential as the PDP
//! endpoints, when the server has one.
//!
//! | Request | Effect |
//! | --- | --- |
//! | `GET /__fake/clock` | The time of the clock. |
//! | `POST /__fake/clock` | Body `{"advance": N}` or `{"set": T}`, in whole seconds. |
//! | `PUT /__fake/load` or `POST /__fake/load` | Body: a data file. Replace the directory, the counters, the failures and the credentials of the services. |
//! | `POST /__fake/reset` | Put the counters back to the first values of the data. |
//! | `GET /__fake/counters` | The counters of the current windows. |
//! | `GET /__fake/log` | The last questions, with the answers and the counters. |
//! | `DELETE /__fake/log` | Remove the entries of the log. |
//! | `GET /__fake/failures` | The failure rules, with the uses that each one has left. |
//! | `POST /__fake/failures` | Body `{"failures": [...]}`. It replaces all the rules. |

use std::sync::PoisonError;

use procurauth_core::directory::{Endpoint, analyze_value};
use procurauth_core::finding::{Finding, JsonPath, Report, Severity};
use procurauth_core::json::parse_slice;
use procurauth_core::read::{Obj, Unknown};
use serde_json::{Value, json};

use crate::faults::{Fault, FaultKind, read_faults};
use crate::http::{Request, Response};
use crate::log::counters_to_value;
use crate::pdp::Pdp;
use crate::server::digest_from_hex;
use crate::service::{Action, Shared};

fn findings_response(status: u16, findings: &[Finding]) -> Action {
    let list: Vec<Value> = findings
        .iter()
        .map(|f| json!({"path": f.path.as_str(), "rule": f.rule, "message": f.message}))
        .collect();
    Action::Respond(Response::json(
        status,
        &json!({"error": crate::http::reason(status), "findings": list}),
    ))
}

fn message_response(status: u16, message: &str) -> Action {
    Action::Respond(Response::json(status, &json!({"error": message})))
}

/// The name of an endpoint in the data format.
fn endpoint_name(endpoint: Endpoint) -> &'static str {
    match endpoint {
        Endpoint::Evaluation => "evaluation",
        Endpoint::Evaluations => "evaluations",
        Endpoint::Metadata => "metadata",
    }
}

fn fault_to_value(fault: &Fault, left: Option<u64>) -> Value {
    let mut when = serde_json::Map::new();
    if let Some(subject) = &fault.when.subject {
        when.insert("subject".into(), json!(subject));
    }
    if let Some(action) = &fault.when.action {
        when.insert("action".into(), json!(action));
    }
    if let Some(resource) = &fault.when.resource {
        when.insert("resource".into(), json!(resource.to_string()));
    }
    if let Some(usage) = fault.when.usage {
        when.insert("usage".into(), json!(usage));
    }
    if let Some(endpoint) = fault.when.endpoint {
        when.insert("endpoint".into(), json!(endpoint_name(endpoint)));
    }
    let mut out = serde_json::Map::new();
    out.insert("kind".into(), json!(fault.kind.name()));
    if let FaultKind::Delay(ms) = fault.kind {
        out.insert("delay_ms".into(), json!(ms));
    }
    out.insert("times".into(), json!(fault.times));
    out.insert("left".into(), json!(left));
    out.insert("when".into(), Value::Object(when));
    Value::Object(out)
}

/// A handler of one admin route.
type Handler = fn(&Shared, &Request) -> Action;

impl Shared {
    /// Handle a request below `/__fake/`.
    pub(crate) fn admin(&self, request: &Request) -> Action {
        if let Err(response) = self.authenticate(request) {
            return Action::Respond(response);
        }
        let (allowed, handler): (&[&str], Handler) = match request.path.as_str() {
            "/__fake/clock" => (&["GET", "POST"], Self::admin_clock),
            "/__fake/load" => (&["PUT", "POST"], Self::admin_load),
            "/__fake/reset" => (&["POST"], Self::admin_reset),
            "/__fake/counters" => (&["GET"], Self::admin_counters),
            "/__fake/log" => (&["GET", "DELETE"], Self::admin_log),
            "/__fake/failures" => (&["GET", "POST"], Self::admin_failures),
            _ => return Action::Respond(Response::error(404)),
        };
        if !allowed.contains(&request.method.as_str()) {
            return Action::Respond(Response::error(405).with_header("Allow", &allowed.join(", ")));
        }
        handler(self, request)
    }

    fn admin_clock(&self, request: &Request) -> Action {
        if request.method == "GET" {
            return Action::Respond(Response::json(200, &self.clock_value()));
        }
        let value = match parse_slice(&request.body) {
            Ok(value) => value,
            Err(error) => {
                return message_response(400, &format!("The body is not valid JSON: {error}."));
            }
        };
        let mut report = Report::new();
        let root = JsonPath::root();
        let (mut advance, mut set) = (None, None);
        if let Some(mut obj) = Obj::new(&value, &root, "admin", Unknown::Error, &mut report) {
            advance = obj.whole_opt("advance", &mut report);
            set = obj.whole_opt("set", &mut report);
            obj.finish(&mut report);
        }
        if !report.has_errors() && advance.is_some() == set.is_some() {
            report.error(
                &root,
                "admin",
                "one_member",
                "Expected exactly one member: `advance` or `set`.",
            );
        }
        if report.has_errors() {
            return findings_response(400, report.findings());
        }
        let result = match (advance, set) {
            (Some(seconds), _) => self.clock.advance(seconds).map(|_| ()),
            (_, Some(seconds)) => self.clock.set(seconds),
            _ => Ok(()),
        };
        match result {
            Ok(()) => Action::Respond(Response::json(200, &self.clock_value())),
            Err(error) => message_response(400, &error.to_string()),
        }
    }

    fn clock_value(&self) -> Value {
        json!({
            "now": self.clock.now_seconds(),
            "now_millis": self.clock.now_millis(),
            "fixed": self.clock.is_fixed(),
        })
    }

    /// Replace the data. The body is a data file. A member of `metadata` that differs
    /// from the values of the start is an error: the listener keeps the values that it started with.
    fn admin_load(&self, request: &Request) -> Action {
        let value = match parse_slice(&request.body) {
            Ok(value) => value,
            Err(error) => {
                return message_response(400, &format!("The body is not valid JSON: {error}."));
            }
        };
        let (directory, report) = analyze_value(&value);
        let Some(directory) = directory else {
            return findings_response(400, report.findings());
        };
        let s = &self.settings;
        let meta = &directory.metadata;
        let differs = |new: Option<u64>, old: u64| new.is_some_and(|n| n != old);
        if differs(meta.usage_max_seconds, s.usage_max_seconds)
            || differs(meta.idle_max_seconds, s.idle_max_seconds)
            || differs(meta.evaluations_max_bytes, s.evaluations_max_bytes)
            || differs(meta.evaluations_max_items, s.evaluations_max_items)
        {
            return message_response(
                400,
                "The member `metadata` differs from the values that the server started with. Restart the server to change them.",
            );
        }
        if let Some(now) = directory.clock_now
            && let Err(error) = self.clock.set(now)
        {
            return message_response(400, &error.to_string());
        }
        let services = directory
            .services
            .iter()
            .filter_map(|svc| {
                svc.credential_sha256
                    .as_deref()
                    .and_then(digest_from_hex)
                    .map(|digest| (svc.id.clone(), digest))
            })
            .collect();
        let faults: Vec<Fault> = directory.failures.iter().map(Fault::from_core).collect();
        let (services_count, subjects_count) = (directory.services.len(), directory.subjects.len());
        let now = self.now_seconds();
        {
            let mut state = self.state();
            state.pdp = Pdp::new(directory, now);
            state.faults.replace(faults);
        }
        self.auth
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .services = services;
        Action::Respond(Response::json(
            200,
            &json!({"loaded": true, "services": services_count, "subjects": subjects_count}),
        ))
    }

    fn admin_reset(&self, request: &Request) -> Action {
        if !request.body.is_empty() {
            match parse_slice(&request.body) {
                Ok(Value::Object(map)) if map.is_empty() => {}
                _ => {
                    return message_response(
                        400,
                        "The body must be empty, or an empty JSON object.",
                    );
                }
            }
        }
        let now = self.now_seconds();
        self.state().pdp.reset_counters(now);
        Action::Respond(Response::json(200, &json!({"reset": true, "now": now})))
    }

    fn admin_counters(&self, _request: &Request) -> Action {
        let now = self.now_seconds();
        let counters = self.state().pdp.counter_view(now);
        Action::Respond(Response::json(
            200,
            &json!({"now": now, "counters": counters_to_value(&counters)}),
        ))
    }

    fn admin_log(&self, request: &Request) -> Action {
        let mut state = self.state();
        if request.method == "DELETE" {
            let count = state.entries.entries().len();
            state.entries.clear();
            return Action::Respond(Response::json(200, &json!({"cleared": count})));
        }
        let entries: Vec<Value> = state
            .entries
            .entries()
            .iter()
            .map(|e| e.to_value())
            .collect();
        Action::Respond(Response::json(200, &json!({"entries": entries})))
    }

    fn admin_failures(&self, request: &Request) -> Action {
        if request.method == "GET" {
            let state = self.state();
            let list: Vec<Value> = state
                .faults
                .rules()
                .map(|(fault, left)| fault_to_value(fault, left))
                .collect();
            return Action::Respond(Response::json(200, &json!({"failures": list})));
        }
        let value = match parse_slice(&request.body) {
            Ok(value) => value,
            Err(error) => {
                return message_response(400, &format!("The body is not valid JSON: {error}."));
            }
        };
        match read_faults(&value) {
            Ok(faults) => {
                let count = faults.len();
                self.state().faults.replace(faults);
                Action::Respond(Response::json(200, &json!({"failures": count})))
            }
            Err(findings) => {
                let errors: Vec<Finding> = findings
                    .into_iter()
                    .filter(|f| f.severity == Severity::Error)
                    .collect();
                findings_response(400, &errors)
            }
        }
    }
}
