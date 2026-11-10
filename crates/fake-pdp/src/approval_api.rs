//! The narrow approval API for a PEP (protocol 17.4).
//!
//! | Request | Effect |
//! | --- | --- |
//! | `POST /approval/v1/requests` | Submit a request. HTTP 201, or HTTP 200 for a request that still waits. |
//! | `GET /approval/v1/requests/{id}?subject=&wait=&renew=` | Read the verdict. |
//! | `POST /approval/v1/requests/{id}/keepalive` | Renew the lease and read the verdict. |
//!
//! The routes share the listener and the credential of the PDP endpoints. A credential that
//! belongs to a service that has no action in its document gets HTTP 403.
//! No answer has more than the verdict (17.12).

use std::time::{Duration, Instant};

use procurauth_core::effect::is_effect;
use procurauth_core::json::{JsonErrorKind, parse_slice};
use serde_json::{Map, Value, json};

use crate::approvals::{
    ApiError, LeaseGiven, Submission, Verdict, WAIT_MAX_SECONDS, parse_rfc3339,
};
use crate::http::{Request, Response};
use crate::pdp::Caller;
use crate::service::{Action, Shared};

/// The start of the paths of the API.
pub(crate) const APPROVAL_PREFIX: &str = "/approval/v1/requests";

fn error_response(error: &ApiError) -> Action {
    Action::Respond(Response::json(error.status, &error.to_value()))
}

fn bad(code: &'static str) -> Action {
    Action::Respond(Response::json(422, &json!({ "error": code })))
}

fn verdict_response(verdict: Verdict) -> Action {
    Action::Respond(Response::json(200, &json!({"verdict": verdict.as_str()})))
}

/// Decode `%XX` in a query value or a path segment. `None` for a bad escape or bytes that are not UTF-8.
fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let pair = text.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(pair, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// The parameters of a query, decoded. The first value of a name counts.
fn query_params(query: &str) -> Option<Vec<(String, String)>> {
    let mut out: Vec<(String, String)> = Vec::new();
    for pair in query.split('&').filter(|p| !p.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let (name, value) = (percent_decode(name)?, percent_decode(value)?);
        if !out.iter().any(|(n, _)| *n == name) {
            out.push((name, value));
        }
    }
    Some(out)
}

fn is_json_content(request: &Request) -> bool {
    request.header("content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|t| t.trim().eq_ignore_ascii_case("application/json"))
    })
}

/// Read the body of a submission into a [`Submission`]. The error is the code of 17.4.
fn read_submission(body: &[u8]) -> Result<Submission, &'static str> {
    let value = match parse_slice(body) {
        Ok(value) => value,
        // A duplicate member name and a lone surrogate in `op` make `op` invalid (17.3).
        Err(error)
            if error.path.as_str().starts_with("$.op")
                && matches!(
                    error.kind,
                    JsonErrorKind::DuplicateMember(_) | JsonErrorKind::BadString(_)
                ) =>
        {
            return Err("invalid_op");
        }
        Err(_) => return Err("invalid_argument"),
    };
    let Some(map) = value.as_object() else {
        return Err("invalid_argument");
    };
    const KNOWN: [&str; 8] = [
        "evaluation_id",
        "effect",
        "op",
        "view",
        "approval_ref",
        "lease_s",
        "until",
        "supersedes",
    ];
    if map.keys().any(|k| !KNOWN.contains(&k.as_str())) {
        return Err("invalid_argument");
    }
    let text = |name: &str, max: usize| -> Result<Option<String>, &'static str> {
        match map.get(name) {
            None => Ok(None),
            Some(Value::String(s)) if !s.is_empty() && s.len() <= max => Ok(Some(s.clone())),
            Some(_) => Err("invalid_argument"),
        }
    };
    let evaluation_id = text("evaluation_id", 1024)?.ok_or("invalid_argument")?;
    let effect = match map.get("effect") {
        Some(Value::String(s)) if is_effect(s) => s.clone(),
        _ => return Err("invalid_argument"),
    };
    let op = map.get("op").ok_or("invalid_argument")?.clone();
    if !op.is_object() {
        return Err("invalid_op");
    }
    let view = map.get("view").ok_or("invalid_argument")?.clone();
    if !view.is_object() {
        return Err("invalid_view");
    }
    let mut lease = LeaseGiven {
        approval_ref: text("approval_ref", 1024)?,
        ..LeaseGiven::default()
    };
    match map.get("lease_s") {
        None => {}
        Some(v) => match v.as_u64() {
            Some(seconds) => lease.lease_s = Some(seconds),
            None => lease.malformed = true,
        },
    }
    match map.get("until") {
        None => {}
        Some(Value::String(s)) => match parse_rfc3339(s) {
            Some(t) => lease.until = Some(t),
            None => lease.malformed = true,
        },
        Some(_) => lease.malformed = true,
    }
    Ok(Submission {
        evaluation_id,
        effect,
        op,
        view,
        lease,
        supersedes: text("supersedes", 1024)?,
    })
}

impl Shared {
    /// Handle a request below `/approval/v1/requests`.
    pub(crate) fn approval_route(&self, request: &Request) -> Action {
        let caller = match self.authenticate(request) {
            Ok(caller) => caller,
            Err(response) => return Action::Respond(response),
        };
        let own_service = match &caller {
            Caller::Any => None,
            Caller::Service(id) => Some(id.as_str()),
        };
        if let Some(service) = own_service
            && !self.state().pdp.serves_approvals(service)
        {
            return Action::Respond(Response::error(403));
        }
        let Some(rest) = request.path.strip_prefix(APPROVAL_PREFIX) else {
            return Action::Respond(Response::error(404));
        };
        let segments: Vec<&str> = match rest {
            "" => Vec::new(),
            _ => match rest.strip_prefix('/') {
                Some(tail) => tail.split('/').collect(),
                None => return Action::Respond(Response::error(404)),
            },
        };
        let allowed = match segments.as_slice() {
            [] => "POST",
            [id] if !id.is_empty() => "GET",
            [id, "keepalive"] if !id.is_empty() => "POST",
            _ => return Action::Respond(Response::error(404)),
        };
        if request.method != allowed {
            return Action::Respond(Response::error(405).with_header("Allow", allowed));
        }
        match segments.as_slice() {
            [] => self.approval_submit(request, own_service),
            [id] => self.approval_read(request, own_service, id),
            [id, _] => self.approval_keepalive(request, own_service, id),
            _ => Action::Respond(Response::error(404)),
        }
    }

    fn approval_submit(&self, request: &Request, service: Option<&str>) -> Action {
        if !is_json_content(request) {
            return Action::Respond(Response::error(415));
        }
        let submission = match read_submission(&request.body) {
            Ok(submission) => submission,
            Err(code) => return bad(code),
        };
        let now = self.now_seconds();
        let result = self
            .state()
            .pdp
            .approvals_mut()
            .submit(now, service, &submission);
        match result {
            Ok(done) => Action::Respond(Response::json(
                if done.created { 201 } else { 200 },
                &json!({"request_id": done.request_id, "code": done.code, "verdict": "pending"}),
            )),
            Err(error) => error_response(&error),
        }
    }

    fn approval_read(&self, request: &Request, service: Option<&str>, id: &str) -> Action {
        let Some(id) = percent_decode(id) else {
            return Action::Respond(Response::error(404));
        };
        let Some(params) = query_params(&request.query) else {
            return bad("invalid_argument");
        };
        let param = |name: &str| {
            params
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.as_str())
        };
        let Some(subject) = param("subject").filter(|s| !s.is_empty()) else {
            return bad("invalid_argument");
        };
        let renew = match param("renew") {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return bad("invalid_argument"),
        };
        let wait = match param("wait") {
            None => 0,
            Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => text
                .parse::<u64>()
                .map_or(WAIT_MAX_SECONDS, |w| w.min(WAIT_MAX_SECONDS)),
            Some(_) => return bad("invalid_argument"),
        };
        let first = self.state().pdp.approvals_mut().verdict(
            self.now_seconds(),
            service,
            subject,
            &id,
            renew,
        );
        let mut verdict = match first {
            Ok(verdict) => verdict,
            Err(error) => return error_response(&error),
        };
        // A long poll. The lock is free between two looks, so other requests go on.
        let end = Instant::now() + Duration::from_secs(wait);
        while verdict == Verdict::Pending && !self.stopping() {
            let left = end.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            self.pause(u64::try_from(left.as_millis().min(50)).unwrap_or(50));
            let next = self.state().pdp.approvals_mut().verdict(
                self.now_seconds(),
                service,
                subject,
                &id,
                false,
            );
            match next {
                Ok(next) => verdict = next,
                Err(error) => return error_response(&error),
            }
        }
        verdict_response(verdict)
    }

    fn approval_keepalive(&self, request: &Request, service: Option<&str>, id: &str) -> Action {
        if !is_json_content(request) {
            return Action::Respond(Response::error(415));
        }
        let Some(id) = percent_decode(id) else {
            return Action::Respond(Response::error(404));
        };
        let subject = match parse_slice(&request.body) {
            Ok(Value::Object(map)) => subject_of(&map),
            _ => None,
        };
        let Some(subject) = subject else {
            return bad("invalid_argument");
        };
        let result = self.state().pdp.approvals_mut().verdict(
            self.now_seconds(),
            service,
            &subject,
            &id,
            true,
        );
        match result {
            Ok(verdict) => verdict_response(verdict),
            Err(error) => error_response(&error),
        }
    }
}

/// The member `subject` of a keepalive body. The body has this member only.
fn subject_of(map: &Map<String, Value>) -> Option<String> {
    if map.len() != 1 {
        return None;
    }
    match map.get("subject") {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_is_decoded_and_the_first_value_of_a_name_counts() {
        let params = query_params("subject=key%3Aabc&wait=5&subject=other&renew=true").unwrap();
        assert_eq!(
            params,
            vec![
                ("subject".to_owned(), "key:abc".to_owned()),
                ("wait".to_owned(), "5".to_owned()),
                ("renew".to_owned(), "true".to_owned()),
            ]
        );
        assert!(query_params("subject=%zz").is_none());
        assert!(query_params("subject=%ff").is_none());
        assert_eq!(query_params("").unwrap(), Vec::new());
    }

    #[test]
    fn the_body_of_a_submission_is_read_with_the_codes_of_17_4() {
        let effect = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        let body = |extra: &str| {
            format!(
                r#"{{"evaluation_id":"ev_1","effect":"{effect}","op":{{"a":1}},"view":{{}}{extra}}}"#
            )
        };
        let ok = read_submission(body(r#","lease_s":60"#).as_bytes()).unwrap();
        assert_eq!(ok.lease.lease_s, Some(60));
        let ok = read_submission(body(r#","until":"2030-01-01T00:00:00Z""#).as_bytes()).unwrap();
        assert_eq!(ok.lease.until, Some(1_893_456_000));
        let none = read_submission(body("").as_bytes()).unwrap();
        assert_eq!(none.lease, LeaseGiven::default());
        let odd = read_submission(body(r#","lease_s":1.5"#).as_bytes()).unwrap();
        assert!(odd.lease.malformed);
        let odd = read_submission(body(r#","until":"tomorrow""#).as_bytes()).unwrap();
        assert!(odd.lease.malformed);
        assert_eq!(
            read_submission(body(r#","extra":1"#).as_bytes()).unwrap_err(),
            "invalid_argument"
        );
        assert_eq!(
            read_submission(body(r#","approval_ref":5"#).as_bytes()).unwrap_err(),
            "invalid_argument"
        );
        let dup = format!(
            r#"{{"evaluation_id":"e","effect":"{effect}","op":{{"a":1,"a":2}},"view":{{}},"lease_s":60}}"#
        );
        assert_eq!(read_submission(dup.as_bytes()).unwrap_err(), "invalid_op");
        let lone = format!(
            r#"{{"evaluation_id":"e","effect":"{effect}","op":{{"a":"\ud800"}},"view":{{}},"lease_s":60}}"#
        );
        assert_eq!(read_submission(lone.as_bytes()).unwrap_err(), "invalid_op");
        let list = format!(
            r#"{{"evaluation_id":"e","effect":"{effect}","op":[1],"view":{{}},"lease_s":60}}"#
        );
        assert_eq!(read_submission(list.as_bytes()).unwrap_err(), "invalid_op");
        let view = format!(
            r#"{{"evaluation_id":"e","effect":"{effect}","op":{{}},"view":[],"lease_s":60}}"#
        );
        assert_eq!(
            read_submission(view.as_bytes()).unwrap_err(),
            "invalid_view"
        );
        assert_eq!(read_submission(b"[]").unwrap_err(), "invalid_argument");
        assert_eq!(read_submission(b"{").unwrap_err(), "invalid_argument");
    }

    #[test]
    fn a_keepalive_body_has_the_member_subject_only() {
        let read = |text: &str| match parse_slice(text.as_bytes()) {
            Ok(Value::Object(map)) => subject_of(&map),
            _ => None,
        };
        assert_eq!(read(r#"{"subject":"key:a"}"#), Some("key:a".to_owned()));
        assert_eq!(read(r#"{"subject":""}"#), None);
        assert_eq!(read(r#"{"subject":"a","x":1}"#), None);
        assert_eq!(read("{}"), None);
    }
}
