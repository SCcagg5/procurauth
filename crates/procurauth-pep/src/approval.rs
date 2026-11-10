//! The approval of an effect (protocol section 17, binding 3.5a and 5.7).
//!
//! Each action of a service follows section 17 (5.2b). A use runs only after the owner approves
//! its effect, when the PDP asks for it. [`Pep::decide_approval`] follows the steps of 17.7.
//! It asks as 10.1 says, with no effect. On a reason of 17.1, it asks again with the effect and no
//! `context.usage`, and it submits the request. After a `true` answer, it asks with `context.usage`,
//! and it runs the action only after a `true` answer to that question.
//!
//! # What the PEP learns and what it never reads
//!
//! The PEP learns the verdict (17.6), and at the submission the id and the code of the
//! request. It never reads an `approval_ref`, an intent, an explanation or a text of the
//! owner (17.7, 17.12). It sends the `approval_ref` of the agent to the PDP as the agent gave
//! it. It sends the `evaluation_id` as the PDP gave it. The counters of [`ApprovalStats`]
//! show what the PEP received, so that a test can prove this.
//!
//! The PEP keeps no answer to a question that has an effect (17.7). It renews a lease only
//! for a call of the agent that names the request: [`Pep::approval_status`] and
//! [`Pep::approval_keepalive`]. It never renews on a timer of its own.

use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use procurauth_core::authzen::{Decision, EvaluationRequest, Reason};
use procurauth_core::effect::{check_op, check_view, effect_hash, resource_text};
use procurauth_core::json::parse_slice;
use serde_json::{Map, Value, json};

use crate::identity::Identity;
use crate::operation::{Operation, Permission};
use crate::pdp_client::PdpClient;
use crate::pep::{Allowed, Granted, Outcome, Pep};
use crate::refusal::{DenialCause, Refusal, UnavailableCause};
use crate::transport::HttpResponse;

/// The path of the routes of the approval API (17.4).
pub const REQUESTS_PATH: &str = "/approval/v1/requests";

/// The longest time that one call of the agent waits for a verdict, in seconds. The PEP
/// bounds `wait_s` with this value (binding 5.7). The PDP bounds the wait again (17.4).
pub const WAIT_MAX_SECONDS: u64 = 25;

/// The verdict of a request (17.6): the only state that a PEP learns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The owner did not decide.
    Pending,
    /// The owner approved.
    Approved,
    /// The owner declined.
    Denied,
    /// The approval is not valid. The PEP cannot know the cause.
    Void,
}

impl Verdict {
    /// The text of the protocol.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Void => "void",
        }
    }

    /// Read a verdict. A text that is not a verdict is `void` (17.7). The second value tells if the text was known.
    fn read(text: &str) -> (Self, bool) {
        match text {
            "pending" => (Self::Pending, true),
            "approved" => (Self::Approved, true),
            "denied" => (Self::Denied, true),
            "void" => (Self::Void, true),
            _ => (Self::Void, false),
        }
    }
}

/// How long the agent wants to wait (17.5), or the reference that it got from the PDP (17.4).
/// A call has at most one of the three (binding 5.7). The PEP needs one only to submit a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Control {
    /// `approval_ref`: an opaque text. The PEP never reads it.
    Reference(String),
    /// `lease_s`: a whole number of seconds.
    LeaseSeconds(u64),
    /// `until`: a time in the form of RFC 3339. The PDP checks it.
    Until(String),
}

/// What the call of an agent gives for the approval of an action (binding 5.7).
#[derive(Clone, Debug, PartialEq)]
pub struct ApprovalCall {
    /// The values that decide what the operation does (17.3a). A JSON object.
    pub op: Value,
    /// The template of what the owner reads (17.3a, 17.9). Each pointer names a value of `op`.
    pub view: Value,
    /// `approval_ref`, `lease_s` or `until`. A call that has none runs when the PDP asks for no approval.
    /// When the PDP asks for one, the PEP cannot submit and the call gets `invalid_argument` (binding 5.7).
    pub control: Option<Control>,
    /// The id of a request that this call replaces.
    pub supersedes: Option<String>,
    /// The most seconds that the call waits for a verdict. The PEP bounds it by [`WAIT_MAX_SECONDS`].
    pub wait_seconds: Option<u64>,
}

/// A request that waits for the owner (17.4, 17.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingApproval {
    /// The id that the PDP gave to the request.
    pub request_id: String,
    /// The short text that the owner sees. The agent can read it.
    pub code: String,
}

/// Why the approval refuses a call. Binding 5.7a gives the tool error of each one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ApprovalRefusal {
    /// The PDP answered `approval_denied`.
    Denied,
    /// The PDP answered `approval_expired`, or the verdict is `void`.
    Expired,
    /// A control argument is not valid, or the PDP refused the submission for such a cause.
    InvalidArgument,
    /// The PDP answered 409 `no_device`: the owner has no way to receive the request.
    NoDevice,
    /// The PDP answered 429 to the submission.
    RateLimited {
        /// The seconds to wait, as the PDP gave them.
        retry_after: u64,
    },
}

/// What the PEP received from the PDP on the approval API and in the answers that carry an effect.
/// A test reads it to prove that the PEP learned only the verdict.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApprovalStats {
    /// The submissions that the PEP sent.
    pub submissions: u64,
    /// The reads of a verdict that the PEP sent.
    pub status_reads: u64,
    /// The keepalive requests that the PEP sent.
    pub keepalives: u64,
    /// The verdicts `pending` that the PEP received.
    pub pending: u64,
    /// The verdicts `approved` that the PEP received.
    pub approved: u64,
    /// The verdicts `denied` that the PEP received.
    pub denied: u64,
    /// The verdicts `void` that the PEP received.
    pub void: u64,
    /// The texts that were not a verdict. The PEP treats each one as `void`.
    pub unknown_verdicts: u64,
    /// The members of the answers of the approval API that the PEP read. They are `verdict`, `request_id` and `code`.
    pub members_read: u64,
    /// The members of the answers of the approval API that the PEP did not read.
    pub members_ignored: u64,
    /// The `evaluation_id` that the PEP sent back without a read.
    pub evaluation_ids_sent: u64,
    /// The `approval_ref` that the PEP sent without a read.
    pub approval_refs_sent: u64,
}

impl PdpClient {
    pub(crate) fn stats(&self) -> MutexGuard<'_, ApprovalStats> {
        self.approval_stats
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    fn approval_url(&self, tail: &str) -> String {
        let path = self.base.path.trim_end_matches('/');
        self.base
            .with_path(&format!("{path}{REQUESTS_PATH}{tail}"))
            .to_text()
    }

    /// Send a request of the approval API. The PEP can send each request again. A second
    /// submission gives the same id (17.4), and a read changes nothing except the lease.
    fn api_request(
        &self,
        method: &str,
        url: &str,
        body: Option<Vec<u8>>,
        timeout: Duration,
    ) -> Result<HttpResponse, UnavailableCause> {
        let headers = [(
            "Authorization".to_owned(),
            format!("Bearer {}", self.credential.expose()),
        )];
        let mut retries = self.plain_retries;
        loop {
            let sent = match &body {
                Some(body) => self.transport.post_json(url, &headers, body, timeout),
                None => self.transport.get_json(url, &headers, timeout),
            };
            match sent {
                Ok(response) => {
                    if u64::try_from(response.body.len()).unwrap_or(u64::MAX)
                        > self.max_response_bytes
                    {
                        return Err(UnavailableCause::Answer(format!(
                            "the answer of {method} on the approval API is larger than `pdp.max_response_bytes`"
                        )));
                    }
                    return Ok(response);
                }
                Err(error) if error.can_repeat_plain_question() && retries > 0 => retries -= 1,
                Err(error) => return Err(UnavailableCause::Transport(error.to_string())),
            }
        }
    }

    /// Read the body of an answer as an object, and count its members.
    fn read_members(
        &self,
        response: &HttpResponse,
        read: &[&str],
    ) -> Result<Map<String, Value>, UnavailableCause> {
        let value = parse_slice(&response.body)
            .map_err(|e| UnavailableCause::Answer(format!("the body is not valid JSON: {e}")))?;
        let Value::Object(map) = value else {
            return Err(UnavailableCause::Answer(
                "the body is not a JSON object".to_owned(),
            ));
        };
        let mut stats = self.stats();
        for name in map.keys() {
            if read.contains(&name.as_str()) {
                stats.members_read += 1;
            } else {
                stats.members_ignored += 1;
            }
        }
        Ok(map)
    }

    /// The refusal for an answer of the approval API that is not a success (17.4, binding 5.7a).
    fn api_refusal(&self, response: &HttpResponse, unknown_request: bool) -> Refusal {
        let body = parse_slice(&response.body).ok();
        let code = body
            .as_ref()
            .and_then(|b| b.get("error"))
            .and_then(Value::as_str)
            .unwrap_or("");
        let status = response.status;
        match (status, code) {
            (429, _) => {
                let from_body = body
                    .as_ref()
                    .and_then(|b| b.get("retry_after"))
                    .and_then(Value::as_u64);
                let from_header = response
                    .headers
                    .iter()
                    .find(|(n, _)| n.eq_ignore_ascii_case("retry-after"))
                    .and_then(|(_, v)| v.trim().parse::<u64>().ok());
                let retry_after = from_body.or(from_header).filter(|s| *s >= 1).unwrap_or(1);
                Refusal::Approval(ApprovalRefusal::RateLimited { retry_after })
            }
            (409, "no_device") => Refusal::Approval(ApprovalRefusal::NoDevice),
            (413, "command_too_large")
            | (422, "invalid_argument" | "invalid_lease" | "lease_required") => {
                Refusal::Approval(ApprovalRefusal::InvalidArgument)
            }
            (404, _) if unknown_request => Refusal::Approval(ApprovalRefusal::InvalidArgument),
            // Any other answer is a failure of the approval API: HTTP 503 (binding 5.7a).
            _ => Refusal::Unavailable(UnavailableCause::Status(status)),
        }
    }

    /// Submit a request (17.4).
    pub(crate) fn submit_approval(&self, body: &Value) -> Result<PendingApproval, Refusal> {
        {
            let mut stats = self.stats();
            stats.submissions += 1;
            if body.get("approval_ref").is_some() {
                stats.approval_refs_sent += 1;
            }
            stats.evaluation_ids_sent += 1;
        }
        let response = self
            .api_request(
                "POST",
                &self.approval_url(""),
                Some(body.to_string().into_bytes()),
                self.request_timeout,
            )
            .map_err(Refusal::Unavailable)?;
        if !matches!(response.status, 200 | 201) {
            return Err(self.api_refusal(&response, false));
        }
        let map = self
            .read_members(&response, &["request_id", "code", "verdict"])
            .map_err(Refusal::Unavailable)?;
        let text = |name: &str| {
            map.get(name)
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())
                .map(str::to_owned)
        };
        let (Some(request_id), Some(code)) = (text("request_id"), text("code")) else {
            return Err(Refusal::Unavailable(UnavailableCause::Answer(
                "the answer to a submission has no `request_id` or no `code`".to_owned(),
            )));
        };
        if let Some(verdict) = map.get("verdict").and_then(Value::as_str) {
            self.count_verdict(verdict);
        }
        Ok(PendingApproval { request_id, code })
    }

    fn count_verdict(&self, text: &str) -> Verdict {
        let (verdict, known) = Verdict::read(text);
        let mut stats = self.stats();
        match verdict {
            Verdict::Pending => stats.pending += 1,
            Verdict::Approved => stats.approved += 1,
            Verdict::Denied => stats.denied += 1,
            Verdict::Void => stats.void += 1,
        }
        if !known {
            stats.unknown_verdicts += 1;
        }
        verdict
    }

    fn verdict_of(&self, response: &HttpResponse) -> Result<Verdict, Refusal> {
        if response.status != 200 {
            return Err(self.api_refusal(response, true));
        }
        let map = self
            .read_members(response, &["verdict"])
            .map_err(Refusal::Unavailable)?;
        let text = map
            .get("verdict")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                Refusal::Unavailable(UnavailableCause::Answer(
                    "the answer has no `verdict`".to_owned(),
                ))
            })?
            .to_owned();
        Ok(self.count_verdict(&text))
    }

    /// Read the verdict of a request (17.4). A read renews the lease only with `renew`.
    pub(crate) fn read_verdict(
        &self,
        request_id: &str,
        subject: &str,
        wait_seconds: Option<u64>,
        renew: bool,
    ) -> Result<Verdict, Refusal> {
        self.stats().status_reads += 1;
        let mut query = format!("?subject={}", percent_encode(subject));
        let mut timeout = self.request_timeout;
        if let Some(wait) = wait_seconds.filter(|w| *w > 0) {
            query.push_str(&format!("&wait={wait}"));
            timeout += Duration::from_secs(wait);
        }
        if renew {
            query.push_str("&renew=true");
        }
        let url = self.approval_url(&format!("/{}{query}", percent_encode(request_id)));
        let response = self
            .api_request("GET", &url, None, timeout)
            .map_err(Refusal::Unavailable)?;
        self.verdict_of(&response)
    }

    /// Renew the lease and read the verdict (17.4).
    pub(crate) fn keepalive(&self, request_id: &str, subject: &str) -> Result<Verdict, Refusal> {
        self.stats().keepalives += 1;
        let url = self.approval_url(&format!("/{}/keepalive", percent_encode(request_id)));
        let body = json!({"subject": subject}).to_string().into_bytes();
        let response = self
            .api_request("POST", &url, Some(body), self.request_timeout)
            .map_err(Refusal::Unavailable)?;
        self.verdict_of(&response)
    }
}

/// Percent-encode a text for a query value or a path segment (RFC 3986): keep the unreserved characters.
fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// A lock for the counters, with the state that a poisoned lock keeps.
pub(crate) fn new_stats() -> Mutex<ApprovalStats> {
    Mutex::new(ApprovalStats::default())
}

fn operation_error(why: &str) -> Refusal {
    Refusal::Internal(why.to_owned())
}

impl Pep {
    /// What the PEP received on the approval API since the start.
    pub fn approval_stats(&self) -> ApprovalStats {
        self.client.stats().clone()
    }

    /// Ask for an operation, and follow the steps of 17.7. This works for each action.
    ///
    /// 1. Ask as 10.1 says: the question of the use, with `context.usage` when the action lists a
    ///    budget, and no effect. A `true` answer, and a `false` answer with another reason than
    ///    17.1, end here as 10.3 says.
    /// 2. On a reason of 17.1, call `build`, which gives `op`, `view` and the controls of the call
    ///    (17.3a). Ask without `context.usage`, with the effect. This answer is never kept.
    /// 3. On `approval_required` or `approval_pending`, submit the request and give
    ///    [`Outcome::ApprovalRequired`]. The caller runs nothing.
    /// 4. On `approval_denied` or `approval_expired`, refuse, and ask nothing more.
    /// 5. On `true`, ask with `context.usage` and the same effect. Run the action only after a
    ///    `true` answer to this question.
    ///
    /// `build` runs only when the PDP asks for an approval. A call that needs none has no cost for it,
    /// and an error of `build` never refuses such a call. The effect comes from `op` and from the
    /// action and the node of the operation (17.3). `op` must hold only the values that the PEP runs.
    /// The operation has one use. Its other permissions (5.5a) are asked first, with no effect.
    pub fn decide_approval(
        &self,
        who: &Identity,
        operation: &Operation,
        build: impl FnOnce() -> Result<ApprovalCall, ApprovalRefusal>,
    ) -> Outcome {
        match self.approval_inner(who, operation, build) {
            Ok(outcome) => outcome,
            Err(refusal) => Outcome::Refused(refusal),
        }
    }

    fn approval_question(
        who: &Identity,
        permission: &Permission,
        effect: &str,
        usage: bool,
    ) -> EvaluationRequest {
        let mut question = EvaluationRequest::new(who.sub(), &permission.action, &permission.node);
        if usage {
            question = question.with_usage();
        }
        question
            .context
            .get_or_insert_with(Map::new)
            .insert("approval".to_owned(), json!({"effect": effect}));
        question
    }

    fn approval_inner(
        &self,
        who: &Identity,
        operation: &Operation,
        build: impl FnOnce() -> Result<ApprovalCall, ApprovalRefusal>,
    ) -> Result<Outcome, Refusal> {
        let (Some(permission), 1) = (operation.uses().first(), operation.uses().len()) else {
            return Err(operation_error("an operation with an approval has one use"));
        };
        self.validate_operation(operation)?;
        let others = self.ask_others(who.sub(), operation)?;
        // Step 1: the question of 10.1, with no effect. Only a reason of 17.1 starts the flow.
        match self.run_use(who.sub(), operation.uses(), true) {
            Ok((units, used)) => return Ok(Outcome::Allowed(Allowed::new(units, used, others))),
            Err(Refusal::Forbidden {
                reason: Some(reason),
                cause: DenialCause::Decision,
            }) if reason.is_approval() => {}
            Err(refusal) => return Err(refusal),
        }
        let call = build().map_err(Refusal::Approval)?;
        if check_view(&call.view, &call.op).is_err() {
            return Err(operation_error(
                "the view of the operation is not valid for its op",
            ));
        }
        if check_op(&call.op).is_err() {
            return Err(Refusal::Approval(ApprovalRefusal::InvalidArgument));
        }
        let effect = effect_hash(
            self.service_id(),
            &permission.action,
            &resource_text(&permission.node),
            &call.op,
        )
        .map_err(|_| Refusal::Approval(ApprovalRefusal::InvalidArgument))?;
        let mut wait = call.wait_seconds.map(|w| w.min(WAIT_MAX_SECONDS));
        // At most two rounds: after a wait that ends with `approved`, the PEP asks again from the start.
        for _ in 0..2 {
            let plain = self
                .client
                .ask(
                    &Self::approval_question(who, permission, &effect, false),
                    false,
                )
                .map_err(Refusal::Unavailable)?;
            if plain.decision {
                return self.approval_use(who, permission, &effect, others);
            }
            match plain.context.reason {
                Some(Reason::ApprovalRequired | Reason::ApprovalPending) => {}
                Some(Reason::ApprovalDenied) => {
                    return Err(Refusal::Approval(ApprovalRefusal::Denied));
                }
                Some(Reason::ApprovalExpired) => {
                    return Err(Refusal::Approval(ApprovalRefusal::Expired));
                }
                _ => return Err(denial(&plain)),
            }
            // 17.7, step 3: the PEP sends the `evaluation_id` back as it came. It never reads it.
            let Some(evaluation_id) = plain.context.evaluation_id.clone() else {
                // Without the id the PEP cannot submit. It fails closed (decision 83).
                return Err(denial(&plain));
            };
            // A call with no control argument cannot give a lease. The PEP submits nothing (binding 5.7).
            let Some(control) = call.control.as_ref() else {
                return Err(Refusal::Approval(ApprovalRefusal::InvalidArgument));
            };
            let pending = self.client.submit_approval(&submission(
                &evaluation_id,
                &effect,
                &call.op,
                &call.view,
                control,
                call.supersedes.as_deref(),
            ))?;
            let Some(seconds) = wait.take().filter(|w| *w > 0) else {
                return Ok(Outcome::ApprovalRequired(pending));
            };
            // A wait is only a help. A failed read leaves the call with the result "it waits".
            match self
                .client
                .read_verdict(&pending.request_id, who.sub(), Some(seconds), false)
            {
                Ok(Verdict::Approved) => {}
                Ok(Verdict::Denied) => return Err(Refusal::Approval(ApprovalRefusal::Denied)),
                Ok(Verdict::Void) => return Err(Refusal::Approval(ApprovalRefusal::Expired)),
                Ok(Verdict::Pending) | Err(_) => {
                    return Ok(Outcome::ApprovalRequired(pending));
                }
            }
        }
        Err(Refusal::Forbidden {
            reason: Some(Reason::ApprovalRequired),
            cause: DenialCause::Decision,
        })
    }

    /// The use of an approved effect: the question with `context.usage` (17.2, 17.7 step 5).
    /// The PEP sends it also when the action lists no budget.
    fn approval_use(
        &self,
        who: &Identity,
        permission: &Permission,
        effect: &str,
        others: Vec<Granted>,
    ) -> Result<Outcome, Refusal> {
        let answer = self
            .client
            .ask(
                &Self::approval_question(who, permission, effect, true),
                true,
            )
            .map_err(Refusal::Unavailable)?;
        if answer.decision {
            // 6.12: a `true` answer without `context.usage.units` counts as `false`.
            let Some(units) = answer.context.usage_units else {
                return Err(Refusal::Forbidden {
                    reason: None,
                    cause: DenialCause::NoUsageUnits,
                });
            };
            let ceilings = self.ceilings_of(&permission.action, &answer)?;
            return Ok(Outcome::Allowed(Allowed::new(
                units,
                Granted {
                    permission: permission.clone(),
                    ceilings,
                },
                others,
            )));
        }
        match answer.context.reason {
            Some(Reason::BudgetExceeded) => Err(Refusal::RateLimited {
                retry_after: answer.context.retry_after.unwrap_or(1),
            }),
            Some(Reason::ApprovalDenied) => Err(Refusal::Approval(ApprovalRefusal::Denied)),
            Some(Reason::ApprovalExpired) => Err(Refusal::Approval(ApprovalRefusal::Expired)),
            // Another answer is treated as 10.3 says (17.7, step 6).
            _ => Err(denial(&answer)),
        }
    }

    /// Read the verdict of a request for a call of the agent that names it. The read renews the
    /// lease of the request, and it names the subject of the token (17.4, binding 5.7b).
    ///
    /// # Errors
    /// Returns [`ApprovalRefusal::InvalidArgument`] for a request that is unknown or that is of
    /// another subject. Returns [`Refusal::Unavailable`] when the approval API does not answer.
    pub fn approval_status(&self, who: &Identity, request_id: &str) -> Result<Verdict, Refusal> {
        self.client.read_verdict(request_id, who.sub(), None, true)
    }

    /// Renew the lease of a request with the route `keepalive` (17.4), for a call of the agent that names it.
    ///
    /// # Errors
    /// The errors are those of [`Pep::approval_status`].
    pub fn approval_keepalive(&self, who: &Identity, request_id: &str) -> Result<Verdict, Refusal> {
        self.client.keepalive(request_id, who.sub())
    }
}

/// The body of a submission (17.4). It has the members that 17.4 lists and no other.
fn submission(
    evaluation_id: &str,
    effect: &str,
    op: &Value,
    view: &Value,
    control: &Control,
    supersedes: Option<&str>,
) -> Value {
    let mut body = Map::new();
    body.insert("evaluation_id".into(), json!(evaluation_id));
    body.insert("effect".into(), json!(effect));
    body.insert("op".into(), op.clone());
    body.insert("view".into(), view.clone());
    match control {
        Control::Reference(text) => body.insert("approval_ref".into(), json!(text)),
        Control::LeaseSeconds(seconds) => body.insert("lease_s".into(), json!(seconds)),
        Control::Until(text) => body.insert("until".into(), json!(text)),
    };
    if let Some(id) = supersedes {
        body.insert("supersedes".into(), json!(id));
    }
    Value::Object(body)
}

/// The refusal for a `false` answer that the approval does not map (10.3).
fn denial(decision: &Decision) -> Refusal {
    Refusal::Forbidden {
        reason: decision.context.reason.clone(),
        cause: DenialCause::Decision,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_17_7_a_text_that_is_not_a_verdict_is_void() {
        assert_eq!(Verdict::read("approved"), (Verdict::Approved, true));
        assert_eq!(Verdict::read("approved_by_alice"), (Verdict::Void, false));
        assert_eq!(Verdict::read(""), (Verdict::Void, false));
    }

    #[test]
    fn a_query_value_keeps_the_unreserved_characters_only() {
        assert_eq!(percent_encode("key:ab-1_x.y~z"), "key%3Aab-1_x.y~z");
        assert_eq!(percent_encode("a b/c&d"), "a%20b%2Fc%26d");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn p_17_4_a_submission_has_exactly_one_control_and_the_listed_members() {
        let (op, view) = (json!({"tool": "t"}), json!({"title": "T"}));
        let body = submission(
            "ev",
            "sha256:00",
            &op,
            &view,
            &Control::LeaseSeconds(900),
            None,
        );
        let names: Vec<&str> = body
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(names, ["effect", "evaluation_id", "lease_s", "op", "view"]);
        let body = submission(
            "ev",
            "sha256:00",
            &op,
            &view,
            &Control::Reference("r".into()),
            Some("apr_1"),
        );
        assert_eq!(body["approval_ref"], "r");
        assert_eq!(body["supersedes"], "apr_1");
        assert!(body.get("lease_s").is_none());
        assert!(body.get("wait_s").is_none());
    }
}
