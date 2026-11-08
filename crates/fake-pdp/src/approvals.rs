//! The approvals of the test PDP (protocol section 17).
//!
//! This module has no network code and no clock. A caller gives the time in seconds in each call.
//! It holds the requests, the evaluation ids and the references of the agent. It decides whether
//! an approval can be used (17.1, 17.2), and it checks and keeps a submission (17.4, 17.9).
//! It also answers a read and a renewal (17.5, 17.6), and it takes the answer of the owner.
//!
//! The values that the PDP "publishes" are the constants of this module. The metadata of the
//! server publishes them. The module never changes a value to make it fit: a value outside a
//! bound is an error.

use std::collections::HashMap;

use procurauth_core::approvals::{
    ApprovalStatus, Comment, CommentIntent, OwnerDecision, SeedApproval,
};
use procurauth_core::effect::{check_op, check_view, effect_hash, resource_text};
use procurauth_core::path::NodePath;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

/// The shortest `lease_s` (17.5).
pub const LEASE_MIN_SECONDS: u64 = 30;
/// The longest `lease_s` (17.5): 7 days.
pub const LEASE_MAX_SECONDS: u64 = 604_800;
/// The grace time after a lease (17.5).
pub const GRACE_SECONDS: u64 = 120;
/// The time after which a request that is abandoned cannot be revived (17.5): 7 days.
pub const REVIVE_SECONDS: u64 = 604_800;
/// The most revivals of one request (17.5).
pub const MAX_REVIVALS: u32 = 3;
/// The longest life of a request (17.5): 90 days.
pub const MAX_LIFE_SECONDS: u64 = 7_776_000;
/// The longest `wait` of a read (17.4). A longer value waits this long.
pub const WAIT_MAX_SECONDS: u64 = 25;
/// The shortest consume time after an answer `approve` (17.6).
pub const CONSUME_SECONDS: u64 = 300;
/// The deny time after an answer `decline` (17.6).
pub const DENY_SECONDS: u64 = 300;
/// The time that an `evaluation_id` stays valid (17.1).
pub const EVALUATION_TTL_SECONDS: u64 = 300;
/// The time that an `approval_ref` stays valid (17.4).
pub const REF_TTL_SECONDS: u64 = 900;
/// The largest size of `op` and `view` together, in bytes (17.4).
pub const MAX_COMMAND_BYTES: usize = 65_536;
/// The most requests of one subject that wait for an answer (17.4).
pub const MAX_OPEN_PER_SUBJECT: usize = 20;
/// The `retry_after` of the error `rate_limited` (17.4).
pub const RATE_LIMIT_RETRY_SECONDS: u64 = 60;
/// The most evaluation ids that the PDP keeps.
const MAX_EVALUATIONS: usize = 100_000;

/// How long a request waits for the owner (17.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lease {
    /// No time limit except the longest life. The requests of the data file have this form.
    None,
    /// The lease lasts 3 times these seconds after the last renewal.
    Seconds(u64),
    /// The request is `expired` at this time, in seconds since the Unix epoch.
    Until(u64),
}

/// One request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    /// The id.
    pub id: String,
    /// The short text that the owner sees.
    pub code: String,
    /// The service.
    pub service: String,
    /// The subject.
    pub subject: String,
    /// The action.
    pub action: String,
    /// The node.
    pub resource: NodePath,
    /// The effect.
    pub effect: String,
    /// The status.
    pub status: ApprovalStatus,
    /// The answer of the owner.
    pub decision: Option<OwnerDecision>,
    /// The last second at which the approval can be used.
    pub consume_before: Option<u64>,
    /// True when the approval is consumed.
    pub consumed: bool,
    /// The end of the deny time.
    pub deny_until: Option<u64>,
    /// The owner who answered.
    pub answered_by: Option<String>,
    /// The device of the answer.
    pub device: Option<String>,
    /// The time of the answer.
    pub answered_at: Option<u64>,
    /// The text of a refusal.
    pub comment: Option<Comment>,
    /// The command: `op`. A request of the data file has none.
    pub op: Option<Value>,
    /// The command: `view`.
    pub view: Option<Value>,
    /// The lease.
    pub lease: Lease,
    /// The time of the submission.
    pub created: u64,
    /// The time of the last renewal.
    pub renewed: u64,
    /// The time at which the request became abandoned.
    pub abandoned_at: Option<u64>,
    /// The number of revivals.
    pub revivals: u32,
    /// True when the intent of the agent lets the owner write a text with a refusal (17.11).
    pub allow_custom: bool,
}

impl Request {
    fn from_seed(seed: &SeedApproval) -> Self {
        Self {
            id: seed.id.clone(),
            code: code_of(&seed.id),
            service: seed.resource.service_id().to_owned(),
            subject: seed.subject.clone(),
            action: seed.action.clone(),
            resource: seed.resource.clone(),
            effect: seed.effect.clone(),
            status: seed.status,
            decision: seed.decision,
            consume_before: seed.consume_before,
            consumed: seed.consumed,
            deny_until: seed.deny_until,
            answered_by: seed.answered_by.clone(),
            device: seed.device.clone(),
            answered_at: seed.answered_at,
            comment: seed.comment.clone(),
            op: None,
            view: None,
            lease: Lease::None,
            created: 0,
            renewed: 0,
            abandoned_at: None,
            revivals: 0,
            allow_custom: seed.comment.is_some(),
        }
    }

    fn same_key(
        &self,
        service: &str,
        subject: &str,
        action: &str,
        resource: &NodePath,
        effect: &str,
    ) -> bool {
        self.service == service
            && self.subject == subject
            && self.action == action
            && &self.resource == resource
            && self.effect == effect
    }

    fn waits(&self) -> bool {
        matches!(
            self.status,
            ApprovalStatus::Pending | ApprovalStatus::Replied
        )
    }

    /// The request as JSON, with all its members. Only the test control uses this form.
    pub fn to_admin_value(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("id".into(), json!(self.id));
        m.insert("code".into(), json!(self.code));
        m.insert("service".into(), json!(self.service));
        m.insert("subject".into(), json!(self.subject));
        m.insert("action".into(), json!(self.action));
        m.insert("resource".into(), json!(self.resource.to_string()));
        m.insert("effect".into(), json!(self.effect));
        m.insert("status".into(), json!(self.status.as_str()));
        if let Some(decision) = self.decision {
            m.insert("decision".into(), json!(decision.as_str()));
        }
        if let Some(t) = self.consume_before {
            m.insert("consume_before".into(), json!(t));
        }
        if self.decision == Some(OwnerDecision::Approve) {
            m.insert("consumed".into(), json!(self.consumed));
        }
        if let Some(t) = self.deny_until {
            m.insert("deny_until".into(), json!(t));
        }
        if let Some(text) = &self.answered_by {
            m.insert("answered_by".into(), json!(text));
        }
        if let Some(text) = &self.device {
            m.insert("device".into(), json!(text));
        }
        if let Some(t) = self.answered_at {
            m.insert("answered_at".into(), json!(t));
        }
        if let Some(c) = &self.comment {
            m.insert(
                "comment".into(),
                json!({"text": c.text, "intent": c.intent.as_str()}),
            );
        }
        if let Some(op) = &self.op {
            m.insert("op".into(), op.clone());
        }
        if let Some(view) = &self.view {
            m.insert("view".into(), view.clone());
        }
        match self.lease {
            Lease::None => {}
            Lease::Seconds(s) => {
                m.insert("lease_s".into(), json!(s));
            }
            Lease::Until(t) => {
                m.insert("until".into(), json!(t));
            }
        }
        m.insert("created".into(), json!(self.created));
        m.insert("renewed".into(), json!(self.renewed));
        m.insert("revivals".into(), json!(self.revivals));
        m.insert("allow_custom".into(), json!(self.allow_custom));
        Value::Object(m)
    }
}

/// A short text for the owner: four characters from a set without look-alikes.
fn code_of(id: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let digest = Sha256::digest(id.as_bytes());
    digest
        .iter()
        .take(4)
        .map(|b| char::from(ALPHABET[usize::from(*b) % ALPHABET.len()]))
        .collect()
}

/// What an `evaluation_id` binds (17.1).
#[derive(Clone, Debug, PartialEq, Eq)]
struct Evaluation {
    service: String,
    subject: String,
    action: String,
    resource: NodePath,
    effect: String,
    issued: u64,
}

/// An `approval_ref` of the agent (17.4). It comes from a channel outside the protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Reference {
    subject: String,
    lease: Lease,
    allow_custom: bool,
    issued: u64,
    used: bool,
}

/// The result of the gate of 17.1 for a question with an effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// No approval, or the approval is consumed, or a deny time ended: `approval_required`.
    Required,
    /// The request waits for the owner: `approval_pending`.
    Pending,
    /// The owner declined and the deny time has not ended: `approval_denied`.
    Denied,
    /// The approval ended and the question has usage: `approval_expired`.
    Expired,
    /// The approval can be used. The number is the index to give to [`Approvals::consume`].
    Usable(usize),
}

/// The verdict that a PEP learns (17.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The owner has not decided.
    Pending,
    /// The owner approved, and the approval is consumed or can be used.
    Approved,
    /// The owner declined.
    Denied,
    /// The request ended with no approval.
    Void,
}

impl Verdict {
    /// The word of the API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Void => "void",
        }
    }
}

/// An error of the narrow API (17.4): the status and the code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApiError {
    /// The HTTP status.
    pub status: u16,
    /// The code of the body.
    pub code: &'static str,
    /// The seconds to wait. Only with `rate_limited`.
    pub retry_after: Option<u64>,
}

impl ApiError {
    fn new(status: u16, code: &'static str) -> Self {
        Self {
            status,
            code,
            retry_after: None,
        }
    }

    /// The body of the error.
    pub fn to_value(&self) -> Value {
        match self.retry_after {
            Some(seconds) => json!({"error": self.code, "retry_after": seconds}),
            None => json!({"error": self.code}),
        }
    }
}

/// The way that the agent says how long it waits (17.5), as the submission gives it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LeaseGiven {
    /// `approval_ref`.
    pub approval_ref: Option<String>,
    /// `lease_s`, when it is a whole number.
    pub lease_s: Option<u64>,
    /// `until`, in seconds, when it is a good RFC 3339 time.
    pub until: Option<u64>,
    /// True when `lease_s` is present but is not a whole number, or `until` is not a good time.
    pub malformed: bool,
}

/// A submission, after the reader of the body (17.4).
#[derive(Clone, Debug, PartialEq)]
pub struct Submission {
    /// `evaluation_id`.
    pub evaluation_id: String,
    /// `effect`.
    pub effect: String,
    /// `op`.
    pub op: Value,
    /// `view`.
    pub view: Value,
    /// The lease.
    pub lease: LeaseGiven,
    /// `supersedes`.
    pub supersedes: Option<String>,
}

/// The result of a submission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Submitted {
    /// The id of the request.
    pub request_id: String,
    /// The code of the request.
    pub code: String,
    /// True for a new request (HTTP 201), false for a request that still waits (HTTP 200).
    pub created: bool,
}

/// The requests, the evaluation ids and the references of the agent.
#[derive(Clone, Debug, Default)]
pub struct Approvals {
    requests: Vec<Request>,
    seed: Vec<Request>,
    evaluations: HashMap<String, Evaluation>,
    refs: HashMap<String, Reference>,
    counter: u64,
}

impl Approvals {
    /// The requests of the data file. A `reset` puts them back.
    pub fn from_seed(seed: &[SeedApproval]) -> Self {
        let requests: Vec<Request> = seed.iter().map(Request::from_seed).collect();
        Self {
            seed: requests.clone(),
            requests,
            ..Self::default()
        }
    }

    /// Put the requests back to the data file. Forget the evaluation ids and the references.
    pub fn reset(&mut self) {
        self.requests = self.seed.clone();
        self.evaluations.clear();
        self.refs.clear();
        self.counter = 0;
    }

    /// All the requests, the oldest first.
    pub fn requests(&self) -> &[Request] {
        &self.requests
    }

    /// Apply the end of a lease, of an `until` time and of a longest life (17.5).
    fn settle(&mut self, now: u64) {
        for r in &mut self.requests {
            if !r.waits() || r.lease == Lease::None {
                continue;
            }
            let end_of_life = r.created.saturating_add(MAX_LIFE_SECONDS);
            let lease_end = match r.lease {
                Lease::Seconds(s) => Some(
                    r.renewed
                        .saturating_add(s.saturating_mul(3))
                        .saturating_add(GRACE_SECONDS),
                ),
                _ => None,
            };
            if now >= end_of_life || matches!(r.lease, Lease::Until(t) if now >= t) {
                r.status = ApprovalStatus::Expired;
            } else if let Some(end) = lease_end
                && now > end
            {
                r.status = ApprovalStatus::Abandoned;
                r.abandoned_at = Some(end);
            }
        }
    }

    fn latest_index(
        &self,
        service: &str,
        subject: &str,
        action: &str,
        resource: &NodePath,
        effect: &str,
    ) -> Option<usize> {
        self.requests
            .iter()
            .rposition(|r| r.same_key(service, subject, action, resource, effect))
    }

    /// The gate of 17.1 for the latest request of the same service, subject, action, resource and effect.
    pub fn gate(
        &mut self,
        now: u64,
        key: (&str, &str, &str, &NodePath, &str),
        with_usage: bool,
    ) -> Gate {
        self.settle(now);
        let (service, subject, action, resource, effect) = key;
        let Some(index) = self.latest_index(service, subject, action, resource, effect) else {
            return Gate::Required;
        };
        let r = &self.requests[index];
        match (r.status, r.decision) {
            (ApprovalStatus::Pending | ApprovalStatus::Replied, _) => Gate::Pending,
            (ApprovalStatus::Answered, Some(OwnerDecision::Decline)) => {
                if r.deny_until.is_some_and(|end| now < end) {
                    Gate::Denied
                } else {
                    Gate::Required
                }
            }
            (ApprovalStatus::Answered, _) => {
                if r.consumed {
                    Gate::Required
                } else if r.consume_before.is_some_and(|end| now <= end) {
                    Gate::Usable(index)
                } else if with_usage {
                    Gate::Expired
                } else {
                    Gate::Required
                }
            }
            _ => {
                if with_usage {
                    Gate::Expired
                } else {
                    Gate::Required
                }
            }
        }
    }

    /// Consume the approval that [`Approvals::gate`] found usable (17.2).
    pub fn consume(&mut self, index: usize) {
        if let Some(r) = self.requests.get_mut(index) {
            r.consumed = true;
        }
    }

    /// Give an `evaluation_id` that binds the question (17.1).
    pub fn issue_evaluation(
        &mut self,
        now: u64,
        key: (&str, &str, &str, &NodePath, &str),
    ) -> String {
        let (service, subject, action, resource, effect) = key;
        if self.evaluations.len() >= MAX_EVALUATIONS {
            self.evaluations
                .retain(|_, e| e.issued.saturating_add(EVALUATION_TTL_SECONDS) >= now);
            if self.evaluations.len() >= MAX_EVALUATIONS {
                self.evaluations.clear();
            }
        }
        self.counter += 1;
        let mut hash = Sha256::new();
        hash.update(self.counter.to_be_bytes());
        for part in [service, subject, action, &resource.to_string(), effect] {
            hash.update(part.as_bytes());
            hash.update([0]);
        }
        let digits: String = hash
            .finalize()
            .iter()
            .take(12)
            .map(|b| format!("{b:02x}"))
            .collect();
        let id = format!("ev_{digits}");
        self.evaluations.insert(
            id.clone(),
            Evaluation {
                service: service.to_owned(),
                subject: subject.to_owned(),
                action: action.to_owned(),
                resource: resource.clone(),
                effect: effect.to_owned(),
                issued: now,
            },
        );
        id
    }

    /// Register an `approval_ref` of an agent. The test control calls this.
    /// Exactly one of `lease_s` and `until` is given, as the intent of the agent says.
    pub fn add_reference(
        &mut self,
        now: u64,
        reference: &str,
        subject: &str,
        lease: Lease,
        allow_custom: bool,
    ) {
        self.refs.insert(
            reference.to_owned(),
            Reference {
                subject: subject.to_owned(),
                lease,
                allow_custom,
                issued: now,
                used: false,
            },
        );
    }

    fn new_id(&mut self) -> String {
        loop {
            self.counter += 1;
            let id = format!("apr_{:06x}", self.counter);
            if !self.requests.iter().any(|r| r.id == id) {
                return id;
            }
        }
    }

    /// Check a submission and keep the request (17.4, 17.9).
    ///
    /// `caller_service` is the service of the credential, when the credential belongs to one.
    ///
    /// # Errors
    /// Returns the error of 17.4 for the first check that fails.
    pub fn submit(
        &mut self,
        now: u64,
        caller_service: Option<&str>,
        submission: &Submission,
    ) -> Result<Submitted, ApiError> {
        self.settle(now);
        let given = &submission.lease;
        let count = usize::from(given.approval_ref.is_some())
            + usize::from(given.lease_s.is_some())
            + usize::from(given.until.is_some());
        if given.malformed {
            return Err(ApiError::new(422, "invalid_lease"));
        }
        if count == 0 {
            return Err(ApiError::new(422, "lease_required"));
        }
        if count > 1 {
            return Err(ApiError::new(422, "invalid_lease"));
        }
        if submission.op.to_string().len() + submission.view.to_string().len() > MAX_COMMAND_BYTES {
            return Err(ApiError::new(413, "command_too_large"));
        }
        let evaluation = match self.evaluations.get(&submission.evaluation_id) {
            Some(e)
                if now <= e.issued.saturating_add(EVALUATION_TTL_SECONDS)
                    && caller_service.is_none_or(|own| own == e.service)
                    && e.effect == submission.effect =>
            {
                e.clone()
            }
            _ => return Err(ApiError::new(422, "invalid_evaluation")),
        };
        if check_op(&submission.op).is_err() {
            return Err(ApiError::new(422, "invalid_op"));
        }
        let computed = effect_hash(
            &evaluation.service,
            &evaluation.action,
            &resource_text(&evaluation.resource),
            &submission.op,
        )
        .map_err(|_| ApiError::new(422, "invalid_op"))?;
        if computed != submission.effect {
            return Err(ApiError::new(422, "effect_mismatch"));
        }
        if check_view(&submission.view, &submission.op).is_err() {
            return Err(ApiError::new(422, "invalid_view"));
        }

        let (lease, allow_custom) = if let Some(reference) = &given.approval_ref {
            let found = self.refs.get(reference);
            match found {
                Some(r)
                    if !r.used
                        && r.subject == evaluation.subject
                        && now <= r.issued.saturating_add(REF_TTL_SECONDS) =>
                {
                    (r.lease, r.allow_custom)
                }
                _ => return Err(ApiError::new(422, "invalid_argument")),
            }
        } else if let Some(seconds) = given.lease_s {
            if !(LEASE_MIN_SECONDS..=LEASE_MAX_SECONDS).contains(&seconds) {
                return Err(ApiError::new(422, "invalid_lease"));
            }
            (Lease::Seconds(seconds), false)
        } else if let Some(until) = given.until {
            if until <= now || until > now.saturating_add(MAX_LIFE_SECONDS) {
                return Err(ApiError::new(422, "invalid_lease"));
            }
            (Lease::Until(until), false)
        } else {
            return Err(ApiError::new(422, "lease_required"));
        };

        let superseded = match &submission.supersedes {
            None => None,
            Some(id) => {
                let found = self.requests.iter().position(|r| {
                    r.id == *id
                        && r.subject == evaluation.subject
                        && r.service == evaluation.service
                });
                let Some(index) = found else {
                    return Err(ApiError::new(422, "invalid_argument"));
                };
                let r = &self.requests[index];
                if r.consumed {
                    return Err(ApiError::new(409, "cannot_supersede"));
                }
                Some(index)
            }
        };

        // A request for the same service, subject, action, resource and effect that still waits.
        if let Some(r) = self.requests.iter().find(|r| {
            r.waits()
                && r.same_key(
                    &evaluation.service,
                    &evaluation.subject,
                    &evaluation.action,
                    &evaluation.resource,
                    &evaluation.effect,
                )
        }) {
            return Ok(Submitted {
                request_id: r.id.clone(),
                code: r.code.clone(),
                created: false,
            });
        }
        let open = self
            .requests
            .iter()
            .filter(|r| r.waits() && r.subject == evaluation.subject)
            .count();
        if open >= MAX_OPEN_PER_SUBJECT {
            return Err(ApiError {
                status: 429,
                code: "rate_limited",
                retry_after: Some(RATE_LIMIT_RETRY_SECONDS),
            });
        }

        if let Some(index) = superseded
            && !matches!(
                self.requests[index].status,
                ApprovalStatus::Abandoned
                    | ApprovalStatus::Expired
                    | ApprovalStatus::Cancelled
                    | ApprovalStatus::Superseded
            )
        {
            self.requests[index].status = ApprovalStatus::Superseded;
        }
        if let Some(reference) = &given.approval_ref
            && let Some(r) = self.refs.get_mut(reference)
        {
            r.used = true;
        }
        let id = self.new_id();
        let code = code_of(&id);
        self.requests.push(Request {
            id: id.clone(),
            code: code.clone(),
            service: evaluation.service,
            subject: evaluation.subject,
            action: evaluation.action,
            resource: evaluation.resource,
            effect: evaluation.effect,
            status: ApprovalStatus::Pending,
            decision: None,
            consume_before: None,
            consumed: false,
            deny_until: None,
            answered_by: None,
            device: None,
            answered_at: None,
            comment: None,
            op: Some(submission.op.clone()),
            view: Some(submission.view.clone()),
            lease,
            created: now,
            renewed: now,
            abandoned_at: None,
            revivals: 0,
            allow_custom,
        });
        Ok(Submitted {
            request_id: id,
            code,
            created: true,
        })
    }

    fn find(&self, service: Option<&str>, subject: &str, id: &str) -> Option<usize> {
        self.requests.iter().position(|r| {
            r.id == id && r.subject == subject && service.is_none_or(|own| own == r.service)
        })
    }

    /// Read the verdict of a request, and renew its lease when `renew` is true (17.4, 17.5).
    ///
    /// An unknown request, a request of another service and a request of another subject
    /// give the same error: HTTP 404 `not_found`.
    ///
    /// # Errors
    /// Returns `not_found` as above.
    pub fn verdict(
        &mut self,
        now: u64,
        service: Option<&str>,
        subject: &str,
        id: &str,
        renew: bool,
    ) -> Result<Verdict, ApiError> {
        self.settle(now);
        let Some(index) = self.find(service, subject, id) else {
            return Err(ApiError::new(404, "not_found"));
        };
        if renew {
            self.renew_at(index, now);
        }
        Ok(verdict_of(&self.requests[index], now))
    }

    fn renew_at(&mut self, index: usize, now: u64) {
        let r = &mut self.requests[index];
        match r.status {
            ApprovalStatus::Pending | ApprovalStatus::Replied => r.renewed = now,
            ApprovalStatus::Abandoned => {
                let in_time = r
                    .abandoned_at
                    .is_some_and(|t| now <= t.saturating_add(REVIVE_SECONDS));
                if in_time && r.revivals < MAX_REVIVALS {
                    r.status = ApprovalStatus::Pending;
                    r.abandoned_at = None;
                    r.revivals += 1;
                    r.renewed = now;
                }
            }
            _ => {}
        }
    }

    /// The answer of the owner (17.11). The test control calls this, in place of a session of the owner.
    ///
    /// # Errors
    /// Returns 404 for an unknown request and 409 for a request that does not wait.
    /// Returns 422 when `shown_effect` is not the effect of the request.
    /// Returns 422 also for a text that 17.11 refuses.
    pub fn answer(&mut self, now: u64, id: &str, answer: &OwnerAnswer) -> Result<(), ApiError> {
        self.settle(now);
        let Some(index) = self.requests.iter().position(|r| r.id == id) else {
            return Err(ApiError::new(404, "not_found"));
        };
        let r = &mut self.requests[index];
        if !r.waits() {
            return Err(ApiError::new(409, "not_waiting"));
        }
        if answer.shown_effect != r.effect {
            return Err(ApiError::new(422, "shown_effect_mismatch"));
        }
        if answer.comment.is_some()
            && (answer.decision == OwnerDecision::Approve || !r.allow_custom)
        {
            return Err(ApiError::new(422, "text_not_allowed"));
        }
        r.status = ApprovalStatus::Answered;
        r.decision = Some(answer.decision);
        r.answered_at = Some(now);
        r.answered_by.clone_from(&answer.answered_by);
        r.device.clone_from(&answer.device);
        r.comment.clone_from(&answer.comment);
        match answer.decision {
            OwnerDecision::Approve => {
                let window = match r.lease {
                    Lease::Seconds(s) => s.max(CONSUME_SECONDS),
                    _ => CONSUME_SECONDS,
                };
                r.consume_before = Some(now.saturating_add(window));
            }
            OwnerDecision::Decline => r.deny_until = Some(now.saturating_add(DENY_SECONDS)),
        }
        Ok(())
    }

    /// The owner asks the agent a question: `pending` becomes `replied` (17.6). Test control.
    ///
    /// # Errors
    /// Returns 404 for an unknown request, and 409 for a request that is not `pending`.
    pub fn reply(&mut self, now: u64, id: &str) -> Result<(), ApiError> {
        self.settle(now);
        let Some(r) = self.requests.iter_mut().find(|r| r.id == id) else {
            return Err(ApiError::new(404, "not_found"));
        };
        if r.status != ApprovalStatus::Pending {
            return Err(ApiError::new(409, "not_waiting"));
        }
        r.status = ApprovalStatus::Replied;
        Ok(())
    }

    /// Cancel a request that waits, or an approval that is not consumed (17.6). Test control.
    ///
    /// # Errors
    /// Returns 404 for an unknown request, and 409 for a request that is final or consumed.
    pub fn cancel(&mut self, now: u64, id: &str) -> Result<(), ApiError> {
        self.settle(now);
        let Some(r) = self.requests.iter_mut().find(|r| r.id == id) else {
            return Err(ApiError::new(404, "not_found"));
        };
        let open_approval = r.status == ApprovalStatus::Answered
            && r.decision == Some(OwnerDecision::Approve)
            && !r.consumed;
        if !(r.waits() || open_approval) {
            return Err(ApiError::new(409, "not_waiting"));
        }
        r.status = ApprovalStatus::Cancelled;
        Ok(())
    }
}

/// The answer of the owner, as the test control gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerAnswer {
    /// `approve` or `decline`.
    pub decision: OwnerDecision,
    /// The effect that the owner saw (17.11).
    pub shown_effect: String,
    /// The text of a refusal.
    pub comment: Option<Comment>,
    /// The owner.
    pub answered_by: Option<String>,
    /// The device.
    pub device: Option<String>,
}

fn verdict_of(r: &Request, now: u64) -> Verdict {
    match (r.status, r.decision) {
        (ApprovalStatus::Pending | ApprovalStatus::Replied, _) => Verdict::Pending,
        (ApprovalStatus::Answered, Some(OwnerDecision::Decline)) => Verdict::Denied,
        (ApprovalStatus::Answered, _) => {
            if r.consumed || r.consume_before.is_some_and(|end| now <= end) {
                Verdict::Approved
            } else {
                Verdict::Void
            }
        }
        _ => Verdict::Void,
    }
}

/// Read a time in RFC 3339 form as seconds since the Unix epoch. A fraction of a second is cut.
/// Return `None` for a text that is not a good time, or a time before 1970.
pub fn parse_rfc3339(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if !text.is_ascii() || bytes.len() < 20 {
        return None;
    }
    let digits = |from: usize, to: usize| -> Option<i64> {
        let part = text.get(from..to)?;
        part.bytes()
            .all(|b| b.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (digits(0, 4)?, digits(5, 7)?, digits(8, 10)?);
    if bytes[4] != b'-' || bytes[7] != b'-' || !matches!(bytes[10], b'T' | b't') {
        return None;
    }
    let (hour, minute, second) = (digits(11, 13)?, digits(14, 16)?, digits(17, 19)?);
    if bytes[13] != b':' || bytes[16] != b':' {
        return None;
    }
    let mut at = 19;
    if bytes[at] == b'.' {
        at += 1;
        let start = at;
        while at < bytes.len() && bytes[at].is_ascii_digit() {
            at += 1;
        }
        if at == start {
            return None;
        }
    }
    let offset_seconds = match bytes.get(at)? {
        b'Z' | b'z' if at + 1 == bytes.len() => 0,
        sign @ (b'+' | b'-') if at + 6 == bytes.len() => {
            if bytes[at + 3] != b':' {
                return None;
            }
            let (oh, om) = (digits(at + 1, at + 3)?, digits(at + 4, at + 6)?);
            if oh > 23 || om > 59 {
                return None;
            }
            let total = oh * 3600 + om * 60;
            if *sign == b'+' { total } else { -total }
        }
        _ => return None,
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > month_days[usize::try_from(month - 1).ok()?]
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    // Days from the civil date (the algorithm of H. Hinnant).
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let seconds = days * 86_400 + hour * 3600 + minute * 60 + second - offset_seconds;
    u64::try_from(seconds).ok()
}

/// The comment of a decline, from the pieces that the test control gives.
pub fn comment_of(text: &str, intent: &str) -> Option<Comment> {
    Some(Comment {
        text: text.to_owned(),
        intent: CommentIntent::parse(intent)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_792_569_648;

    fn node() -> NodePath {
        NodePath::parse("service:datastore/host:prod/database:analytics").unwrap()
    }

    fn key<'a>(
        subject: &'a str,
        node: &'a NodePath,
        effect: &'a str,
    ) -> (&'a str, &'a str, &'a str, &'a NodePath, &'a str) {
        ("datastore", subject, "data.write", node, effect)
    }

    fn op() -> Value {
        json!({"tool": "run_write_query", "sql": "DELETE 1"})
    }

    fn effect_of(op: &Value) -> String {
        effect_hash(
            "datastore",
            "data.write",
            "host:prod/database:analytics",
            op,
        )
        .unwrap()
    }

    fn submission(approvals: &mut Approvals, op: Value, lease: LeaseGiven) -> Submission {
        let n = node();
        let effect = effect_of(&op);
        let id = approvals.issue_evaluation(NOW, key("key:k1", &n, &effect));
        Submission {
            evaluation_id: id,
            effect,
            op,
            view: json!({"title": "Write"}),
            lease,
            supersedes: None,
        }
    }

    fn lease(seconds: u64) -> LeaseGiven {
        LeaseGiven {
            lease_s: Some(seconds),
            ..LeaseGiven::default()
        }
    }

    fn submit(approvals: &mut Approvals, now: u64) -> Submitted {
        let s = submission(approvals, op(), lease(60));
        approvals.submit(now, Some("datastore"), &s).unwrap()
    }

    fn approve(approvals: &mut Approvals, id: &str, now: u64) {
        let answer = OwnerAnswer {
            decision: OwnerDecision::Approve,
            shown_effect: effect_of(&op()),
            comment: None,
            answered_by: None,
            device: None,
        };
        approvals.answer(now, id, &answer).unwrap();
    }

    #[test]
    fn p_17_1_with_no_request_the_gate_says_required() {
        let mut a = Approvals::default();
        let n = node();
        assert_eq!(
            a.gate(NOW, key("key:k1", &n, "sha256:x"), true),
            Gate::Required
        );
    }

    #[test]
    fn p_17_4_a_submission_makes_a_pending_request_and_a_second_one_gives_the_same_id() {
        let mut a = Approvals::default();
        let first = submit(&mut a, NOW);
        assert!(first.created);
        assert_eq!(first.code.len(), 4);
        let second = submit(&mut a, NOW + 1);
        assert!(!second.created);
        assert_eq!(second.request_id, first.request_id);
        assert_eq!(second.code, first.code);
        // The second submission does not renew the lease.
        assert_eq!(a.requests()[0].renewed, NOW);
        let n = node();
        let effect = effect_of(&op());
        assert_eq!(
            a.gate(NOW + 1, key("key:k1", &n, &effect), false),
            Gate::Pending
        );
    }

    #[test]
    fn p_17_9_a_submission_is_checked_in_order() {
        let mut a = Approvals::default();
        let code =
            |a: &mut Approvals, s: &Submission| a.submit(NOW, Some("datastore"), s).unwrap_err();
        let good = submission(&mut a, op(), lease(60));

        let mut s = good.clone();
        s.evaluation_id = "ev_unknown".into();
        assert_eq!(code(&mut a, &s).code, "invalid_evaluation");

        let mut s = good.clone();
        s.effect = effect_of(&json!({"other": 1}));
        assert_eq!(code(&mut a, &s).code, "invalid_evaluation");

        // An op that does not give the effect of the evaluation.
        let n = node();
        let other = json!({"tool": "x"});
        let wrong_effect = effect_of(&op());
        let id = a.issue_evaluation(NOW, key("key:k1", &n, &wrong_effect));
        let mut s = good.clone();
        s.evaluation_id = id;
        s.op = other;
        assert_eq!(code(&mut a, &s).code, "effect_mismatch");

        let mut s = good.clone();
        s.op = json!({"x": 1.5});
        assert_eq!(code(&mut a, &s).code, "invalid_op");

        let mut s = good.clone();
        s.view = json!({"body": "/missing"});
        assert_eq!(code(&mut a, &s).code, "invalid_view");

        let mut s = good.clone();
        s.lease = LeaseGiven::default();
        assert_eq!(code(&mut a, &s).code, "lease_required");

        let mut s = good.clone();
        s.lease.until = Some(NOW + 100);
        assert_eq!(code(&mut a, &s).code, "invalid_lease");

        for bad in [LEASE_MIN_SECONDS - 1, LEASE_MAX_SECONDS + 1] {
            let mut s = good.clone();
            s.lease = lease(bad);
            assert_eq!(code(&mut a, &s).code, "invalid_lease", "{bad}");
        }

        let mut s = good.clone();
        s.op = json!({"pad": "x".repeat(MAX_COMMAND_BYTES)});
        let error = code(&mut a, &s);
        assert_eq!((error.status, error.code), (413, "command_too_large"));

        // A credential of another service.
        let error = a.submit(NOW, Some("other"), &good).unwrap_err();
        assert_eq!(error.code, "invalid_evaluation");
        assert!(a.requests().is_empty());
        assert!(a.submit(NOW, Some("datastore"), &good).is_ok());
    }

    #[test]
    fn p_17_1_an_evaluation_id_is_late_after_its_time() {
        let mut a = Approvals::default();
        let s = submission(&mut a, op(), lease(60));
        let late = NOW + EVALUATION_TTL_SECONDS + 1;
        assert_eq!(
            a.submit(late, None, &s).unwrap_err().code,
            "invalid_evaluation"
        );
        assert!(a.submit(late - 1, None, &s).is_ok());
    }

    #[test]
    fn p_17_6_the_approval_can_be_used_once_up_to_consume_before() {
        let mut a = Approvals::default();
        let submitted = submit(&mut a, NOW);
        approve(&mut a, &submitted.request_id, NOW + 10);
        let n = node();
        let effect = effect_of(&op());
        let k = key("key:k1", &n, &effect);
        let Gate::Usable(index) = a.gate(NOW + 11, k, true) else {
            panic!("not usable");
        };
        a.consume(index);
        assert_eq!(a.gate(NOW + 11, k, true), Gate::Required);
        assert_eq!(a.gate(NOW + 11, k, false), Gate::Required);
        // The approval that nobody consumed is void after consume_before.
        let again = submit(&mut a, NOW + 20);
        approve(&mut a, &again.request_id, NOW + 20);
        let end = NOW + 20 + CONSUME_SECONDS;
        assert!(matches!(a.gate(end, k, true), Gate::Usable(_)));
        assert_eq!(a.gate(end + 1, k, true), Gate::Expired);
        assert_eq!(a.gate(end + 1, k, false), Gate::Required);
    }

    #[test]
    fn p_17_6_a_decline_gives_a_deny_time_and_no_text_without_allow_custom() {
        let mut a = Approvals::default();
        let submitted = submit(&mut a, NOW);
        let with_text = OwnerAnswer {
            decision: OwnerDecision::Decline,
            shown_effect: effect_of(&op()),
            comment: comment_of("use staging", "change_request"),
            answered_by: None,
            device: None,
        };
        assert_eq!(
            a.answer(NOW, &submitted.request_id, &with_text)
                .unwrap_err()
                .code,
            "text_not_allowed"
        );
        let plain = OwnerAnswer {
            comment: None,
            ..with_text
        };
        a.answer(NOW, &submitted.request_id, &plain).unwrap();
        let n = node();
        let effect = effect_of(&op());
        let k = key("key:k1", &n, &effect);
        assert_eq!(a.gate(NOW + DENY_SECONDS - 1, k, true), Gate::Denied);
        assert_eq!(a.gate(NOW + DENY_SECONDS, k, true), Gate::Required);
        assert_eq!(
            a.verdict(
                NOW,
                Some("datastore"),
                "key:k1",
                &submitted.request_id,
                false
            ),
            Ok(Verdict::Denied)
        );
    }

    #[test]
    fn p_17_11_the_answer_needs_the_shown_effect_and_only_the_first_counts() {
        let mut a = Approvals::default();
        let submitted = submit(&mut a, NOW);
        let wrong = OwnerAnswer {
            decision: OwnerDecision::Approve,
            shown_effect: effect_of(&json!({"other": 1})),
            comment: None,
            answered_by: None,
            device: None,
        };
        assert_eq!(
            a.answer(NOW, &submitted.request_id, &wrong)
                .unwrap_err()
                .code,
            "shown_effect_mismatch"
        );
        approve(&mut a, &submitted.request_id, NOW);
        let decline = OwnerAnswer {
            decision: OwnerDecision::Decline,
            shown_effect: effect_of(&op()),
            ..wrong
        };
        assert_eq!(
            a.answer(NOW, &submitted.request_id, &decline)
                .unwrap_err()
                .status,
            409
        );
        assert_eq!(a.answer(NOW, "apr_none", &decline).unwrap_err().status, 404);
    }

    #[test]
    fn p_17_5_a_lease_ends_after_three_times_lease_s_and_the_grace_time() {
        let mut a = Approvals::default();
        let submitted = submit(&mut a, NOW);
        let id = submitted.request_id;
        let end = NOW + 3 * 60 + GRACE_SECONDS;
        let read =
            |a: &mut Approvals, now, renew| a.verdict(now, Some("datastore"), "key:k1", &id, renew);
        assert_eq!(read(&mut a, end, false), Ok(Verdict::Pending));
        // A renewal moves the end.
        assert_eq!(read(&mut a, end, true), Ok(Verdict::Pending));
        assert_eq!(read(&mut a, end + 1, false), Ok(Verdict::Pending));
        assert_eq!(read(&mut a, end + end - NOW + 1, false), Ok(Verdict::Void));
        assert_eq!(a.requests()[0].status, ApprovalStatus::Abandoned);
    }

    #[test]
    fn p_17_5_a_renewal_revives_an_abandoned_request_a_limited_number_of_times() {
        let mut a = Approvals::default();
        let id = submit(&mut a, NOW).request_id;
        let mut now = NOW;
        for revival in 1..=MAX_REVIVALS {
            now += 3 * 60 + GRACE_SECONDS + 10;
            assert_eq!(
                a.verdict(now, Some("datastore"), "key:k1", &id, false),
                Ok(Verdict::Void)
            );
            assert_eq!(
                a.verdict(now, Some("datastore"), "key:k1", &id, true),
                Ok(Verdict::Pending),
                "revival {revival}"
            );
        }
        now += 3 * 60 + GRACE_SECONDS + 10;
        assert_eq!(
            a.verdict(now, Some("datastore"), "key:k1", &id, true),
            Ok(Verdict::Void)
        );
        assert_eq!(a.requests()[0].revivals, MAX_REVIVALS);
    }

    #[test]
    fn p_17_5_the_revival_time_ends() {
        let mut a = Approvals::default();
        let id = submit(&mut a, NOW).request_id;
        let late = NOW + 3 * 60 + GRACE_SECONDS + 1 + REVIVE_SECONDS + 1;
        assert_eq!(
            a.verdict(late, Some("datastore"), "key:k1", &id, true),
            Ok(Verdict::Void)
        );
        assert_eq!(a.requests()[0].revivals, 0);
    }

    #[test]
    fn p_17_5_a_request_with_until_expires_at_that_time() {
        let mut a = Approvals::default();
        let s = submission(
            &mut a,
            op(),
            LeaseGiven {
                until: Some(NOW + 100),
                ..LeaseGiven::default()
            },
        );
        let id = a.submit(NOW, None, &s).unwrap().request_id;
        assert_eq!(
            a.verdict(NOW + 99, None, "key:k1", &id, true),
            Ok(Verdict::Pending)
        );
        assert_eq!(
            a.verdict(NOW + 100, None, "key:k1", &id, true),
            Ok(Verdict::Void)
        );
        assert_eq!(a.requests()[0].status, ApprovalStatus::Expired);
        let past = LeaseGiven {
            until: Some(NOW),
            ..LeaseGiven::default()
        };
        let s = submission(&mut a, json!({"n": 1}), past);
        assert_eq!(a.submit(NOW, None, &s).unwrap_err().code, "invalid_lease");
    }

    #[test]
    fn p_17_5_a_request_expires_after_the_longest_life() {
        let mut a = Approvals::default();
        let id = submit(&mut a, NOW).request_id;
        let mut now = NOW;
        // Renew each day: the lease never ends, the life does.
        while now + 86_400 < NOW + MAX_LIFE_SECONDS {
            now += 86_400;
            a.requests[0].renewed = now;
        }
        assert_eq!(
            a.verdict(now, None, "key:k1", &id, false),
            Ok(Verdict::Pending)
        );
        assert_eq!(
            a.verdict(NOW + MAX_LIFE_SECONDS, None, "key:k1", &id, false),
            Ok(Verdict::Void)
        );
        assert_eq!(a.requests()[0].status, ApprovalStatus::Expired);
    }

    #[test]
    fn p_17_4_a_request_of_another_subject_or_service_is_not_found() {
        let mut a = Approvals::default();
        let id = submit(&mut a, NOW).request_id;
        for (service, subject, id) in [
            (Some("datastore"), "key:k2", id.as_str()),
            (Some("other"), "key:k1", id.as_str()),
            (Some("datastore"), "key:k1", "apr_unknown"),
        ] {
            let error = a.verdict(NOW, service, subject, id, true).unwrap_err();
            assert_eq!((error.status, error.code), (404, "not_found"));
        }
        // The other subject did not renew the lease.
        assert_eq!(a.requests()[0].renewed, NOW);
    }

    #[test]
    fn p_17_4_a_new_request_can_supersede_an_old_one_that_is_not_consumed() {
        let mut a = Approvals::default();
        let first = submit(&mut a, NOW).request_id;
        let other_op = json!({"tool": "run_write_query", "sql": "DELETE 2"});
        let mut s = submission(&mut a, other_op, lease(60));
        s.supersedes = Some(first.clone());
        let second = a.submit(NOW, None, &s).unwrap();
        assert!(second.created);
        assert_eq!(a.requests()[0].status, ApprovalStatus::Superseded);
        assert_eq!(
            a.verdict(NOW, None, "key:k1", &first, false),
            Ok(Verdict::Void)
        );
        // A request that is consumed cannot be superseded.
        let used = submit(&mut a, NOW + 1).request_id;
        approve(&mut a, &used, NOW + 1);
        let n = node();
        let effect = effect_of(&op());
        let Gate::Usable(index) = a.gate(NOW + 2, key("key:k1", &n, &effect), true) else {
            panic!("not usable");
        };
        a.consume(index);
        let mut s = submission(&mut a, json!({"n": 3}), lease(60));
        s.supersedes = Some(used);
        assert_eq!(
            a.submit(NOW + 3, None, &s).unwrap_err().code,
            "cannot_supersede"
        );
        let mut s = submission(&mut a, json!({"n": 4}), lease(60));
        s.supersedes = Some("apr_none".into());
        assert_eq!(
            a.submit(NOW + 3, None, &s).unwrap_err().code,
            "invalid_argument"
        );
    }

    #[test]
    fn p_17_4_an_approval_ref_gives_the_lease_and_is_used_once() {
        let mut a = Approvals::default();
        a.add_reference(NOW, "ref_1", "key:k1", Lease::Seconds(120), true);
        let mut s = submission(
            &mut a,
            op(),
            LeaseGiven {
                approval_ref: Some("ref_1".into()),
                ..LeaseGiven::default()
            },
        );
        let id = a.submit(NOW, None, &s).unwrap().request_id;
        assert_eq!(a.requests()[0].lease, Lease::Seconds(120));
        assert!(a.requests()[0].allow_custom);
        // A second use of the reference, for a new effect.
        s = submission(
            &mut a,
            json!({"n": 1}),
            LeaseGiven {
                approval_ref: Some("ref_1".into()),
                ..LeaseGiven::default()
            },
        );
        assert_eq!(
            a.submit(NOW, None, &s).unwrap_err().code,
            "invalid_argument"
        );
        // A reference of another subject, and an unknown reference.
        a.add_reference(NOW, "ref_2", "key:k2", Lease::Seconds(120), false);
        for name in ["ref_2", "ref_none"] {
            let mut s = s.clone();
            s.lease.approval_ref = Some(name.into());
            assert_eq!(
                a.submit(NOW, None, &s).unwrap_err().code,
                "invalid_argument"
            );
        }
        // The text of a refusal is allowed with this reference.
        let answer = OwnerAnswer {
            decision: OwnerDecision::Decline,
            shown_effect: effect_of(&op()),
            comment: comment_of("no", "comment"),
            answered_by: Some("eliot".into()),
            device: Some("d:1".into()),
        };
        a.answer(NOW, &id, &answer).unwrap();
        assert_eq!(a.requests()[0].comment.as_ref().unwrap().text, "no");
    }

    #[test]
    fn p_17_4_a_subject_that_has_many_open_requests_gets_rate_limited() {
        let mut a = Approvals::default();
        for n in 0..MAX_OPEN_PER_SUBJECT {
            let s = submission(&mut a, json!({"n": n}), lease(60));
            a.submit(NOW, None, &s).unwrap();
        }
        let s = submission(&mut a, json!({"n": "last"}), lease(60));
        let error = a.submit(NOW, None, &s).unwrap_err();
        assert_eq!((error.status, error.code), (429, "rate_limited"));
        assert_eq!(error.retry_after, Some(RATE_LIMIT_RETRY_SECONDS));
        assert_eq!(
            error.to_value(),
            json!({"error": "rate_limited", "retry_after": 60})
        );
    }

    #[test]
    fn p_17_6_cancel_and_reply_change_the_status() {
        let mut a = Approvals::default();
        let id = submit(&mut a, NOW).request_id;
        a.reply(NOW, &id).unwrap();
        assert_eq!(a.requests()[0].status, ApprovalStatus::Replied);
        assert_eq!(a.reply(NOW, &id).unwrap_err().status, 409);
        let n = node();
        let effect = effect_of(&op());
        assert_eq!(
            a.gate(NOW, key("key:k1", &n, &effect), false),
            Gate::Pending
        );
        a.cancel(NOW, &id).unwrap();
        assert_eq!(a.cancel(NOW, &id).unwrap_err().status, 409);
        assert_eq!(
            a.verdict(NOW, None, "key:k1", &id, false),
            Ok(Verdict::Void)
        );
        assert_eq!(a.gate(NOW, key("key:k1", &n, &effect), true), Gate::Expired);
    }

    #[test]
    fn the_data_file_gives_the_first_requests_and_a_reset_puts_them_back() {
        let seed = SeedApproval {
            id: "apr_seed".into(),
            subject: "key:k1".into(),
            action: "data.write".into(),
            resource: node(),
            effect: effect_of(&op()),
            status: ApprovalStatus::Answered,
            decision: Some(OwnerDecision::Approve),
            consume_before: Some(NOW + 10),
            consumed: false,
            deny_until: None,
            answered_by: None,
            device: None,
            answered_at: None,
            comment: None,
        };
        let mut a = Approvals::from_seed(&[seed]);
        let n = node();
        let effect = effect_of(&op());
        let k = key("key:k1", &n, &effect);
        let Gate::Usable(index) = a.gate(NOW, k, true) else {
            panic!("not usable");
        };
        a.consume(index);
        assert_eq!(a.gate(NOW, k, true), Gate::Required);
        a.reset();
        assert!(matches!(a.gate(NOW, k, true), Gate::Usable(_)));
    }

    #[test]
    fn rfc_3339_times_are_read() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-10-16T12:00:48Z"), Some(1_792_152_048));
        assert_eq!(
            parse_rfc3339("2026-10-16T12:00:48.987Z"),
            Some(1_792_152_048)
        );
        assert_eq!(
            parse_rfc3339("2026-10-16T14:00:48+02:00"),
            Some(1_792_152_048)
        );
        assert_eq!(
            parse_rfc3339("2026-10-16T10:30:48-01:30"),
            Some(1_792_152_048)
        );
        assert_eq!(parse_rfc3339("2026-10-16t12:00:48z"), Some(1_792_152_048));
        for bad in [
            "",
            "2026-10-16",
            "2026-10-16T12:00:48",
            "2026-13-16T12:00:48Z",
            "2026-02-30T12:00:48Z",
            "2026-10-16T25:00:48Z",
            "2026-10-16 12:00:48Z",
            "2026-10-16T12:00:48+0200",
            "1969-12-31T23:59:59Z",
            "2026-10-16T12:00:48.Z",
        ] {
            assert_eq!(parse_rfc3339(bad), None, "{bad}");
        }
    }
}
