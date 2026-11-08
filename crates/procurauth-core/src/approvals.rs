//! The approvals that the data of the test PDP holds at the start (protocol 17.6).
//!
//! The member `approvals` of the data file lists approvals. For one subject, action,
//! resource and effect, the last entry is the latest approval. The test PDP answers a
//! question with an effect from this list (17.1). The members `answered_by`, `device`,
//! `answered_at` and `comment` are data that a PDP never gives to a PEP (17.12).

use serde_json::{Value, json};

use crate::effect::is_effect;
use crate::finding::{JsonPath, Report, show};
use crate::names::is_action_name;
use crate::path::NodePath;
use crate::read::{Obj, Unknown};

/// The status of a request (17.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalStatus {
    /// The owner has not answered.
    Pending,
    /// `pending`, with a question of the owner to the agent.
    Replied,
    /// The owner answered `approve` or `decline`.
    Answered,
    /// The lease ended.
    Abandoned,
    /// The time of the request ended.
    Expired,
    /// The agent, an administrator or the revocation of the key cancelled the request.
    Cancelled,
    /// A newer request replaced this one.
    Superseded,
}

impl ApprovalStatus {
    /// The word of the data format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Replied => "replied",
            Self::Answered => "answered",
            Self::Abandoned => "abandoned",
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::Superseded => "superseded",
        }
    }

    /// Read the word of the data format.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pending" => Self::Pending,
            "replied" => Self::Replied,
            "answered" => Self::Answered,
            "abandoned" => Self::Abandoned,
            "expired" => Self::Expired,
            "cancelled" => Self::Cancelled,
            "superseded" => Self::Superseded,
            _ => return None,
        })
    }
}

/// The answer of the owner (17.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OwnerDecision {
    /// The owner approves the effect.
    Approve,
    /// The owner declines it.
    Decline,
}

impl OwnerDecision {
    /// The word of the data format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approve => "approve",
            Self::Decline => "decline",
        }
    }
}

/// The intent of a text with a refusal (17.11).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CommentIntent {
    /// A remark.
    Comment,
    /// A request for another command. For the PEP it is a refusal.
    ChangeRequest,
}

impl CommentIntent {
    /// The word of the data format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Comment => "comment",
            Self::ChangeRequest => "change_request",
        }
    }

    /// Read the word of the data format.
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "comment" => Some(Self::Comment),
            "change_request" => Some(Self::ChangeRequest),
            _ => None,
        }
    }
}

/// The text of a refusal. It goes only to the agent (17.11).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Comment {
    /// The text.
    pub text: String,
    /// The intent.
    pub intent: CommentIntent,
}

/// One approval of the data file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeedApproval {
    /// The id of the request.
    pub id: String,
    /// The subject of the request.
    pub subject: String,
    /// The action.
    pub action: String,
    /// The node of the resource.
    pub resource: NodePath,
    /// The effect (17.3).
    pub effect: String,
    /// The status (17.6).
    pub status: ApprovalStatus,
    /// The answer of the owner. Only for the status `answered`.
    pub decision: Option<OwnerDecision>,
    /// The last second at which the approval can be used. Only for `approve`.
    pub consume_before: Option<u64>,
    /// True when the approval is consumed. Only for `approve`.
    pub consumed: bool,
    /// The end of the deny time. Only for `decline`. Without it, the deny time has ended.
    pub deny_until: Option<u64>,
    /// The owner who answered.
    pub answered_by: Option<String>,
    /// The device of the answer.
    pub device: Option<String>,
    /// The time of the answer, in seconds.
    pub answered_at: Option<u64>,
    /// The text of a refusal.
    pub comment: Option<Comment>,
}

/// Read the list `approvals` (17.6). The reader follows the schema `fake-pdp-data`.
pub fn read_approvals(items: &[Value], base: &JsonPath, report: &mut Report) -> Vec<SeedApproval> {
    let mut out: Vec<SeedApproval> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        if let Some(approval) = read_one(item, &path, report) {
            if out.iter().any(|a| a.id == approval.id) {
                report.error(
                    &path.key("id"),
                    "17.6",
                    "duplicate_approval",
                    format!("The request `{}` occurs more than one time.", approval.id),
                );
            }
            out.push(approval);
        }
    }
    out
}

fn read_one(value: &Value, path: &JsonPath, report: &mut Report) -> Option<SeedApproval> {
    let start = report.error_count();
    let mut obj = Obj::new(value, path, "17.6", Unknown::Error, report)?;
    let id = obj.string("id", report);
    let subject = obj.string("subject", report);
    let action = obj.string("action", report);
    let resource = obj.string("resource", report);
    let effect = obj.string("effect", report);
    let status = obj.string("status", report);
    let decision = obj.string_opt("decision", report);
    let consume_before = obj.whole_opt("consume_before", report);
    let consumed = obj.boolean_opt("consumed", report);
    let deny_until = obj.whole_opt("deny_until", report);
    let answered_by = obj.string_opt("answered_by", report);
    let device = obj.string_opt("device", report);
    let answered_at = obj.whole_opt("answered_at", report);
    let comment_value = obj.optional("comment");
    obj.finish(report);

    for (key, text) in [("id", id), ("subject", subject)] {
        if text.is_some_and(str::is_empty) {
            report.error(
                &path.key(key),
                "17.6",
                "empty_text",
                format!("Member `{key}`: expected a text that is not empty."),
            );
        }
    }
    if let Some(action) = action
        && !is_action_name(action)
    {
        report.error(
            &path.key("action"),
            "5.2",
            "bad_action_name",
            format!("Action name {}: expected 1 to 64 characters, parts of a to z, 0 to 9 and underscore, with `.` between the parts.", show(&json!(action))),
        );
    }
    let node = resource.and_then(|text| match NodePath::parse(text) {
        Ok(node) => Some(node),
        Err(error) => {
            report.error(
                &path.key("resource"),
                "4.1",
                "bad_path",
                format!("Resource {}: {error}.", show(&json!(text))),
            );
            None
        }
    });
    if let Some(effect) = effect
        && !is_effect(effect)
    {
        report.error(
            &path.key("effect"),
            "17.3",
            "bad_effect",
            format!(
                "Member `effect`: expected `sha256:` and 64 lower-case hexadecimal digits, found {}.",
                show(&json!(effect))
            ),
        );
    }
    let status = status.and_then(|text| {
        let parsed = ApprovalStatus::parse(text);
        if parsed.is_none() {
            report.error(
                &path.key("status"),
                "17.6",
                "bad_status",
                format!("Member `status`: expected `pending`, `replied`, `answered`, `abandoned`, `expired`, `cancelled` or `superseded`, found {}.", show(&json!(text))),
            );
        }
        parsed
    });
    let decision = decision.and_then(|text| match text {
        "approve" => Some(OwnerDecision::Approve),
        "decline" => Some(OwnerDecision::Decline),
        other => {
            report.error(
                &path.key("decision"),
                "17.11",
                "bad_decision",
                format!(
                    "Member `decision`: expected `approve` or `decline`, found {}.",
                    show(&json!(other))
                ),
            );
            None
        }
    });
    let comment = comment_value.and_then(|v| read_comment(v, &path.key("comment"), report));

    // The members that belong to a state (17.6).
    let answered = status == Some(ApprovalStatus::Answered);
    let mut only = |present: bool, member: &str, rule: &'static str, holds: bool, why: &str| {
        if present && !holds {
            report.error(
                &path.key(member),
                rule,
                "member_not_allowed",
                format!("Member `{member}` is only for {why}."),
            );
        }
    };
    let approve = decision == Some(OwnerDecision::Approve);
    let decline = decision == Some(OwnerDecision::Decline);
    for (member, present) in [
        ("decision", decision.is_some()),
        ("answered_by", answered_by.is_some()),
        ("device", device.is_some()),
        ("answered_at", answered_at.is_some()),
        ("comment", comment_value.is_some()),
    ] {
        only(
            present,
            member,
            "17.6",
            answered || status.is_none(),
            "the status `answered`",
        );
    }
    only(
        consume_before.is_some(),
        "consume_before",
        "17.6",
        approve,
        "the decision `approve`",
    );
    only(
        consumed.is_some(),
        "consumed",
        "17.6",
        approve,
        "the decision `approve`",
    );
    only(
        deny_until.is_some(),
        "deny_until",
        "17.6",
        decline,
        "the decision `decline`",
    );
    only(
        comment_value.is_some(),
        "comment",
        "17.11",
        decline,
        "the decision `decline`",
    );
    if answered && decision.is_none() && !report_has_decision_error(report, path) {
        report.error(
            path,
            "17.6",
            "missing_member",
            "Member `decision` is absent. A request with the status `answered` needs it.",
        );
    }
    if approve && consume_before.is_none() && status.is_some() {
        report.error(
            path,
            "17.6",
            "missing_member",
            "Member `consume_before` is absent. An approval needs it.",
        );
    }
    if report.error_count() != start {
        return None;
    }
    Some(SeedApproval {
        id: id?.to_owned(),
        subject: subject?.to_owned(),
        action: action?.to_owned(),
        resource: node?,
        effect: effect?.to_owned(),
        status: status?,
        decision,
        consume_before,
        consumed: consumed.unwrap_or(false),
        deny_until,
        answered_by: answered_by.map(str::to_owned),
        device: device.map(str::to_owned),
        answered_at,
        comment,
    })
}

/// True when a finding about `decision` is already in the report. This avoids a second finding.
fn report_has_decision_error(report: &Report, path: &JsonPath) -> bool {
    let wanted = path.key("decision");
    report.findings().iter().any(|f| f.path == wanted)
}

fn read_comment(value: &Value, path: &JsonPath, report: &mut Report) -> Option<Comment> {
    let mut obj = Obj::new(value, path, "17.11", Unknown::Error, report)?;
    let text = obj.string("text", report);
    let intent = obj.string("intent", report);
    obj.finish(report);
    let intent = intent.and_then(|word| {
        let parsed = CommentIntent::parse(word);
        if parsed.is_none() {
            report.error(
                &path.key("intent"),
                "17.11",
                "bad_intent",
                format!(
                    "Member `intent`: expected `comment` or `change_request`, found {}.",
                    show(&json!(word))
                ),
            );
        }
        parsed
    });
    Some(Comment {
        text: text?.to_owned(),
        intent: intent?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EFFECT: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

    fn base() -> Value {
        json!({
            "id": "apr_1", "subject": "key:abc", "action": "data.write",
            "resource": "service:datastore/host:prod", "effect": EFFECT, "status": "pending"
        })
    }

    fn read(items: &[Value]) -> (Vec<SeedApproval>, Report) {
        let mut report = Report::new();
        let list = read_approvals(items, &JsonPath::root().key("approvals"), &mut report);
        (list, report)
    }

    fn with(value: Value, changes: &[(&str, Value)]) -> Value {
        let mut value = value;
        for (key, new) in changes {
            if new.is_null() {
                value.as_object_mut().unwrap().remove(*key);
            } else {
                value[*key] = new.clone();
            }
        }
        value
    }

    #[test]
    fn p_17_6_a_pending_request_is_read() {
        let (list, report) = read(&[base()]);
        assert!(!report.has_errors(), "{report:?}");
        assert_eq!(list[0].status, ApprovalStatus::Pending);
        assert_eq!(list[0].decision, None);
        assert!(!list[0].consumed);
    }

    #[test]
    fn p_17_6_an_approval_has_a_decision_and_a_consume_time() {
        let a = with(
            base(),
            &[
                ("status", json!("answered")),
                ("decision", json!("approve")),
                ("consume_before", json!(1000)),
                ("consumed", json!(true)),
            ],
        );
        let (list, report) = read(&[a]);
        assert!(!report.has_errors(), "{report:?}");
        assert_eq!(list[0].decision, Some(OwnerDecision::Approve));
        assert_eq!(list[0].consume_before, Some(1000));
        assert!(list[0].consumed);
    }

    #[test]
    fn p_17_11_a_refusal_has_a_deny_time_and_a_comment() {
        let a = with(
            base(),
            &[
                ("status", json!("answered")),
                ("decision", json!("decline")),
                ("deny_until", json!(2000)),
                ("answered_by", json!("eliot")),
                ("comment", json!({"text": "no", "intent": "comment"})),
            ],
        );
        let (list, report) = read(&[a]);
        assert!(!report.has_errors(), "{report:?}");
        assert_eq!(list[0].deny_until, Some(2000));
        assert_eq!(list[0].comment.as_ref().unwrap().text, "no");
    }

    #[test]
    fn p_17_6_a_member_that_does_not_fit_the_state_is_an_error() {
        let bad = [
            with(base(), &[("decision", json!("approve"))]),
            with(base(), &[("consume_before", json!(5))]),
            with(
                base(),
                &[
                    ("status", json!("answered")),
                    ("decision", json!("decline")),
                    ("consume_before", json!(5)),
                ],
            ),
            with(
                base(),
                &[
                    ("status", json!("answered")),
                    ("decision", json!("approve")),
                    ("deny_until", json!(5)),
                    ("consume_before", json!(5)),
                ],
            ),
            with(base(), &[("status", json!("answered"))]),
            with(
                base(),
                &[
                    ("status", json!("answered")),
                    ("decision", json!("approve")),
                ],
            ),
        ];
        for (index, item) in bad.into_iter().enumerate() {
            let (_, report) = read(&[item]);
            assert!(report.has_errors(), "case {index}");
        }
    }

    #[test]
    fn p_17_6_a_bad_value_is_an_error_with_its_path() {
        for (key, value, code) in [
            ("status", json!("done"), "bad_status"),
            ("effect", json!("sha256:xyz"), "bad_effect"),
            ("action", json!("Data Write"), "bad_action_name"),
            ("resource", json!("host:prod"), "bad_path"),
        ] {
            let (_, report) = read(&[with(base(), &[(key, value)])]);
            let finding = &report.findings()[0];
            assert_eq!(finding.code, code, "{key}");
            assert_eq!(finding.path.as_str(), format!("$.approvals[0].{key}"));
        }
    }

    #[test]
    fn p_17_6_an_unknown_member_and_a_duplicate_id_are_errors() {
        let (_, report) = read(&[with(base(), &[("extra", json!(1))])]);
        assert!(report.has_errors());
        let (_, report) = read(&[base(), base()]);
        assert_eq!(report.findings()[0].code, "duplicate_approval");
    }
}
