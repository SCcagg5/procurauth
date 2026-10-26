//! Failures that the PDP makes on purpose, to test a PEP (6.9, 10.3, 10.6, 6.12).
//!
//! The data file can hold the kinds `error_503`, `delay` and `no_answer`.
//! A second file, or the admin endpoint, can also hold the kinds `close`,
//! `invalid_json` and `no_units`. A rule applies to a question when each
//! member of its `when` is equal to the question. The first rule that
//! applies, and that has uses left, makes the failure.

use procurauth_core::directory::{Endpoint, FailureKind, FailureMatch, FailureRule};
use procurauth_core::finding::{Finding, JsonPath, Report, show};
use procurauth_core::json::parse_str;
use procurauth_core::names::is_action_name;
use procurauth_core::path::NodePath;
use procurauth_core::read::{Obj, Unknown};
use serde_json::Value;

/// What a failure does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// Answer HTTP 503 with no decision. The PDP counts nothing (6.9).
    Error503,
    /// Wait this many milliseconds, then answer as usual.
    Delay(u64),
    /// Decide and count, then never answer (10.6).
    NoAnswer,
    /// Decide and count, then close the connection with no bytes (10.6).
    Close,
    /// Decide and count, then answer HTTP 200 with a body that is not valid JSON (10.3).
    InvalidJson,
    /// Answer as usual, but remove `context.usage.units` from a `true` answer (6.12).
    NoUnits,
}

impl FaultKind {
    /// The word of the data format.
    pub fn name(self) -> &'static str {
        match self {
            Self::Error503 => "error_503",
            Self::Delay(_) => "delay",
            Self::NoAnswer => "no_answer",
            Self::Close => "close",
            Self::InvalidJson => "invalid_json",
            Self::NoUnits => "no_units",
        }
    }
}

/// One failure rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    /// What to do.
    pub kind: FaultKind,
    /// When to do it.
    pub when: FailureMatch,
    /// How many times the rule applies. Without it, the rule applies each time.
    pub times: Option<u64>,
}

impl Fault {
    /// The rule that the data file gave.
    pub fn from_core(rule: &FailureRule) -> Self {
        let kind = match rule.kind {
            FailureKind::Error503 => FaultKind::Error503,
            FailureKind::Delay(ms) => FaultKind::Delay(ms),
            FailureKind::NoAnswer => FaultKind::NoAnswer,
        };
        Self {
            kind,
            when: rule.when.clone(),
            times: rule.times,
        }
    }
}

/// What a rule can match in one question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Facts {
    /// The endpoint of the request.
    pub endpoint: Endpoint,
    /// The subject id. The metadata request has none.
    pub subject: Option<String>,
    /// The action name.
    pub action: Option<String>,
    /// The node of the resource, when the chain is good.
    pub resource: Option<NodePath>,
    /// True when the question has `context.usage`.
    pub usage: bool,
}

impl Facts {
    /// The facts of a request that holds no question.
    pub fn for_endpoint(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            subject: None,
            action: None,
            resource: None,
            usage: false,
        }
    }

    fn matches(&self, when: &FailureMatch) -> bool {
        when.endpoint.is_none_or(|e| e == self.endpoint)
            && when
                .subject
                .as_ref()
                .is_none_or(|s| self.subject.as_ref() == Some(s))
            && when
                .action
                .as_ref()
                .is_none_or(|a| self.action.as_ref() == Some(a))
            && when
                .resource
                .as_ref()
                .is_none_or(|r| self.resource.as_ref() == Some(r))
            && when.usage.is_none_or(|u| u == self.usage)
    }
}

/// The rules, with the uses that each one has left.
#[derive(Clone, Debug, Default)]
pub struct FaultSet {
    rules: Vec<(Fault, Option<u64>)>,
}

impl FaultSet {
    /// A set of rules, each with all its uses.
    pub fn new(faults: Vec<Fault>) -> Self {
        Self {
            rules: faults
                .into_iter()
                .map(|fault| {
                    let left = fault.times;
                    (fault, left)
                })
                .collect(),
        }
    }

    /// Replace all the rules.
    pub fn replace(&mut self, faults: Vec<Fault>) {
        *self = Self::new(faults);
    }

    /// The rules, with the uses that each one has left.
    pub fn rules(&self) -> impl Iterator<Item = (&Fault, Option<u64>)> {
        self.rules.iter().map(|(fault, left)| (fault, *left))
    }

    /// Find the first rule that applies to a request, and use it one time.
    /// A request with several questions matches when one question matches.
    pub fn take(&mut self, facts: &[Facts]) -> Option<FaultKind> {
        for (fault, left) in &mut self.rules {
            if *left == Some(0) {
                continue;
            }
            if facts.iter().any(|f| f.matches(&fault.when)) {
                if let Some(count) = left {
                    *count -= 1;
                }
                return Some(fault.kind);
            }
        }
        None
    }
}

/// Read a list of failures from the text of a failure file or of an admin request.
/// The text is an object with the member `failures`. The reader is strict.
///
/// # Errors
/// Returns every finding, each with its JSON path.
pub fn read_faults_str(text: &str) -> Result<Vec<Fault>, Vec<Finding>> {
    match parse_str(text) {
        Ok(value) => read_faults(&value),
        Err(error) => {
            let mut report = Report::new();
            report.error(
                &error.path,
                "6.9",
                "bad_json",
                format!("The text is not valid JSON: {error}."),
            );
            Err(report.into_findings())
        }
    }
}

/// Read a list of failures from a JSON value.
///
/// # Errors
/// Returns every finding, each with its JSON path.
pub fn read_faults(value: &Value) -> Result<Vec<Fault>, Vec<Finding>> {
    let mut report = Report::new();
    let root = JsonPath::root();
    let mut out = Vec::new();
    if let Some(mut obj) = Obj::new(value, &root, "6.9", Unknown::Error, &mut report) {
        let items = obj.array("failures", &mut report);
        obj.finish(&mut report);
        for (index, item) in items.unwrap_or_default().iter().enumerate() {
            out.extend(read_fault(
                item,
                &root.key("failures").index(index),
                &mut report,
            ));
        }
    }
    if report.has_errors() {
        Err(report.into_findings())
    } else {
        Ok(out)
    }
}

fn read_fault(value: &Value, path: &JsonPath, report: &mut Report) -> Option<Fault> {
    let mut obj = Obj::new(value, path, "6.9", Unknown::Error, report)?;
    let kind = obj.string("kind", report);
    let delay = obj.whole_opt("delay_ms", report);
    let times = obj.whole_opt("times", report);
    let when = obj.object_opt("when", "6.9", Unknown::Error, report);
    obj.finish(report);
    let kind = match (kind, delay) {
        (Some("delay"), Some(ms)) if ms >= 1 => Some(FaultKind::Delay(ms)),
        (Some("delay"), _) => {
            report.error(
                path,
                "6.9",
                "bad_delay",
                "A failure of the kind `delay` needs the member `delay_ms`, a whole number from 1.",
            );
            None
        }
        (
            Some(other @ ("error_503" | "no_answer" | "close" | "invalid_json" | "no_units")),
            None,
        ) => Some(match other {
            "error_503" => FaultKind::Error503,
            "no_answer" => FaultKind::NoAnswer,
            "close" => FaultKind::Close,
            "invalid_json" => FaultKind::InvalidJson,
            _ => FaultKind::NoUnits,
        }),
        (Some("error_503" | "no_answer" | "close" | "invalid_json" | "no_units"), Some(_)) => {
            report.error(
                &path.key("delay_ms"),
                "6.9",
                "bad_delay",
                "Only a failure of the kind `delay` has the member `delay_ms`.",
            );
            None
        }
        (Some(other), _) => {
            report.error(
                &path.key("kind"),
                "6.9",
                "bad_kind",
                format!(
                    "Member `kind`: expected `error_503`, `delay`, `no_answer`, `close`, `invalid_json` or `no_units`, found {}.",
                    show(&Value::String(other.to_owned()))
                ),
            );
            None
        }
        (None, _) => None,
    };
    if times == Some(0) {
        report.error(
            &path.key("times"),
            "6.9",
            "bad_value",
            "Member `times`: expected a whole number from 1, found 0.",
        );
    }
    let when = when.map_or_else(FailureMatch::default, |w| read_when(w, report));
    Some(Fault {
        kind: kind?,
        when,
        times,
    })
}

fn read_when(mut obj: Obj<'_>, report: &mut Report) -> FailureMatch {
    let subject = obj.string_opt("subject", report).map(str::to_owned);
    let action = obj.string_opt("action", report).map(str::to_owned);
    let resource = obj.string_opt("resource", report);
    let usage = obj.boolean_opt("usage", report);
    let endpoint = obj.string_opt("endpoint", report);
    obj.finish(report);
    if let Some(action) = &action
        && !is_action_name(action)
    {
        report.error(
            &obj.member_path("action"),
            "5.2",
            "bad_action_name",
            format!(
                "Member `action` {} is not an action name.",
                show(&Value::String(action.clone()))
            ),
        );
    }
    let resource = resource.and_then(|text| match NodePath::parse(text) {
        Ok(path) => Some(path),
        Err(error) => {
            report.error(
                &obj.member_path("resource"),
                "4.1",
                "bad_path",
                format!(
                    "Resource {}: {error}.",
                    show(&Value::String(text.to_owned()))
                ),
            );
            None
        }
    });
    let endpoint = endpoint.and_then(|text| match text {
        "evaluation" => Some(Endpoint::Evaluation),
        "evaluations" => Some(Endpoint::Evaluations),
        "metadata" => Some(Endpoint::Metadata),
        other => {
            report.error(
                &obj.member_path("endpoint"),
                "6.9",
                "bad_endpoint",
                format!(
                    "Member `endpoint`: expected `evaluation`, `evaluations` or `metadata`, found {}.",
                    show(&Value::String(other.to_owned()))
                ),
            );
            None
        }
    });
    FailureMatch {
        subject,
        action,
        resource,
        usage,
        endpoint,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn facts(subject: &str, usage: bool) -> Facts {
        Facts {
            endpoint: Endpoint::Evaluation,
            subject: Some(subject.to_owned()),
            action: Some("data.read".to_owned()),
            resource: NodePath::parse("service:datastore").ok(),
            usage,
        }
    }

    #[test]
    fn p_6_9_a_rule_with_times_applies_that_many_times() {
        let mut set = FaultSet::new(vec![Fault {
            kind: FaultKind::Error503,
            when: FailureMatch::default(),
            times: Some(2),
        }]);
        let f = [facts("alice", true)];
        assert_eq!(set.take(&f), Some(FaultKind::Error503));
        assert_eq!(set.take(&f), Some(FaultKind::Error503));
        assert_eq!(set.take(&f), None);
    }

    #[test]
    fn p_6_9_a_rule_without_times_applies_each_time() {
        let mut set = FaultSet::new(vec![Fault {
            kind: FaultKind::Close,
            when: FailureMatch::default(),
            times: None,
        }]);
        for _ in 0..5 {
            assert_eq!(set.take(&[facts("a", false)]), Some(FaultKind::Close));
        }
    }

    #[test]
    fn p_6_9_a_rule_applies_only_when_each_member_of_when_is_equal() {
        let when = FailureMatch {
            subject: Some("alice".to_owned()),
            usage: Some(true),
            ..FailureMatch::default()
        };
        let mut set = FaultSet::new(vec![Fault {
            kind: FaultKind::NoAnswer,
            when,
            times: None,
        }]);
        assert_eq!(set.take(&[facts("bob", true)]), None);
        assert_eq!(set.take(&[facts("alice", false)]), None);
        assert_eq!(set.take(&[facts("alice", true)]), Some(FaultKind::NoAnswer));
        assert_eq!(set.take(&[Facts::for_endpoint(Endpoint::Metadata)]), None);
    }

    #[test]
    fn p_6_9_the_first_rule_that_applies_wins() {
        let mut set = FaultSet::new(vec![
            Fault {
                kind: FaultKind::Delay(5),
                when: FailureMatch::default(),
                times: Some(1),
            },
            Fault {
                kind: FaultKind::Error503,
                when: FailureMatch::default(),
                times: None,
            },
        ]);
        let f = [facts("a", false)];
        assert_eq!(set.take(&f), Some(FaultKind::Delay(5)));
        assert_eq!(set.take(&f), Some(FaultKind::Error503));
    }

    #[test]
    fn a_request_with_several_questions_matches_when_one_question_matches() {
        let when = FailureMatch {
            subject: Some("bob".to_owned()),
            ..FailureMatch::default()
        };
        let mut set = FaultSet::new(vec![Fault {
            kind: FaultKind::Close,
            when,
            times: None,
        }]);
        assert_eq!(
            set.take(&[facts("alice", false), facts("bob", false)]),
            Some(FaultKind::Close)
        );
    }

    #[test]
    fn the_reader_accepts_every_kind() {
        let value = json!({"failures": [
            {"kind": "error_503"},
            {"kind": "delay", "delay_ms": 20, "times": 1, "when": {"usage": true, "endpoint": "evaluation"}},
            {"kind": "no_answer", "when": {"subject": "key:abc", "action": "data.read", "resource": "service:datastore/host:prod"}},
            {"kind": "close"},
            {"kind": "invalid_json"},
            {"kind": "no_units"}
        ]});
        let faults = read_faults(&value).unwrap();
        assert_eq!(faults.len(), 6);
        assert_eq!(faults[1].kind, FaultKind::Delay(20));
        assert_eq!(faults[5].kind, FaultKind::NoUnits);
    }

    #[test]
    fn the_reader_is_closed_and_names_each_path() {
        let value = json!({"failures": [
            {"kind": "delay"},
            {"kind": "explode"},
            {"kind": "close", "delay_ms": 5},
            {"kind": "close", "times": 0, "extra": 1},
            {"kind": "close", "when": {"endpoint": "x", "action": "A", "resource": "nope", "color": 1}}
        ], "more": 1});
        let findings = read_faults(&value).unwrap_err();
        let paths: Vec<_> = findings
            .iter()
            .map(|f| f.path.as_str().to_owned())
            .collect();
        for expected in [
            "$.failures[0]",
            "$.failures[1].kind",
            "$.failures[2].delay_ms",
            "$.failures[3].times",
            "$.failures[3].extra",
            "$.failures[4].when.endpoint",
            "$.failures[4].when.action",
            "$.failures[4].when.resource",
            "$.failures[4].when.color",
            "$.more",
        ] {
            assert!(
                paths.iter().any(|p| p == expected),
                "{expected} in {paths:?}"
            );
        }
    }

    #[test]
    fn the_reader_refuses_a_duplicate_member() {
        let findings = read_faults_str(r#"{"failures": [], "failures": []}"#).unwrap_err();
        assert_eq!(findings[0].code, "bad_json");
    }
}
