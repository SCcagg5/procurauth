//! The data of the test PDP (the document `fake-pdp-data`).
//!
//! The data is the directory of protocol section 2: subjects, grants and
//! limit values. It also holds the action document of each service.
//! Some settings make a test repeatable: a fixed clock, the first values of
//! the counters, the metadata of the PDP and the failures to make.
//! The conformance cases of the series D and U use the same data.

use serde_json::{Value, json};

use crate::action_document::{ActionDocument, check_into};
use crate::finding::{Finding, JsonPath, Report, show};
use crate::grants::{Grant, ServiceLookup, read_grants};
use crate::json::parse_str;
use crate::limits::Window;
use crate::names::{is_action_name, is_type_or_limit_name, validate_id};
use crate::path::NodePath;
use crate::read::{Obj, Unknown};
use crate::subject::{SubjectKind, classify};

/// The state of a key (3.8, 11.1).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum KeyState {
    /// The key works.
    #[default]
    Active,
    /// The system revoked the key. The key is an unknown subject.
    Revoked,
    /// The key expired. The key is an unknown subject.
    Expired,
}

impl KeyState {
    /// The word of the data format.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
            Self::Expired => "expired",
        }
    }
}

/// One service that the PDP knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceEntry {
    /// The id of the service.
    pub id: String,
    /// The last good action document. Without it, the PDP has no good document (11.1).
    pub document: Option<ActionDocument>,
    /// The SHA-256 digest of the credential of the service, in lower-case hexadecimal (12).
    /// Without it, the test PDP accepts any credential.
    pub credential_sha256: Option<String>,
}

/// One subject: a person or a key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectEntry {
    /// The id of the subject.
    pub id: String,
    /// The owner of a key. The owner can be absent from the data: then the key is an unknown subject (11.1).
    pub owner: Option<String>,
    /// The state of a key. A person is always `active`.
    pub state: KeyState,
    /// The grants.
    pub grants: Vec<Grant>,
}

/// The first value of one counter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CounterPreset {
    /// The id of the subject.
    pub subject: String,
    /// The name of the budget.
    pub limit: String,
    /// The window.
    pub window: Window,
    /// The units that the subject spent in the window of the fixed clock.
    pub used: u64,
}

/// The endpoint of the PDP that a failure rule names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// The Access Evaluation API.
    Evaluation,
    /// The Access Evaluations API.
    Evaluations,
    /// The metadata.
    Metadata,
}

/// What a failure does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureKind {
    /// Answer HTTP 503.
    Error503,
    /// Wait this many milliseconds, then answer as usual.
    Delay(u64),
    /// Never answer.
    NoAnswer,
}

/// When a failure rule applies. A rule applies when every member that it gives is equal to the question.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FailureMatch {
    /// The subject id of the question.
    pub subject: Option<String>,
    /// The action name of the question.
    pub action: Option<String>,
    /// The node of the question.
    pub resource: Option<NodePath>,
    /// True when the question has `context.usage`.
    pub usage: Option<bool>,
    /// The endpoint.
    pub endpoint: Option<Endpoint>,
}

/// One failure to make.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FailureRule {
    /// What to do.
    pub kind: FailureKind,
    /// When to do it.
    pub when: FailureMatch,
    /// How many times the rule applies. Without it, the rule applies each time.
    pub times: Option<u64>,
}

/// The values of the metadata members of the PDP (6.9, 10.7, 10.7a, section 14).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MetadataValues {
    /// `procurauth_usage_max_seconds`.
    pub usage_max_seconds: Option<u64>,
    /// `procurauth_idle_max_seconds`.
    pub idle_max_seconds: Option<u64>,
    /// `procurauth_evaluations_max_bytes`.
    pub evaluations_max_bytes: Option<u64>,
    /// `procurauth_evaluations_max_items`.
    pub evaluations_max_items: Option<u64>,
}

/// The whole data of the test PDP.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Directory {
    /// The fixed clock, in seconds since the Unix epoch. Without it, the PDP uses the system clock.
    pub clock_now: Option<u64>,
    /// The metadata members that the PDP publishes.
    pub metadata: MetadataValues,
    /// The services.
    pub services: Vec<ServiceEntry>,
    /// The subjects.
    pub subjects: Vec<SubjectEntry>,
    /// The first values of counters.
    pub counters: Vec<CounterPreset>,
    /// The failures to make.
    pub failures: Vec<FailureRule>,
}

impl Directory {
    /// Read the data from JSON text. The reader is strict.
    ///
    /// # Errors
    /// Returns every finding when the data is bad.
    pub fn parse_str(text: &str) -> Result<Self, Vec<Finding>> {
        match parse_str(text) {
            Ok(value) => Self::from_value(&value),
            Err(error) => {
                let mut report = Report::new();
                report.error(
                    &error.path,
                    "directory",
                    "bad_json",
                    format!("The text is not valid JSON: {error}."),
                );
                Err(report.into_findings())
            }
        }
    }

    /// Read the data from a JSON value, and return every finding.
    /// The data is good when no finding is an error.
    ///
    /// # Errors
    /// Returns every finding when the data is bad.
    pub fn from_value(value: &Value) -> Result<Self, Vec<Finding>> {
        let analysis = analyze_value(value);
        match analysis.0 {
            Some(directory) => Ok(directory),
            None => Err(analysis.1.into_findings()),
        }
    }

    /// The service with this id.
    pub fn service(&self, id: &str) -> Option<&ServiceEntry> {
        self.services.iter().find(|s| s.id == id)
    }

    /// The subject with this id.
    pub fn subject(&self, id: &str) -> Option<&SubjectEntry> {
        self.subjects.iter().find(|s| s.id == id)
    }
}

/// Read the data and return the directory (when no error) and all findings.
pub fn analyze_value(value: &Value) -> (Option<Directory>, Report) {
    let mut report = Report::new();
    let directory = read_directory(value, &mut report);
    let directory = if report.has_errors() { None } else { directory };
    (directory, report)
}

fn read_directory(value: &Value, report: &mut Report) -> Option<Directory> {
    let root = JsonPath::root();
    let mut obj = Obj::new(value, &root, "directory", Unknown::Error, report)?;
    let mut out = Directory::default();

    if let Some(mut clock) = obj.object_opt("clock", "directory", Unknown::Error, report) {
        out.clock_now = clock.whole("now", report);
        clock.finish(report);
    }
    if let Some(mut meta) = obj.object_opt("metadata", "directory", Unknown::Error, report) {
        out.metadata = read_metadata(&mut meta, report);
        meta.finish(report);
    }
    let services = obj.array("services", report);
    let subjects = obj.array("subjects", report);
    let counters = obj.array_opt("counters", report);
    let failures = obj.array_opt("failures", report);
    obj.finish(report);

    out.services = read_services(services.unwrap_or_default(), &root.key("services"), report);
    out.subjects = read_subjects(
        subjects.unwrap_or_default(),
        &root.key("subjects"),
        &out.services,
        report,
    );
    out.counters = read_counters(
        counters.unwrap_or_default(),
        &root.key("counters"),
        &out.subjects,
        report,
    );
    out.failures = read_failures(failures.unwrap_or_default(), &root.key("failures"), report);
    Some(out)
}

fn read_metadata(obj: &mut Obj<'_>, report: &mut Report) -> MetadataValues {
    let mut positive = |key: &'static str| {
        let value = obj.whole_opt(key, report)?;
        if value == 0 {
            report.error(
                &obj.member_path(key),
                "directory",
                "bad_value",
                format!("Member `{key}`: expected a whole number from 1, found 0."),
            );
            return None;
        }
        Some(value)
    };
    MetadataValues {
        usage_max_seconds: positive("usage_max_seconds"),
        idle_max_seconds: positive("idle_max_seconds"),
        evaluations_max_bytes: positive("evaluations_max_bytes"),
        evaluations_max_items: positive("evaluations_max_items"),
    }
}

fn read_services(items: &[Value], base: &JsonPath, report: &mut Report) -> Vec<ServiceEntry> {
    let mut out: Vec<ServiceEntry> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "directory", Unknown::Error, report) else {
            continue;
        };
        let id = obj.string("id", report);
        let document_value = obj.optional("document");
        let credential = obj.string_opt("credential_sha256", report);
        obj.finish(report);
        if let Some(id) = id
            && let Err(error) = validate_id(id)
        {
            report.error(
                &path.key("id"),
                "5.2",
                "bad_service_id",
                format!("Member `id` {}: {error}.", show(&json!(id))),
            );
        }
        if let Some(id) = id
            && out.iter().any(|s| s.id == id)
        {
            report.error(
                &path.key("id"),
                "directory",
                "duplicate_service",
                format!("The service `{id}` occurs more than one time."),
            );
        }
        if let Some(digest) = credential
            && !(digest.len() == 64
                && digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        {
            report.error(
                &path.key("credential_sha256"),
                "12",
                "bad_digest",
                "Member `credential_sha256`: expected 64 lower-case hexadecimal digits.",
            );
        }
        let document = document_value.and_then(|v| check_into(v, &path.key("document"), report));
        if let (Some(id), Some(doc)) = (id, &document)
            && doc.server != id
        {
            report.error(
                &path.key("document").key("server"),
                "5.2",
                "service_id_mismatch",
                format!(
                    "Member `server` is {}, and the member `id` of the service is {}.",
                    show(&json!(doc.server)),
                    show(&json!(id))
                ),
            );
        }
        out.push(ServiceEntry {
            id: id.unwrap_or_default().to_owned(),
            document,
            credential_sha256: credential.map(str::to_owned),
        });
    }
    out
}

fn read_subjects(
    items: &[Value],
    base: &JsonPath,
    services: &[ServiceEntry],
    report: &mut Report,
) -> Vec<SubjectEntry> {
    let lookup = |id: &str| match services.iter().find(|s| s.id == id) {
        None => ServiceLookup::Unknown,
        Some(entry) => entry
            .document
            .as_ref()
            .map_or(ServiceLookup::NoDocument, ServiceLookup::Document),
    };
    let mut out: Vec<SubjectEntry> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "directory", Unknown::Error, report) else {
            continue;
        };
        let id = obj.string("id", report);
        let owner = obj.string_opt("owner", report);
        let state = obj.string_opt("state", report);
        let grants_value = obj.optional("grants");
        obj.finish(report);

        let mut kind_state = KeyState::Active;
        if let Some(id) = id {
            if out.iter().any(|s| s.id == id) {
                report.error(
                    &path.key("id"),
                    "directory",
                    "duplicate_subject",
                    format!("The subject `{id}` occurs more than one time."),
                );
            }
            match classify(id) {
                SubjectKind::Person => {
                    for (key, present) in [("owner", owner.is_some()), ("state", state.is_some())] {
                        if present {
                            report.error(
                                &path.key(key),
                                "3.1",
                                "member_for_key_only",
                                format!("Member `{key}` is for a key. The subject `{id}` is a person, and its id has no colon."),
                            );
                        }
                    }
                }
                SubjectKind::Key { .. } => {
                    match owner {
                        None => report.error(&path, "3.4", "missing_owner", format!("The key `{id}` needs the member `owner` (3.4).")),
                        Some(owner) if classify(owner) != SubjectKind::Person => report.error(
                            &path.key("owner"),
                            "3.1",
                            "bad_owner",
                            format!("Member `owner`: expected the id of a person, which has no colon, found {}.", show(&json!(owner))),
                        ),
                        Some(_) => {}
                    }
                    kind_state = match state {
                        None | Some("active") => KeyState::Active,
                        Some("revoked") => KeyState::Revoked,
                        Some("expired") => KeyState::Expired,
                        Some(other) => {
                            report.error(
                                &path.key("state"),
                                "directory",
                                "bad_state",
                                format!("Member `state`: expected `active`, `revoked` or `expired`, found {}.", show(&json!(other))),
                            );
                            KeyState::Active
                        }
                    };
                }
                SubjectKind::Unknown => report.error(
                    &path.key("id"),
                    "3.7",
                    "bad_subject_id",
                    format!(
                        "Member `id`: {} is not the id of a person or of a key (3.1, 3.2).",
                        show(&json!(id))
                    ),
                ),
            }
        }
        let grants = grants_value.map_or_else(Vec::new, |v| {
            read_grants(v, &path.key("grants"), &lookup, report)
        });
        out.push(SubjectEntry {
            id: id.unwrap_or_default().to_owned(),
            owner: owner.map(str::to_owned),
            state: kind_state,
            grants,
        });
    }
    out
}

fn read_counters(
    items: &[Value],
    base: &JsonPath,
    subjects: &[SubjectEntry],
    report: &mut Report,
) -> Vec<CounterPreset> {
    let mut out: Vec<CounterPreset> = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "6.7", Unknown::Error, report) else {
            continue;
        };
        let subject = obj.string("subject", report);
        let limit = obj.string("limit", report);
        let window = obj.string("window", report);
        let used = obj.whole("used", report);
        obj.finish(report);
        if let Some(subject) = subject
            && !subjects.iter().any(|s| s.id == subject)
        {
            report.error(
                &path.key("subject"),
                "6.7",
                "unknown_subject",
                format!("The subject `{subject}` is not in `subjects`."),
            );
        }
        if let Some(limit) = limit
            && !is_type_or_limit_name(limit)
        {
            report.error(
                &path.key("limit"),
                "5.2",
                "bad_limit_name",
                format!(
                    "Member `limit` {} is not a limit name.",
                    show(&json!(limit))
                ),
            );
        }
        let window = window.and_then(|text| {
            let window = Window::parse(text);
            if window.is_none() {
                report.error(
                    &path.key("window"),
                    "6.1",
                    "bad_window",
                    format!(
                        "Member `window`: expected `second`, `minute`, `hour` or `day`, found {}.",
                        show(&json!(text))
                    ),
                );
            }
            window
        });
        if let (Some(subject), Some(limit), Some(window), Some(used)) =
            (subject, limit, window, used)
        {
            if out
                .iter()
                .any(|c| c.subject == subject && c.limit == limit && c.window == window)
            {
                report.error(
                    &path,
                    "6.7",
                    "duplicate_counter",
                    "This counter occurs more than one time.",
                );
            }
            out.push(CounterPreset {
                subject: subject.to_owned(),
                limit: limit.to_owned(),
                window,
                used,
            });
        }
    }
    out
}

fn read_failures(items: &[Value], base: &JsonPath, report: &mut Report) -> Vec<FailureRule> {
    let mut out = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "6.9", Unknown::Error, report) else {
            continue;
        };
        let kind = obj.string("kind", report);
        let delay = obj.whole_opt("delay_ms", report);
        let times = obj.whole_opt("times", report);
        let when = obj.object_opt("when", "6.9", Unknown::Error, report);
        obj.finish(report);

        let kind = match (kind, delay) {
            (Some("error_503"), None) => Some(FailureKind::Error503),
            (Some("no_answer"), None) => Some(FailureKind::NoAnswer),
            (Some("delay"), Some(ms)) if ms >= 1 => Some(FailureKind::Delay(ms)),
            (Some("delay"), _) => {
                report.error(&path, "6.9", "bad_delay", "A failure of the kind `delay` needs the member `delay_ms`, a whole number from 1.");
                None
            }
            (Some("error_503" | "no_answer"), Some(_)) => {
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
                        "Member `kind`: expected `error_503`, `delay` or `no_answer`, found {}.",
                        show(&json!(other))
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
        if let Some(kind) = kind {
            out.push(FailureRule { kind, when, times });
        }
    }
    out
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
                show(&json!(action))
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
                format!("Resource {}: {error}.", show(&json!(text))),
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
                format!("Member `endpoint`: expected `evaluation`, `evaluations` or `metadata`, found {}.", show(&json!(other))),
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
    use crate::finding::Severity;

    /// The data of protocol section 13: Alice and her key.
    pub(crate) fn section_13() -> Value {
        json!({
            "clock": {"now": 1_792_569_648},
            "services": [{"id": "datastore", "document": {
                "server": "datastore",
                "resource_types": [
                    {"name": "host", "parent": "service", "description": "One database server."},
                    {"name": "database", "parent": "host", "description": "One database."},
                    {"name": "table", "parent": "database", "description": "One table."}],
                "actions": [
                    {"name": "data.read", "resource_types": ["service", "host", "database", "table"],
                     "description": "Read data.", "limits": ["requests", "max_rows", "max_duration"]},
                    {"name": "data.write", "resource_types": ["service", "host", "database", "table"],
                     "description": "Change data.", "limits": ["requests", "max_duration"]}],
                "resources": [{"path": "host:prod", "label": "Production"}],
                "limits": [
                    {"name": "requests", "label": "Requests", "description": "Requests that run.", "unit": "request", "kind": "budget"},
                    {"name": "max_rows", "label": "Most rows", "description": "The most rows that one read gives.", "unit": "row", "kind": "ceiling", "min": 1, "max": 1_000_000},
                    {"name": "max_duration", "label": "Longest run", "description": "The longest run of one use, in seconds.", "unit": "second", "kind": "ceiling", "min": 1, "max": 600}]
            }}],
            "subjects": [
                {"id": "alice", "grants": [
                    {"action": "access", "resource": "service:datastore",
                     "limits": {"requests": [{"amount": 10, "window": "second"}, {"amount": 300, "window": "minute"}]}},
                    {"action": "data.read", "resource": "service:datastore/host:prod/database:test1", "limits": {"max_rows": 1000}},
                    {"action": "data.read", "resource": "service:datastore/host:prod/database:test2", "limits": {"max_rows": 5000, "max_duration": 30}},
                    {"action": "data.read", "resource": "service:datastore/host:prod/database:test2/table:orders", "limits": {"max_rows": 100}},
                    {"action": "data.write", "resource": "service:datastore/host:prod/database:test2", "limits": {"max_duration": 10}}]},
                {"id": "key:9b1c04e2aa71f0c3", "owner": "alice", "grants": [
                    {"action": "access", "resource": "service:datastore",
                     "limits": {"requests": [{"amount": 100, "window": "minute"}]}},
                    {"action": "data.read", "resource": "service:datastore/host:prod/database:test2", "limits": {"max_rows": 10000}}]}
            ],
            "counters": [{"subject": "alice", "limit": "requests", "window": "second", "used": 9}],
            "failures": [
                {"kind": "delay", "delay_ms": 250, "when": {"subject": "alice", "usage": true}, "times": 1},
                {"kind": "error_503", "when": {"endpoint": "evaluations"}},
                {"kind": "no_answer", "when": {"action": "data.write", "resource": "service:datastore/host:prod"}}
            ],
            "metadata": {"usage_max_seconds": 5, "idle_max_seconds": 30, "evaluations_max_bytes": 65536, "evaluations_max_items": 100}
        })
    }

    fn findings(value: &Value) -> Vec<(String, &'static str, Severity)> {
        analyze_value(value)
            .1
            .findings()
            .iter()
            .map(|f| (f.path.as_str().to_owned(), f.code, f.severity))
            .collect()
    }

    fn errors(value: &Value) -> Vec<(String, &'static str)> {
        findings(value)
            .into_iter()
            .filter(|f| f.2 == Severity::Error)
            .map(|f| (f.0, f.1))
            .collect()
    }

    #[test]
    fn p_13_the_data_of_section_13_is_good() {
        let (directory, report) = analyze_value(&section_13());
        assert!(report.findings().is_empty(), "{report:?}");
        let directory = directory.unwrap();
        assert_eq!(directory.clock_now, Some(1_792_569_648));
        assert_eq!(
            directory.services[0].document.as_ref().unwrap().server,
            "datastore"
        );
        let key = directory.subject("key:9b1c04e2aa71f0c3").unwrap();
        assert_eq!(key.owner.as_deref(), Some("alice"));
        assert_eq!(key.state, KeyState::Active);
        assert_eq!(directory.subject("alice").unwrap().grants.len(), 5);
        assert_eq!(directory.counters[0].window, Window::Second);
        assert_eq!(directory.failures.len(), 3);
        assert_eq!(directory.failures[0].kind, FailureKind::Delay(250));
        assert_eq!(directory.failures[0].when.usage, Some(true));
        assert_eq!(directory.metadata.idle_max_seconds, Some(30));
    }

    #[test]
    fn p_13_a_bad_action_document_inside_the_data_is_reported_with_its_path() {
        let mut v = section_13();
        v["services"][0]["document"]["limits"][0]["min"] = json!(1);
        assert_eq!(
            errors(&v),
            vec![(
                "$.services[0].document.limits[0].min".to_owned(),
                "budget_with_min"
            )]
        );
    }

    #[test]
    fn p_5_2_the_id_of_a_service_is_its_server() {
        let mut v = section_13();
        v["services"][0]["id"] = json!("other");
        let found = errors(&v);
        assert!(found.contains(&(
            "$.services[0].document.server".to_owned(),
            "service_id_mismatch"
        )));
    }

    #[test]
    fn p_11_1_a_service_without_a_document_has_no_good_document() {
        let v = json!({"services": [{"id": "s"}], "subjects": [
            {"id": "alice", "grants": [{"action": "data.read", "resource": "service:s/anything:x"}]}]});
        let (directory, report) = analyze_value(&v);
        assert!(report.findings().is_empty());
        assert!(directory.unwrap().services[0].document.is_none());
    }

    #[test]
    fn p_3_1_a_person_has_no_owner_and_no_state() {
        let mut v = section_13();
        v["subjects"][0]["owner"] = json!("bob");
        v["subjects"][0]["state"] = json!("revoked");
        assert_eq!(
            errors(&v),
            vec![
                ("$.subjects[0].owner".to_owned(), "member_for_key_only"),
                ("$.subjects[0].state".to_owned(), "member_for_key_only")
            ]
        );
    }

    #[test]
    fn p_3_4_a_key_has_an_owner_that_is_a_person() {
        let mut v = section_13();
        v["subjects"][1].as_object_mut().unwrap().remove("owner");
        assert_eq!(
            errors(&v),
            vec![("$.subjects[1]".to_owned(), "missing_owner")]
        );
        v["subjects"][1]["owner"] = json!("key:abc");
        assert_eq!(
            errors(&v),
            vec![("$.subjects[1].owner".to_owned(), "bad_owner")]
        );
    }

    #[test]
    fn p_11_1_the_owner_of_a_key_can_be_absent_from_the_data() {
        let mut v = section_13();
        v["subjects"][1]["owner"] = json!("nobody");
        let (directory, report) = analyze_value(&v);
        assert!(report.findings().is_empty());
        assert!(directory.unwrap().subject("nobody").is_none());
    }

    #[test]
    fn p_11_1_a_revoked_or_expired_key_is_a_state_of_the_data() {
        for (text, state) in [
            ("revoked", KeyState::Revoked),
            ("expired", KeyState::Expired),
            ("active", KeyState::Active),
        ] {
            let mut v = section_13();
            v["subjects"][1]["state"] = json!(text);
            assert_eq!(analyze_value(&v).0.unwrap().subjects[1].state, state);
        }
        let mut v = section_13();
        v["subjects"][1]["state"] = json!("deleted");
        assert_eq!(
            errors(&v),
            vec![("$.subjects[1].state".to_owned(), "bad_state")]
        );
    }

    #[test]
    fn p_3_7_a_subject_id_has_the_form_of_a_person_or_of_a_key() {
        let mut v = section_13();
        v["subjects"][0]["id"] = json!("svc:alice");
        assert!(errors(&v).contains(&("$.subjects[0].id".to_owned(), "bad_subject_id")));
    }

    #[test]
    fn p_3_8_each_key_is_one_subject_and_ids_are_unique() {
        let mut v = section_13();
        v["subjects"][1]["id"] = json!("alice");
        v["subjects"][1].as_object_mut().unwrap().remove("owner");
        assert!(errors(&v).contains(&("$.subjects[1].id".to_owned(), "duplicate_subject")));
    }

    #[test]
    fn p_6_10_a_grant_value_for_an_undeclared_limit_is_a_warning_in_the_data() {
        let mut v = section_13();
        v["subjects"][0]["grants"][1]["limits"] = json!({"max_rows": 1000, "ghost": 1});
        assert_eq!(
            findings(&v),
            vec![(
                "$.subjects[0].grants[1].limits.ghost".to_owned(),
                "undeclared_limit",
                Severity::Warning
            )]
        );
        assert!(analyze_value(&v).0.is_some());
    }

    #[test]
    fn p_4_1_a_grant_of_an_unknown_service_is_bad() {
        let mut v = section_13();
        v["subjects"][0]["grants"][1]["resource"] = json!("service:other/host:prod");
        assert_eq!(
            errors(&v),
            vec![(
                "$.subjects[0].grants[1].resource".to_owned(),
                "unknown_service"
            )]
        );
    }

    #[test]
    fn p_6_7_a_counter_names_a_subject_of_the_data() {
        let mut v = section_13();
        v["counters"] = json!([
            {"subject": "ghost", "limit": "requests", "window": "second", "used": 1},
            {"subject": "alice", "limit": "requests", "window": "week", "used": 1},
            {"subject": "alice", "limit": "requests", "window": "second", "used": 1},
            {"subject": "alice", "limit": "requests", "window": "second", "used": 2}]);
        assert_eq!(
            errors(&v),
            vec![
                ("$.counters[0].subject".to_owned(), "unknown_subject"),
                ("$.counters[1].window".to_owned(), "bad_window"),
                ("$.counters[3]".to_owned(), "duplicate_counter")
            ]
        );
    }

    #[test]
    fn p_6_9_failure_rules() {
        let mut v = section_13();
        v["failures"] = json!([
            {"kind": "delay"},
            {"kind": "error_503", "delay_ms": 5},
            {"kind": "boom"},
            {"kind": "no_answer", "times": 0},
            {"kind": "no_answer", "when": {"endpoint": "tokens", "resource": "host:x", "extra": 1}}]);
        let found = errors(&v);
        let codes: Vec<_> = found.iter().map(|f| f.1).collect();
        assert_eq!(
            codes,
            vec![
                "bad_delay",
                "bad_delay",
                "bad_kind",
                "bad_value",
                "unknown_member",
                "bad_path",
                "bad_endpoint"
            ]
        );
    }

    #[test]
    fn p_6_9_the_metadata_values_are_whole_numbers_from_one() {
        let mut v = section_13();
        v["metadata"] = json!({"usage_max_seconds": 0, "idle_max_seconds": 1.5, "unknown": 1});
        let codes: Vec<_> = errors(&v).into_iter().map(|f| f.1).collect();
        assert_eq!(codes, vec!["bad_value", "wrong_type", "unknown_member"]);
    }

    #[test]
    fn p_3_9_the_data_is_a_closed_object() {
        let mut v = section_13();
        v["extra"] = json!(1);
        assert_eq!(errors(&v), vec![("$.extra".to_owned(), "unknown_member")]);
        assert!(Directory::from_value(&json!({})).is_err());
        assert!(Directory::from_value(&json!([])).is_err());
        let minimal = json!({"services": [], "subjects": []});
        assert!(Directory::from_value(&minimal).is_ok());
    }

    #[test]
    fn p_3_9_a_duplicate_member_in_the_text_is_bad() {
        let text = r#"{"services": [], "subjects": [], "subjects": []}"#;
        assert_eq!(Directory::parse_str(text).unwrap_err()[0].code, "bad_json");
    }

    #[test]
    fn p_12_the_credential_is_kept_as_a_sha256_digest() {
        let mut v = section_13();
        v["services"][0]["credential_sha256"] = json!("00".repeat(32));
        assert!(analyze_value(&v).0.is_some());
        v["services"][0]["credential_sha256"] = json!("ABC");
        assert_eq!(
            errors(&v),
            vec![("$.services[0].credential_sha256".to_owned(), "bad_digest")]
        );
    }
}
