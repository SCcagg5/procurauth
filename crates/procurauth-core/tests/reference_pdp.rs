//! A small reference PDP, built on the pure functions of the core, runs the cases of the series D.
//!
//! It proves two things. The expected results of the cases agree with the
//! protocol, as the core reads it. The core has what a test PDP needs. The
//! reference PDP is a test tool: it has no HTTP, and it answers a request with
//! a status and a body. It reads the endpoints `evaluation` and `evaluations`.
//! It chooses the service from the credential, as protocol 12 says.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use procurauth_core::action_document::{Action, ActionDocument, LimitKind};
use procurauth_core::authzen::{
    Decision, EvaluationRequest, EvaluationsRequest, MatchMode, Reason, RequestContext,
    check_resource, check_usage_placement, evaluations_answer_to_value,
};
use procurauth_core::coverage::{
    ceilings_of_key, ceilings_of_side, granted, key_granted, key_subtree_applies, subtree_applies,
};
use procurauth_core::directory::{Directory, KeyState, ServiceEntry, SubjectEntry};
use procurauth_core::grants::Grant;
use procurauth_core::json::parse_str;
use procurauth_core::limits::{LimitValue, Window, retry_after};
use procurauth_core::path::NodePath;
use procurauth_core::subject::{SubjectKind, classify};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

type Counters = HashMap<(String, String, Window), u64>;

/// The action that opens a service to a subject (8.3).
const ACCESS: &str = "access";

/// What the PDP answers to a request: an HTTP status and a JSON body.
struct Response {
    status: u16,
    body: Value,
}

/// The result of one question.
enum Outcome {
    /// A decision. The status is 200.
    Answer(Decision),
    /// A bad member of this protocol. A request with one evaluation gets HTTP 400 (11.1).
    /// An item of an Access Evaluations request gets `invalid_request`.
    BadRequest,
}

struct ReferencePdp {
    directory: Directory,
    counters: Counters,
    now_millis: u64,
}

impl ReferencePdp {
    fn new(directory: Directory, case_clock: Option<u64>, case_counters: &[Value]) -> Self {
        let now = case_clock.or(directory.clock_now).expect("a fixed clock");
        let mut counters = Counters::new();
        for c in &directory.counters {
            counters.insert((c.subject.clone(), c.limit.clone(), c.window), c.used);
        }
        for c in case_counters {
            let key = (
                c["subject"].as_str().unwrap().to_owned(),
                c["limit"].as_str().unwrap().to_owned(),
                Window::parse(c["window"].as_str().unwrap()).unwrap(),
            );
            counters.insert(key, c["used"].as_u64().unwrap());
        }
        Self {
            directory,
            counters,
            now_millis: now * 1000,
        }
    }

    /// The service that the credential names. A directory with no digest has one service for each PEP: the first one.
    fn service_index(&self, headers: &Map<String, Value>) -> Option<usize> {
        if self
            .directory
            .services
            .iter()
            .all(|s| s.credential_sha256.is_none())
        {
            return Some(0);
        }
        let credential = headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
            .and_then(|(_, value)| value.as_str())
            .and_then(|text| text.strip_prefix("Bearer "))?;
        let digest = hex::encode(Sha256::digest(credential.as_bytes()));
        self.directory
            .services
            .iter()
            .position(|s| s.credential_sha256.as_deref() == Some(digest.as_str()))
    }

    /// Answer a request of the endpoint `evaluation` or `evaluations`.
    fn handle(&mut self, endpoint: &str, headers: &Map<String, Value>, body: &Value) -> Response {
        let Some(index) = self.service_index(headers) else {
            return Response {
                status: 401,
                body: json!({}),
            };
        };
        match endpoint {
            "evaluation" => self.single(index, body),
            "evaluations" => self.batch(index, body),
            other => panic!("the reference PDP has no endpoint {other}"),
        }
    }

    fn bad_request() -> Response {
        Response {
            status: 400,
            body: json!({"error": "bad request"}),
        }
    }

    fn single(&mut self, index: usize, body: &Value) -> Response {
        let Ok(request) = EvaluationRequest::from_value(body) else {
            return Self::bad_request();
        };
        match self.decide(index, &request) {
            Outcome::Answer(decision) => Response {
                status: 200,
                body: decision.to_value(),
            },
            Outcome::BadRequest => Self::bad_request(),
        }
    }

    fn batch(&mut self, index: usize, body: &Value) -> Response {
        // Only a request with one evaluation can carry usage (6.11).
        if !check_usage_placement(body).is_empty() {
            return Self::bad_request();
        }
        let Ok(request) = EvaluationsRequest::from_value(body) else {
            return Self::bad_request();
        };
        let mut answers = Vec::new();
        for item in &request.items {
            answers.push(match self.decide(index, item) {
                Outcome::Answer(decision) => decision,
                Outcome::BadRequest => Decision::deny(Some(Reason::InvalidRequest)),
            });
        }
        Response {
            status: 200,
            body: evaluations_answer_to_value(&answers),
        }
    }

    /// The subject, and its owner when it is a key. `None` is an unknown subject (11.1).
    fn resolve(&self, id: &str) -> Option<(&SubjectEntry, Option<&SubjectEntry>)> {
        let entry = self.directory.subject(id)?;
        match classify(id) {
            SubjectKind::Person => Some((entry, None)),
            SubjectKind::Key { .. } if entry.state == KeyState::Active => {
                let owner = self.directory.subject(entry.owner.as_deref()?)?;
                Some((entry, Some(owner)))
            }
            _ => None,
        }
    }

    fn decide(&mut self, index: usize, request: &EvaluationRequest) -> Outcome {
        // A bad member of this protocol (4.4, 6.4, 6.11, 4.1).
        let Ok(context) = request.request_context() else {
            return Outcome::BadRequest;
        };
        if let Err(error) = request.resource.ancestors()
            && error.reason() == Some(Reason::InvalidRequest)
        {
            return Outcome::BadRequest;
        }
        if request.subject.subject_type != "user" {
            return Outcome::Answer(Decision::deny(Some(Reason::UnknownSubject)));
        }
        let Some((subject, owner)) = self.resolve(&request.subject.id) else {
            return Outcome::Answer(Decision::deny(Some(Reason::UnknownSubject)));
        };
        let (subject, owner) = (subject.clone(), owner.cloned());
        let service: ServiceEntry = self.directory.services[index].clone();
        let action = request.action.name.as_str();
        let node = match &service.document {
            Some(document) => match check_resource(document, &request.resource) {
                Ok(node) => node,
                Err(error) => return Outcome::Answer(Decision::deny(error.reason())),
            },
            // With no good document, only a question for access on the service gets a decision (11.1).
            None => match request.resource.node_path() {
                Ok(node)
                    if action == ACCESS && node.depth() == 0 && node.service_id() == service.id =>
                {
                    node
                }
                _ => return Outcome::Answer(Decision::deny(None)),
            },
        };
        Outcome::Answer(self.answer(&service, &subject, owner.as_ref(), action, &node, &context))
    }

    fn answer(
        &mut self,
        service: &ServiceEntry,
        subject: &SubjectEntry,
        owner: Option<&SubjectEntry>,
        action: &str,
        node: &NodePath,
        context: &RequestContext,
    ) -> Decision {
        let own: &[Grant] = &subject.grants;
        if context.match_mode == MatchMode::Subtree {
            let applies = match owner {
                None => subtree_applies(own, action, node),
                Some(owner) => key_subtree_applies(own, &owner.grants, action, node),
            };
            return Decision {
                decision: applies,
                context: Default::default(),
            };
        }
        let allowed = match owner {
            None => granted(own, action, node),
            Some(owner) => key_granted(own, &owner.grants, action, node),
        };
        if !allowed {
            return Decision::deny(None);
        }
        let limits = match &service.document {
            None => Default::default(),
            Some(document) => match owner {
                None => ceilings_of_side(document, own, action, node),
                Some(owner) => ceilings_of_key(document, own, &owner.grants, action, node),
            },
        };
        if context.usage_units.is_none() {
            return Decision::allow(limits, None);
        }
        match self.spend(service, subject, owner, action) {
            Ok(units) => Decision::allow(limits, Some(units)),
            Err(seconds) => Decision::budget_exceeded(seconds),
        }
    }

    /// Take one unit from each counter of the use, or from none (6.5, 6.7).
    fn spend(
        &mut self,
        service: &ServiceEntry,
        subject: &SubjectEntry,
        owner: Option<&SubjectEntry>,
        action: &str,
    ) -> Result<u64, u64> {
        let budgets: Vec<String> = match &service.document {
            None => Vec::new(),
            Some(document) => document
                .action(action)
                .map(|a| budget_names(document, a))
                .unwrap_or_default(),
        };
        let mut needed = Vec::new();
        for side in std::iter::once(subject).chain(owner) {
            for name in &budgets {
                let access = side
                    .grants
                    .iter()
                    .find(|g| g.action == ACCESS && g.resource == NodePath::service(&service.id));
                if let Some(LimitValue::Budget(items)) = access.and_then(|g| g.limits.get(name)) {
                    for item in items {
                        needed.push((side.id.clone(), name.clone(), item.window, item.amount));
                    }
                }
            }
        }
        let refusing: Vec<Window> = needed
            .iter()
            .filter(|(id, name, window, amount)| {
                self.counters
                    .get(&(id.clone(), name.clone(), *window))
                    .copied()
                    .unwrap_or(0)
                    + 1
                    > *amount
            })
            .map(|(_, _, window, _)| *window)
            .collect();
        if !refusing.is_empty() {
            return Err(retry_after(self.now_millis, refusing));
        }
        for (id, name, window, _) in &needed {
            *self
                .counters
                .entry((id.clone(), name.clone(), *window))
                .or_insert(0) += 1;
        }
        Ok(u64::from(!needed.is_empty()))
    }
}

/// The budgets that an action lists.
fn budget_names(document: &ActionDocument, action: &Action) -> Vec<String> {
    action
        .limits
        .iter()
        .filter(|name| {
            document
                .limit(name)
                .is_some_and(|l| l.kind == LimitKind::Budget)
        })
        .cloned()
        .collect()
}

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// The check of one matcher against a value, with the vocabulary of the data model.
fn matches(matcher: &Value, actual: Option<&Value>) -> bool {
    let (kind, expected) = matcher.as_object().unwrap().iter().next().unwrap();
    let text = |value: &Value| match value {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    match kind.as_str() {
        "equals" => actual == Some(expected),
        "absent" => actual.is_none(),
        "present" => actual.is_some(),
        "one_of" => actual.is_some_and(|a| expected.as_array().unwrap().contains(a)),
        "regex" => actual.is_some_and(|a| {
            regex::Regex::new(expected.as_str().unwrap())
                .unwrap()
                .is_match(&text(a))
        }),
        "not_regex" => actual.is_none_or(|a| {
            !regex::Regex::new(expected.as_str().unwrap())
                .unwrap()
                .is_match(&text(a))
        }),
        other => panic!("unknown matcher {other}"),
    }
}

/// Load the directory of a case: a file name, or the data itself.
fn load_directory(given: &Value) -> Directory {
    match &given["directory"] {
        Value::String(name) => {
            let text =
                fs::read_to_string(conformance_dir().join("directories").join(name)).unwrap();
            Directory::parse_str(&text).unwrap_or_else(|e| panic!("{name}: {e:?}"))
        }
        data @ Value::Object(_) => Directory::from_value(data).unwrap(),
        other => panic!("the case has no directory: {other}"),
    }
}

/// Run the steps of a case on a new reference PDP. The error names the first step that fails.
fn run_case_value(case: &Value) -> Result<(), String> {
    let id = case["id"].as_str().unwrap();
    let given = &case["given"];
    let counters = given["counters"].as_array().cloned().unwrap_or_default();
    let mut pdp = ReferencePdp::new(
        load_directory(given),
        given["clock"]["now"].as_u64(),
        &counters,
    );
    let no_headers = Map::new();
    for step in case["steps"].as_array().unwrap() {
        let name = step["name"].as_str().unwrap_or("step");
        let endpoint = step["request"]["endpoint"].as_str().unwrap();
        let headers = step["request"]["headers"]
            .as_object()
            .unwrap_or(&no_headers);
        let response = pdp.handle(endpoint, headers, &step["request"]["body"]);
        let expect = &step["expect"];
        if let Some(matcher) = expect.get("status")
            && !matches(matcher, Some(&json!(response.status)))
        {
            return Err(format!(
                "{id}: step {name:?}: the status {} does not match {matcher}",
                response.status
            ));
        }
        if let Some(pointers) = expect["json"].as_object() {
            for (pointer, matcher) in pointers {
                if !matches(matcher, response.body.pointer(pointer)) {
                    return Err(format!(
                        "{id}: step {name:?}: the answer {} does not match {pointer} {matcher}",
                        response.body
                    ));
                }
            }
        }
    }
    Ok(())
}

fn case_files() -> Vec<PathBuf> {
    let mut paths: Vec<_> = fs::read_dir(conformance_dir().join("cases/D"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p: &PathBuf| p.extension().is_some_and(|e| e == "json"))
        .collect();
    paths.sort();
    paths
}

fn read_case(path: &Path) -> Value {
    parse_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn the_reference_pdp_passes_every_case_of_the_series_d() {
    let mut count = 0;
    let mut failures = Vec::new();
    for path in case_files() {
        let case = read_case(&path);
        if let Err(message) = run_case_value(&case) {
            failures.push(message);
        }
        count += 1;
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(count >= 60, "only {count} cases ran");
}

/// Change the first expected value that a case compares with `equals`, so that it is wrong.
/// The function returns false when the case has no such value.
fn make_wrong(case: &mut Value) -> bool {
    fn wrong(value: &Value) -> Value {
        match value {
            Value::Bool(b) => json!(!b),
            Value::Number(n) => json!(n.as_i64().unwrap_or(0) + 1),
            Value::String(s) => json!(format!("{s}-wrong")),
            _ => json!("wrong"),
        }
    }
    for step in case["steps"].as_array_mut().unwrap() {
        if let Some(matcher) = step["expect"]["status"].as_object_mut()
            && let Some(value) = matcher.get_mut("equals")
        {
            *value = wrong(value);
            return true;
        }
        if let Some(pointers) = step["expect"]["json"].as_object_mut() {
            for matcher in pointers.values_mut() {
                if let Some(value) = matcher.as_object_mut().and_then(|m| m.get_mut("equals")) {
                    *value = wrong(value);
                    return true;
                }
            }
        }
    }
    false
}

#[test]
fn a_wrong_expectation_fails_in_every_case() {
    let mut mutated = 0;
    for path in case_files() {
        let mut case = read_case(&path);
        let id = case["id"].as_str().unwrap().to_owned();
        assert!(
            make_wrong(&mut case),
            "{id}: the case has no value to change"
        );
        assert!(
            run_case_value(&case).is_err(),
            "{id}: the reference PDP accepts a wrong expectation"
        );
        mutated += 1;
    }
    assert!(mutated >= 60);
}

#[test]
fn a_matcher_that_says_absent_fails_when_the_member_is_present() {
    // The mutation turns the first `absent` of a case into `present`.
    let mut mutated = 0;
    for path in case_files() {
        let mut case = read_case(&path);
        let id = case["id"].as_str().unwrap().to_owned();
        let mut done = false;
        'steps: for step in case["steps"].as_array_mut().unwrap() {
            if let Some(pointers) = step["expect"]["json"].as_object_mut() {
                for matcher in pointers.values_mut() {
                    if matcher.get("absent").is_some() {
                        *matcher = json!({"present": true});
                        done = true;
                        break 'steps;
                    }
                }
            }
        }
        if done {
            assert!(
                run_case_value(&case).is_err(),
                "{id}: the reference PDP accepts present for an absent member"
            );
            mutated += 1;
        }
    }
    assert!(mutated >= 20, "only {mutated} cases have an absent member");
}

#[test]
fn the_reference_pdp_counts_a_budget_in_one_atomic_step() {
    // Alice has 10 units a second and 300 a minute (protocol 13). Her key shares the counters of Alice.
    let text = fs::read_to_string(conformance_dir().join("directories/datastore.json")).unwrap();
    let directory = Directory::parse_str(&text).unwrap();
    let mut pdp = ReferencePdp::new(directory, None, &[]);
    let node = NodePath::parse("service:datastore/host:prod/database:test1").unwrap();
    let alice = EvaluationRequest::new("alice", "data.read", &node).with_usage();
    let decide = |pdp: &mut ReferencePdp, request: &EvaluationRequest| match pdp.decide(0, request)
    {
        Outcome::Answer(decision) => decision,
        Outcome::BadRequest => panic!("a bad request"),
    };
    for _ in 0..10 {
        assert_eq!(decide(&mut pdp, &alice).context.usage_units, Some(1));
    }
    // The eleventh use in the same second is refused, and it takes no unit.
    let refused = decide(&mut pdp, &alice);
    assert!(!refused.decision);
    assert_eq!(refused.context.reason, Some(Reason::BudgetExceeded));
    assert_eq!(refused.context.retry_after, Some(1));
    assert_eq!(
        pdp.counters[&("alice".to_owned(), "requests".to_owned(), Window::Minute)],
        10
    );
    // A use of the key of Alice takes units from its own counter and from the counters of Alice.
    let node2 = NodePath::parse("service:datastore/host:prod/database:test2").unwrap();
    let key = EvaluationRequest::new("key:9b1c04e2aa71f0c3", "data.read", &node2).with_usage();
    // Alice already spent 10 units in the second: the owner side refuses the key.
    let refused = decide(&mut pdp, &key);
    assert_eq!(refused.context.reason, Some(Reason::BudgetExceeded));
    assert_eq!(
        pdp.counters.get(&(
            "key:9b1c04e2aa71f0c3".to_owned(),
            "requests".to_owned(),
            Window::Minute
        )),
        None
    );
}
