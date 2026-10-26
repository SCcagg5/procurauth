//! A small reference PDP, built on the pure functions of the core, runs the cases of the series D.
//!
//! It proves two things. The expected results of the example cases agree with
//! the protocol, as the core reads it. The core has what a test PDP needs. The
//! reference PDP is a test tool: it knows one service, and it has no HTTP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use procurauth_core::action_document::{ActionDocument, LimitKind};
use procurauth_core::authzen::{Decision, EvaluationRequest, MatchMode, Reason, check_resource};
use procurauth_core::coverage::{
    ceilings_of_key, ceilings_of_side, granted, key_granted, key_subtree_applies, subtree_applies,
};
use procurauth_core::directory::{Directory, KeyState, SubjectEntry};
use procurauth_core::grants::Grant;
use procurauth_core::json::parse_str;
use procurauth_core::limits::{LimitValue, Window, retry_after};
use procurauth_core::path::NodePath;
use procurauth_core::subject::{SubjectKind, classify};
use serde_json::Value;

type Counters = HashMap<(String, String, Window), u64>;

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

    fn document(&self) -> &ActionDocument {
        self.directory.services[0].document.as_ref().unwrap()
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

    fn decide(&mut self, request: &EvaluationRequest) -> Decision {
        let Some((subject, owner)) = self.resolve(&request.subject.id) else {
            return Decision::deny(Some(Reason::UnknownSubject));
        };
        let (subject, owner) = (subject.clone(), owner.cloned());
        let node = match check_resource(self.document(), &request.resource) {
            Ok(node) => node,
            Err(error) => return Decision::deny(error.reason()),
        };
        let context = request.request_context().unwrap();
        let action = request.action.name.as_str();
        let own: &[Grant] = &subject.grants;
        if context.match_mode == MatchMode::Subtree {
            let applies = match &owner {
                None => subtree_applies(own, action, &node),
                Some(owner) => key_subtree_applies(own, &owner.grants, action, &node),
            };
            return Decision {
                decision: applies,
                context: Default::default(),
            };
        }
        let allowed = match &owner {
            None => granted(own, action, &node),
            Some(owner) => key_granted(own, &owner.grants, action, &node),
        };
        if !allowed {
            return Decision::deny(None);
        }
        let limits = match &owner {
            None => ceilings_of_side(self.document(), own, action, &node),
            Some(owner) => ceilings_of_key(self.document(), own, &owner.grants, action, &node),
        };
        if context.usage_units.is_none() {
            return Decision::allow(limits, None);
        }
        match self.spend(&subject, owner.as_ref(), action) {
            Ok(units) => Decision::allow(limits, Some(units)),
            Err(seconds) => Decision::budget_exceeded(seconds),
        }
    }

    /// Take one unit from each counter of the use, or from none (6.5, 6.7).
    fn spend(
        &mut self,
        subject: &SubjectEntry,
        owner: Option<&SubjectEntry>,
        action: &str,
    ) -> Result<u64, u64> {
        let service = self.document().server.clone();
        let budgets: Vec<String> = self
            .document()
            .action(action)
            .unwrap()
            .limits
            .iter()
            .filter(|name| self.document().limit(name).unwrap().kind == LimitKind::Budget)
            .cloned()
            .collect();
        let mut needed = Vec::new();
        for side in std::iter::once(subject).chain(owner) {
            for name in &budgets {
                let access = side
                    .grants
                    .iter()
                    .find(|g| g.action == "access" && g.resource == NodePath::service(&service));
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

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// The check of one matcher against a value, with the vocabulary of the data model.
fn matches(matcher: &Value, actual: Option<&Value>) -> bool {
    let (kind, expected) = matcher.as_object().unwrap().iter().next().unwrap();
    match kind.as_str() {
        "equals" => actual == Some(expected),
        "absent" => actual.is_none(),
        "present" => actual.is_some(),
        "one_of" => actual.is_some_and(|a| expected.as_array().unwrap().contains(a)),
        "regex" => {
            let text = match actual {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => return false,
            };
            regex::Regex::new(expected.as_str().unwrap())
                .unwrap()
                .is_match(&text)
        }
        other => panic!("unknown matcher {other}"),
    }
}

fn run_case(path: &std::path::Path) {
    let case = parse_str(&fs::read_to_string(path).unwrap()).unwrap();
    let id = case["id"].as_str().unwrap();
    let given = &case["given"];
    let directory_name = given["directory"].as_str().unwrap();
    let directory_text =
        fs::read_to_string(conformance_dir().join("directories").join(directory_name)).unwrap();
    let directory = Directory::parse_str(&directory_text).unwrap();
    let counters = given["counters"].as_array().cloned().unwrap_or_default();
    let mut pdp = ReferencePdp::new(directory, given["clock"]["now"].as_u64(), &counters);
    for step in case["steps"].as_array().unwrap() {
        let name = step["name"].as_str().unwrap_or("step");
        assert_eq!(
            step["request"]["endpoint"], "evaluation",
            "{id}: the reference PDP reads Access Evaluation requests"
        );
        let request = EvaluationRequest::from_value(&step["request"]["body"]).unwrap();
        let answer = pdp.decide(&request).to_value();
        for (pointer, matcher) in step["expect"]["json"].as_object().unwrap() {
            assert!(
                matches(matcher, answer.pointer(pointer)),
                "{id}: step {name:?}: the answer {answer} does not match {pointer} {matcher}"
            );
        }
    }
}

#[test]
fn the_reference_pdp_passes_every_case_of_the_series_d() {
    let mut count = 0;
    let mut paths: Vec<_> = fs::read_dir(conformance_dir().join("D"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    for path in paths {
        run_case(&path);
        count += 1;
    }
    assert!(count >= 6);
}

#[test]
fn the_reference_pdp_counts_a_budget_in_one_atomic_step() {
    // Alice has 10 units a second and 300 a minute (protocol 13). Her key shares the counters of Alice.
    let text = fs::read_to_string(conformance_dir().join("directories/datastore.json")).unwrap();
    let directory = Directory::parse_str(&text).unwrap();
    let mut pdp = ReferencePdp::new(directory, None, &[]);
    let node = NodePath::parse("service:datastore/host:prod/database:test1").unwrap();
    let alice = EvaluationRequest::new("alice", "data.read", &node).with_usage();
    for _ in 0..10 {
        assert_eq!(pdp.decide(&alice).context.usage_units, Some(1));
    }
    // The eleventh use in the same second is refused, and it takes no unit.
    let refused = pdp.decide(&alice);
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
    let refused = pdp.decide(&key);
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
