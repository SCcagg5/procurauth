//! The decisions of the test PDP, from fixed data.
//!
//! This module has no network code and no clock. A caller gives the time
//! in each call. The module copies the logic of the reference PDP in the tests
//! of `procurauth-core`. It adds these points. It knows many services and the
//! credential of a service (12). It handles a subject of another type (3.3) and
//! an action that the document does not declare.
//!
//! It also handles a service with no good document (11.1). Its counters have
//! fixed windows that follow the clock (6.3).
//!
//! The decision for a key follows 3.5: a grant of the key and the current
//! grants of its owner. The PDP counts a budget only for a `true` decision
//! to a question with `context.usage`, in one atomic step (6.5).

use procurauth_core::action_document::LimitKind;
use procurauth_core::authzen::{
    Decision, EvaluationRequest, MatchMode, Reason, RequestContext, SUBJECT_TYPE, check_resource,
};
use procurauth_core::coverage::{
    ceilings_of_key, ceilings_of_side, granted, key_granted, key_subtree_applies, subtree_applies,
};
use procurauth_core::directory::{Directory, KeyState, SubjectEntry};
use procurauth_core::grants::Grant;
use procurauth_core::limits::{LimitValue, Window, retry_after};
use procurauth_core::names::ACCESS_ACTION;
use procurauth_core::path::NodePath;
use procurauth_core::subject::{SubjectKind, classify};

use crate::counters::{CounterKey, CounterView, Counters};

/// Who asks. The PDP answers each PEP only for its own service (12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Caller {
    /// A caller that the PDP does not tie to one service.
    Any,
    /// A caller whose credential belongs to this service.
    Service(String),
}

/// The answer to one question, and the counters that the question touched.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The answer.
    pub decision: Decision,
    /// The counters of the use after the answer: first the key, then its owner.
    /// The list is empty when the question reached no budget.
    pub counters: Vec<CounterView>,
}

impl Outcome {
    fn plain(decision: Decision) -> Self {
        Self {
            decision,
            counters: Vec::new(),
        }
    }
}

/// The directory and the counters.
#[derive(Clone, Debug)]
pub struct Pdp {
    directory: Directory,
    counters: Counters,
}

impl Pdp {
    /// A PDP with the first counter values of the data, at the time `now_seconds`.
    pub fn new(directory: Directory, now_seconds: u64) -> Self {
        // A preset names no service. It applies to each service that declares the budget.
        let mut presets = Vec::new();
        for service in &directory.services {
            let Some(document) = &service.document else {
                continue;
            };
            for preset in &directory.counters {
                if document
                    .limit(&preset.limit)
                    .is_some_and(|l| l.kind == LimitKind::Budget)
                {
                    presets.push((service.id.clone(), preset.clone()));
                }
            }
        }
        let counters = Counters::new(presets, now_seconds);
        Self {
            directory,
            counters,
        }
    }

    /// The data.
    pub fn directory(&self) -> &Directory {
        &self.directory
    }

    /// The counters of the windows that hold `now_seconds`.
    pub fn counter_view(&self, now_seconds: u64) -> Vec<CounterView> {
        self.counters.view(now_seconds)
    }

    /// Put the counters back to the first values of the data.
    pub fn reset_counters(&mut self, now_seconds: u64) {
        self.counters.reset(now_seconds);
    }

    /// Decide one question. The function counts units only when the answer is
    /// `true` and the question has `context.usage` (6.5, 6.6).
    pub fn decide(
        &mut self,
        caller: &Caller,
        request: &EvaluationRequest,
        context: &RequestContext,
        now_millis: u64,
    ) -> Outcome {
        let directory = &self.directory;
        let counters = &mut self.counters;

        // The subject (3.3, 3.7, 11.1).
        if request.subject.subject_type != SUBJECT_TYPE {
            return Outcome::plain(Decision::deny(Some(Reason::UnknownSubject)));
        }
        let Some((subject, owner)) = resolve(directory, &request.subject.id) else {
            return Outcome::plain(Decision::deny(Some(Reason::UnknownSubject)));
        };

        // The resource (4.1, 11.1).
        let node = match request.resource.node_path() {
            Ok(node) => node,
            Err(error) => return Outcome::plain(Decision::deny(error.reason())),
        };
        let Some(service) = directory.service(node.service_id()) else {
            return Outcome::plain(Decision::deny(Some(Reason::InvalidResource)));
        };
        if let Caller::Service(own) = caller
            && own != &service.id
        {
            return Outcome::plain(Decision::deny(Some(Reason::InvalidResource)));
        }
        let action = request.action.name.as_str();
        let own_grants: &[Grant] = &subject.grants;
        let owner_grants: Option<&[Grant]> = owner.map(|o| o.grants.as_slice());

        let Some(document) = service.document.as_ref() else {
            // With no good document, only the question for `access` on the service has an answer (11.1).
            let is_access_on_service = action == ACCESS_ACTION && node.depth() == 0;
            let allowed = is_access_on_service
                && match owner_grants {
                    None => granted(own_grants, action, &node),
                    Some(og) => key_granted(own_grants, og, action, &node),
                };
            return Outcome::plain(if allowed {
                Decision::allow(Default::default(), context.usage_units.map(|_| 0))
            } else {
                Decision::deny(None)
            });
        };
        if let Err(error) = check_resource(document, &request.resource) {
            return Outcome::plain(Decision::deny(error.reason()));
        }

        // `context.match` = `subtree` (4.4).
        if context.match_mode == MatchMode::Subtree {
            let applies = match owner_grants {
                None => subtree_applies(own_grants, action, &node),
                Some(og) => key_subtree_applies(own_grants, og, action, &node),
            };
            return Outcome::plain(Decision {
                decision: applies,
                context: Default::default(),
            });
        }

        // The grants (3.5, 4.3).
        let allowed = match owner_grants {
            None => granted(own_grants, action, &node),
            Some(og) => key_granted(own_grants, og, action, &node),
        };
        if !allowed {
            return Outcome::plain(Decision::deny(None));
        }
        let limits = match owner_grants {
            None => ceilings_of_side(document, own_grants, action, &node),
            Some(og) => ceilings_of_key(document, own_grants, og, action, &node),
        };

        // The budgets (6.2, 6.5, 6.7, 8.3).
        let budgets: Vec<&str> = document
            .action(action)
            .map(|a| {
                a.limits
                    .iter()
                    .filter(|name| {
                        document
                            .limit(name)
                            .is_some_and(|l| l.kind == LimitKind::Budget)
                    })
                    .map(String::as_str)
                    .collect()
            })
            .unwrap_or_default();
        let service_node = NodePath::service(&service.id);
        let mut needed: Vec<(CounterKey, u64)> = Vec::new();
        for side in std::iter::once(subject).chain(owner) {
            let access = side
                .grants
                .iter()
                .find(|g| g.action == ACCESS_ACTION && g.resource == service_node);
            for name in &budgets {
                if let Some(LimitValue::Budget(items)) = access.and_then(|g| g.limits.get(*name)) {
                    for item in items {
                        needed.push((
                            CounterKey::new(&service.id, &side.id, name, item.window),
                            item.amount,
                        ));
                    }
                }
            }
        }
        let now_seconds = now_millis / 1000;
        let view_of = |counters: &Counters, needed: &[(CounterKey, u64)]| -> Vec<CounterView> {
            needed
                .iter()
                .map(|(key, _)| CounterView {
                    service: key.service.clone(),
                    subject: key.subject.clone(),
                    limit: key.limit.clone(),
                    window: key.window,
                    used: counters.used(key, now_seconds),
                    window_start: procurauth_core::limits::window_start(now_seconds, key.window),
                })
                .collect()
        };
        if context.usage_units.is_none() {
            let views = view_of(counters, &needed);
            return Outcome {
                decision: Decision::allow(limits, None),
                counters: views,
            };
        }
        let refusing: Vec<Window> = needed
            .iter()
            .filter(|(key, amount)| counters.used(key, now_seconds) + 1 > *amount)
            .map(|(key, _)| key.window)
            .collect();
        if !refusing.is_empty() {
            let views = view_of(counters, &needed);
            return Outcome {
                decision: Decision::budget_exceeded(retry_after(now_millis, refusing)),
                counters: views,
            };
        }
        for (key, _) in &needed {
            counters.take(key, now_seconds);
        }
        let views = view_of(counters, &needed);
        Outcome {
            decision: Decision::allow(limits, Some(u64::from(!needed.is_empty()))),
            counters: views,
        }
    }
}

/// The subject, and its owner when it is a key. `None` is an unknown subject (11.1).
fn resolve<'a>(
    directory: &'a Directory,
    id: &str,
) -> Option<(&'a SubjectEntry, Option<&'a SubjectEntry>)> {
    let entry = directory.subject(id)?;
    match classify(id) {
        SubjectKind::Person => Some((entry, None)),
        SubjectKind::Key { .. } if entry.state == KeyState::Active => {
            let owner = directory.subject(entry.owner.as_deref()?)?;
            (classify(&owner.id) == SubjectKind::Person).then_some((entry, Some(owner)))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use procurauth_core::authzen::EvaluationRequest;
    use serde_json::Value;

    const DATASTORE: &str = include_str!("../../../conformance/directories/datastore.json");
    const NOW: u64 = 1_792_569_648;
    const KEY_ALICE: &str = "key:9b1c04e2aa71f0c3";
    const KEY_BOB: &str = "key:4d2e8f6a10b37c95";

    fn directory_from(value: &Value) -> Directory {
        Directory::from_value(value).unwrap()
    }

    fn datastore_value() -> Value {
        serde_json::from_str(DATASTORE).unwrap()
    }

    fn pdp() -> Pdp {
        Pdp::new(directory_from(&datastore_value()), NOW)
    }

    fn path(text: &str) -> NodePath {
        NodePath::parse(text).unwrap()
    }

    fn ask(pdp: &mut Pdp, request: &EvaluationRequest, now_millis: u64) -> Decision {
        ask_as(pdp, &Caller::Any, request, now_millis)
    }

    fn ask_as(
        pdp: &mut Pdp,
        caller: &Caller,
        request: &EvaluationRequest,
        now_millis: u64,
    ) -> Decision {
        let context = request.request_context().unwrap();
        pdp.decide(caller, request, &context, now_millis).decision
    }

    fn read(sub: &str, node: &str) -> EvaluationRequest {
        EvaluationRequest::new(sub, "data.read", &path(node))
    }

    const TEST1: &str = "service:datastore/host:prod/database:test1";
    const TEST2: &str = "service:datastore/host:prod/database:test2";

    #[test]
    fn p_4_3_a_grant_covers_a_node_that_the_directory_does_not_list() {
        let mut pdp = pdp();
        let q = read(
            "alice",
            "service:datastore/host:prod/database:test1/table:ledger",
        );
        let d = ask(&mut pdp, &q, NOW * 1000);
        assert!(d.decision);
        assert_eq!(d.context.limits["max_rows"], 1000);
        assert_eq!(d.context.usage_units, None);
    }

    #[test]
    fn p_4_3_a_grant_on_a_database_does_not_cover_its_host() {
        let mut pdp = pdp();
        let d = ask(
            &mut pdp,
            &read("alice", "service:datastore/host:prod"),
            NOW * 1000,
        );
        assert_eq!(d, Decision::deny(None));
    }

    #[test]
    fn p_3_5_a_key_needs_a_grant_of_its_own_and_a_right_of_its_owner() {
        let mut pdp = pdp();
        // The key of Bob has a grant on test2, but Bob has none.
        assert_eq!(
            ask(&mut pdp, &read(KEY_BOB, TEST2), NOW * 1000),
            Decision::deny(None)
        );
        // Bob has a grant on test1, but his key has none.
        assert_eq!(
            ask(&mut pdp, &read(KEY_BOB, TEST1), NOW * 1000),
            Decision::deny(None)
        );
        // The key of Alice and Alice both have a grant on test2.
        assert!(ask(&mut pdp, &read(KEY_ALICE, TEST2), NOW * 1000).decision);
    }

    #[test]
    fn p_4_4_a_key_needs_one_node_that_both_sides_cover_for_subtree() {
        let mut pdp = pdp();
        let subtree = |sub: &str| {
            EvaluationRequest::new(sub, "data.read", &path("service:datastore"))
                .with_match(MatchMode::Subtree)
        };
        assert!(!ask(&mut pdp, &subtree(KEY_BOB), NOW * 1000).decision);
        assert!(ask(&mut pdp, &subtree("bob"), NOW * 1000).decision);
        assert!(ask(&mut pdp, &subtree(KEY_ALICE), NOW * 1000).decision);
    }

    #[test]
    fn p_7_3_a_ceiling_takes_the_lowest_value_of_the_grants_of_the_action() {
        let mut pdp = pdp();
        let q = read(
            "alice",
            "service:datastore/host:prod/database:test2/table:orders",
        );
        let d = ask(&mut pdp, &q, NOW * 1000);
        assert_eq!(d.context.limits["max_rows"], 100);
        assert_eq!(d.context.limits["max_duration"], 30);
        let w = EvaluationRequest::new("alice", "data.write", &path(TEST2));
        let d = ask(&mut pdp, &w, NOW * 1000);
        assert_eq!(d.context.limits["max_duration"], 10);
        assert!(!d.context.limits.contains_key("max_rows"));
    }

    #[test]
    fn p_8_4_a_value_of_a_key_above_the_value_of_its_owner_has_no_effect() {
        let mut pdp = pdp();
        let d = ask(&mut pdp, &read(KEY_ALICE, TEST2), NOW * 1000);
        assert_eq!(d.context.limits["max_rows"], 5000);
        assert_eq!(d.context.limits["max_duration"], 30);
    }

    #[test]
    fn p_6_6_a_question_without_usage_counts_nothing() {
        let mut pdp = pdp();
        for _ in 0..30 {
            let d = ask(&mut pdp, &read("alice", TEST1), NOW * 1000);
            assert!(d.decision);
            assert_eq!(d.context.usage_units, None);
        }
        assert!(pdp.counter_view(NOW).is_empty());
    }

    #[test]
    fn p_6_5_the_eleventh_use_in_one_second_is_refused_and_takes_no_unit() {
        let mut pdp = pdp();
        let q = read("alice", TEST1).with_usage();
        for _ in 0..10 {
            assert_eq!(ask(&mut pdp, &q, NOW * 1000).context.usage_units, Some(1));
        }
        let refused = ask(&mut pdp, &q, NOW * 1000);
        assert_eq!(refused, Decision::budget_exceeded(1));
        let minute = pdp
            .counter_view(NOW)
            .into_iter()
            .find(|c| c.window == Window::Minute)
            .unwrap();
        assert_eq!(minute.used, 10);
    }

    #[test]
    fn p_11_1_retry_after_is_the_latest_end_among_the_refusing_windows() {
        let mut value = datastore_value();
        value["counters"] = serde_json::json!([
            {"subject": "alice", "limit": "requests", "window": "second", "used": 10},
            {"subject": "alice", "limit": "requests", "window": "minute", "used": 300}
        ]);
        let mut pdp = Pdp::new(directory_from(&value), NOW);
        // 1792569648 is 48 seconds into the minute: 12 seconds remain.
        let d = ask(&mut pdp, &read("alice", TEST1).with_usage(), NOW * 1000);
        assert_eq!(d, Decision::budget_exceeded(12));
        // With 500 ms gone in the second, 11.5 seconds remain, and the PDP rounds up.
        let d = ask(
            &mut pdp,
            &read("alice", TEST1).with_usage(),
            NOW * 1000 + 500,
        );
        assert_eq!(d, Decision::budget_exceeded(12));
    }

    #[test]
    fn p_6_3_a_new_window_gives_the_units_back() {
        let mut pdp = pdp();
        let q = read("alice", TEST1).with_usage();
        for _ in 0..10 {
            ask(&mut pdp, &q, NOW * 1000);
        }
        assert!(!ask(&mut pdp, &q, NOW * 1000).decision);
        // The next second: the second counter is new, the minute counter has 10 of 300.
        assert!(ask(&mut pdp, &q, (NOW + 1) * 1000).decision);
        // The next minute: both counters are new.
        let d = ask(&mut pdp, &q, (NOW + 12) * 1000);
        assert!(d.decision);
        let views = pdp.counter_view(NOW + 12);
        assert!(views.iter().all(|c| c.used == 1), "{views:?}");
    }

    #[test]
    fn p_6_7_a_use_of_a_key_takes_units_from_its_counters_and_from_its_owner() {
        let mut pdp = pdp();
        let context = read(KEY_ALICE, TEST2).with_usage();
        let c = context.request_context().unwrap();
        let outcome = pdp.decide(&Caller::Any, &context, &c, NOW * 1000);
        assert_eq!(outcome.decision.context.usage_units, Some(1));
        let names: Vec<_> = outcome
            .counters
            .iter()
            .map(|c| format!("{}/{}={}", c.subject, c.window.as_str(), c.used))
            .collect();
        assert_eq!(
            names,
            [
                format!("{KEY_ALICE}/minute=1"),
                "alice/second=1".to_owned(),
                "alice/minute=1".to_owned()
            ]
        );
    }

    #[test]
    fn p_6_7_the_owner_counters_bound_each_use_of_its_keys() {
        let mut pdp = pdp();
        let q = read("alice", TEST1).with_usage();
        for _ in 0..10 {
            ask(&mut pdp, &q, NOW * 1000);
        }
        // Alice spent her 10 units of the second: her key is refused, and it takes nothing.
        let key = read(KEY_ALICE, TEST2).with_usage();
        let d = ask(&mut pdp, &key, NOW * 1000);
        assert_eq!(d, Decision::budget_exceeded(1));
        let key_counter = pdp
            .counter_view(NOW)
            .into_iter()
            .find(|c| c.subject == KEY_ALICE);
        assert_eq!(key_counter, None);
    }

    #[test]
    fn p_6_7_the_budget_of_a_key_adds_no_units_to_its_owner() {
        let mut pdp = pdp();
        let key = read(KEY_ALICE, TEST2).with_usage();
        for _ in 0..10 {
            assert!(ask(&mut pdp, &key, NOW * 1000).decision);
        }
        // The key has 100 a minute and Alice has 10 a second: the eleventh use is refused.
        assert!(!ask(&mut pdp, &key, NOW * 1000).decision);
    }

    #[test]
    fn p_6_12_a_use_with_no_counter_takes_no_unit() {
        // The key of Bob has `access` with no budget, and Bob has 5 a second.
        let mut value = datastore_value();
        value["subjects"][2]["grants"][0] =
            serde_json::json!({"action": "access", "resource": "service:datastore"});
        value["subjects"][3]["grants"] = serde_json::json!([
            {"action": "access", "resource": "service:datastore"},
            {"action": "data.read", "resource": TEST1}
        ]);
        let mut pdp = Pdp::new(directory_from(&value), NOW);
        let d = ask(&mut pdp, &read(KEY_BOB, TEST1).with_usage(), NOW * 1000);
        assert!(d.decision);
        assert_eq!(d.context.usage_units, Some(0));
        assert!(pdp.counter_view(NOW).is_empty());
    }

    #[test]
    fn p_6_2_a_use_counts_each_budget_that_its_action_lists() {
        let mut value = datastore_value();
        value["subjects"][0]["grants"][0]["limits"] =
            serde_json::json!({"requests": [{"amount": 1, "window": "second"}]});
        let mut pdp = Pdp::new(directory_from(&value), NOW);
        let q = EvaluationRequest::new("alice", "data.write", &path(TEST2)).with_usage();
        assert!(ask(&mut pdp, &q, NOW * 1000).decision);
        assert!(!ask(&mut pdp, &q, NOW * 1000).decision);
    }

    #[test]
    fn p_8_3_the_pdp_ignores_a_budget_on_a_grant_that_is_not_access() {
        let value = datastore_value();
        let pdp_data = directory_from(&value);
        let alice = pdp_data.subject("alice").unwrap();
        for grant in &alice.grants {
            if grant.action != "access" {
                assert!(
                    grant
                        .limits
                        .values()
                        .all(|v| matches!(v, LimitValue::Ceiling(_)))
                );
            }
        }
    }

    #[test]
    fn p_11_1_an_unknown_subject_gets_the_reason() {
        let mut value = datastore_value();
        value["subjects"]
            .as_array_mut()
            .unwrap()
            .extend([
                serde_json::json!({"id": "key:revoked1", "owner": "alice", "state": "revoked", "grants": []}),
                serde_json::json!({"id": "key:expired1", "owner": "alice", "state": "expired", "grants": []}),
                serde_json::json!({"id": "key:orphan1", "owner": "nobody", "grants": []}),
            ]);
        let mut pdp = Pdp::new(directory_from(&value), NOW);
        for sub in [
            "key:revoked1",
            "key:expired1",
            "key:orphan1",
            "carol",
            "svc:abc",
            "key:",
            "key:ABC",
        ] {
            let d = ask(&mut pdp, &read(sub, TEST1), NOW * 1000);
            assert_eq!(d, Decision::deny(Some(Reason::UnknownSubject)), "{sub}");
        }
    }

    #[test]
    fn p_3_3_a_subject_of_another_type_is_an_unknown_subject() {
        let mut pdp = pdp();
        let mut q = read("alice", TEST1);
        q.subject.subject_type = "service".to_owned();
        assert_eq!(
            ask(&mut pdp, &q, NOW * 1000),
            Decision::deny(Some(Reason::UnknownSubject))
        );
    }

    #[test]
    fn p_11_1_a_bad_chain_gets_invalid_resource() {
        let mut pdp = pdp();
        let invalid = Decision::deny(Some(Reason::InvalidResource));
        // A resource below the service with no chain.
        let mut q = read("alice", TEST1);
        q.resource.properties = None;
        assert_eq!(ask(&mut pdp, &q, NOW * 1000), invalid);
        // The first object of the chain is another service.
        let mut q = read("alice", "service:other/host:prod/database:test1");
        assert_eq!(ask(&mut pdp, &q, NOW * 1000), invalid);
        // A type that the document does not declare.
        q = read("alice", TEST1);
        q.resource.resource_type = "schema".to_owned();
        assert_eq!(ask(&mut pdp, &q, NOW * 1000), invalid);
        // The types do not follow the parents of the document.
        let q = read("alice", "service:datastore/database:test1");
        assert_eq!(ask(&mut pdp, &q, NOW * 1000), invalid);
        // The service has a chain.
        let mut q = read("alice", "service:datastore");
        q.resource.properties = read("alice", TEST1).resource.properties;
        assert_eq!(ask(&mut pdp, &q, NOW * 1000), invalid);
    }

    #[test]
    fn p_11_1_a_caller_of_one_service_gets_invalid_resource_for_another_service() {
        let mut value = datastore_value();
        value["services"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"id": "other"}));
        let mut pdp = Pdp::new(directory_from(&value), NOW);
        let q = read("alice", TEST1);
        let me = Caller::Service("other".to_owned());
        assert_eq!(
            ask_as(&mut pdp, &me, &q, NOW * 1000),
            Decision::deny(Some(Reason::InvalidResource))
        );
        let me = Caller::Service("datastore".to_owned());
        assert!(ask_as(&mut pdp, &me, &q, NOW * 1000).decision);
    }

    #[test]
    fn p_11_1_a_service_with_no_document_answers_only_for_access_on_the_service() {
        let mut value = datastore_value();
        value["services"][0]
            .as_object_mut()
            .unwrap()
            .remove("document");
        for subject in value["subjects"].as_array_mut().unwrap() {
            subject["grants"] = serde_json::json!([]);
        }
        value["subjects"][0]["grants"] = serde_json::json!([
            {"action": "access", "resource": "service:datastore"}
        ]);
        value["counters"] = serde_json::json!([]);
        let mut pdp = Pdp::new(directory_from(&value), NOW);
        let access = EvaluationRequest::new("alice", "access", &path("service:datastore"));
        assert!(ask(&mut pdp, &access, NOW * 1000).decision);
        // Any other node gets `false` with no reason.
        assert_eq!(
            ask(&mut pdp, &read("alice", TEST1), NOW * 1000),
            Decision::deny(None)
        );
        let access_deep = EvaluationRequest::new("alice", "access", &path(TEST1));
        assert_eq!(
            ask(&mut pdp, &access_deep, NOW * 1000),
            Decision::deny(None)
        );
    }

    #[test]
    fn p_6_5_a_question_to_a_service_with_an_undeclared_action_takes_no_unit() {
        let mut pdp = pdp();
        let q = EvaluationRequest::new("alice", "access", &path("service:datastore")).with_usage();
        let d = ask(&mut pdp, &q, NOW * 1000);
        assert!(d.decision);
        assert_eq!(d.context.usage_units, Some(0));
    }

    #[test]
    fn p_11_2_a_false_answer_for_an_unknown_action_has_no_reason() {
        let mut pdp = pdp();
        let q = EvaluationRequest::new("alice", "data.delete", &path(TEST1));
        assert_eq!(ask(&mut pdp, &q, NOW * 1000), Decision::deny(None));
    }
}
