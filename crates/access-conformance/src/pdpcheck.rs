//! The check that a PDP under test holds the directory of a case.
//!
//! The runner asks a set of control questions. It computes the expected
//! answers with the decision code of `fake-pdp`, from the same directory. A
//! control question has no `context.usage`, so it changes no counter. The
//! check proves the grants, the keys, the owners and the ceilings. It cannot
//! prove the counters.

use std::collections::BTreeSet;

use fake_pdp::pdp::{Caller, Pdp};
use procurauth_core::authzen::{EvaluationRequest, MatchMode};
use procurauth_core::directory::Directory;
use procurauth_core::names::ACCESS_ACTION;
use procurauth_core::path::NodePath;
use serde_json::Value;

/// One control question and the answer that the directory gives.
#[derive(Clone, Debug)]
pub(crate) struct Control {
    /// The question, as JSON.
    pub(crate) question: Value,
    /// The expected answer, as JSON.
    pub(crate) expected: Value,
    /// A short text for a message.
    pub(crate) label: String,
}

/// Make the control questions for a directory, at most `max` of them.
///
/// # Errors
/// Returns a message when the directory is not valid.
pub(crate) fn controls(data: &Value, max: usize) -> Result<Vec<Control>, String> {
    let directory = Directory::from_value(data).map_err(|findings| {
        findings
            .iter()
            .map(|f| format!("{}: {}", f.path, f.message))
            .collect::<Vec<_>>()
            .join("; ")
    })?;
    let now = directory.clock_now.unwrap_or(0);
    let mut pdp = Pdp::new(directory.clone(), now);
    let mut seen = BTreeSet::new();
    let mut first: Vec<(String, String, NodePath, MatchMode)> = Vec::new();
    let mut second: Vec<(String, String, NodePath, MatchMode)> = Vec::new();
    for service in &directory.services {
        let root = NodePath::service(&service.id);
        let mut actions: Vec<String> = vec![ACCESS_ACTION.to_owned()];
        let mut other_nodes: Vec<NodePath> = Vec::new();
        if let Some(document) = &service.document {
            actions.extend(document.actions.iter().map(|a| a.name.clone()));
            for item in &document.resources {
                let mut path = root.clone();
                for node in &item.nodes {
                    path = path.child(node.clone());
                }
                other_nodes.push(path);
            }
        }
        for subject in &directory.subjects {
            let mut grant_nodes: Vec<NodePath> = subject
                .grants
                .iter()
                .map(|g| g.resource.clone())
                .filter(|p| p.service_id() == service.id)
                .collect();
            grant_nodes.sort();
            grant_nodes.dedup();
            for action in &actions {
                first.push((
                    subject.id.clone(),
                    action.clone(),
                    root.clone(),
                    MatchMode::Node,
                ));
                for node in &grant_nodes {
                    first.push((
                        subject.id.clone(),
                        action.clone(),
                        node.clone(),
                        MatchMode::Node,
                    ));
                    second.push((
                        subject.id.clone(),
                        action.clone(),
                        node.clone(),
                        MatchMode::Subtree,
                    ));
                }
                for node in &other_nodes {
                    second.push((
                        subject.id.clone(),
                        action.clone(),
                        node.clone(),
                        MatchMode::Node,
                    ));
                }
            }
        }
    }
    let mut out = Vec::new();
    for (subject, action, node, mode) in first.into_iter().chain(second) {
        if out.len() >= max {
            break;
        }
        let key = (
            subject.clone(),
            action.clone(),
            node.to_string(),
            mode == MatchMode::Subtree,
        );
        if !seen.insert(key) {
            continue;
        }
        let mut request = EvaluationRequest::new(&subject, &action, &node);
        if mode == MatchMode::Subtree {
            request = request.with_match(MatchMode::Subtree);
        }
        let context = request
            .request_context()
            .map_err(|_| "a control question is not valid".to_owned())?;
        let outcome = pdp.decide(&Caller::Any, &request, &context, now.saturating_mul(1000));
        out.push(Control {
            question: request.to_value(),
            expected: outcome.decision.to_value(),
            label: format!(
                "subject {subject}, action {action}, node {node}{}",
                if mode == MatchMode::Subtree {
                    ", match subtree"
                } else {
                    ""
                }
            ),
        });
    }
    Ok(out)
}

/// Compare the answer of the PDP under test with the expected answer.
/// The check covers the decision, the reason and the ceilings.
pub(crate) fn same_answer(expected: &Value, actual: &Value) -> bool {
    expected.get("decision") == actual.get("decision")
        && expected.pointer("/context/reason") == actual.pointer("/context/reason")
        && expected.pointer("/context/limits") == actual.pointer("/context/limits")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn datastore() -> Value {
        serde_json::from_str(include_str!(
            "../../../conformance/directories/datastore.json"
        ))
        .unwrap()
    }

    #[test]
    fn the_controls_cover_each_subject_with_the_expected_answers() {
        let list = controls(&datastore(), 1000).unwrap();
        assert!(list.len() > 20, "{}", list.len());
        // Alice has a grant of data.read on the database test1 of the host prod.
        assert!(list.iter().any(
            |c| c.question["subject"]["id"] == "alice" && c.expected["decision"] == json!(true)
        ));
        assert!(list.iter().any(|c| c.expected["decision"] == json!(false)));
        // No control question asks for a unit.
        assert!(
            list.iter()
                .all(|c| c.question.pointer("/context/usage").is_none())
        );
    }

    #[test]
    fn the_number_of_controls_has_a_maximum() {
        assert_eq!(controls(&datastore(), 5).unwrap().len(), 5);
    }

    #[test]
    fn two_answers_agree_on_the_decision_the_reason_and_the_ceilings() {
        let a = json!({"decision": true, "context": {"limits": {"max_rows": 5}}});
        assert!(same_answer(
            &a,
            &json!({"decision": true, "context": {"limits": {"max_rows": 5}}})
        ));
        assert!(!same_answer(
            &a,
            &json!({"decision": true, "context": {"limits": {"max_rows": 6}}})
        ));
        assert!(!same_answer(&a, &json!({"decision": false})));
        assert!(!same_answer(
            &json!({"decision": false}),
            &json!({"decision": false, "context": {"reason": "x"}})
        ));
    }

    #[test]
    fn a_directory_that_is_not_valid_is_an_error() {
        assert!(controls(&json!({"services": 5}), 10).is_err());
    }
}
