//! Coverage and the decision for a key (protocol 3.5, 4.3 and 4.4).
//!
//! These functions are pure. The test PDP and the conformance suite use
//! them. They work on grants of one subject and on the path of a node.

use std::collections::BTreeMap;

use crate::action_document::{ActionDocument, LimitKind};
use crate::grants::Grant;
use crate::limits::{LimitValue, combine_sides, lowest};
use crate::path::NodePath;

/// True when a grant on `grant` covers `node` (4.3): the node is the grant
/// node, or it is below it. A grant on a database does not cover its host.
pub fn covers(grant: &NodePath, node: &NodePath) -> bool {
    grant.is_prefix_of(node)
}

/// True when one grant of `action` covers `node` (4.3).
pub fn granted(grants: &[Grant], action: &str, node: &NodePath) -> bool {
    grants
        .iter()
        .any(|g| g.action == action && covers(&g.resource, node))
}

/// True when a grant of `action` applies on `node`, above it or below it
/// (4.4, `context.match` = `subtree`), for a person.
pub fn subtree_applies(grants: &[Grant], action: &str, node: &NodePath) -> bool {
    grants.iter().any(|g| {
        g.action == action && (g.resource.is_prefix_of(node) || node.is_prefix_of(&g.resource))
    })
}

/// The decision for a key and `context.match` = `node` (3.5). The answer is
/// `true` only when a grant of the key covers the node and a grant of the
/// owner covers it too. The protocol does not say how a PDP decides the
/// rights of the owner. This function uses the grants of the owner.
pub fn key_granted(
    key_grants: &[Grant],
    owner_grants: &[Grant],
    action: &str,
    node: &NodePath,
) -> bool {
    granted(key_grants, action, node) && granted(owner_grants, action, node)
}

/// The decision for a key and `context.match` = `subtree` (4.4).
/// The answer is `true` only when one node is covered by a grant of the key and by a grant of the owner.
/// This node is the node of the question, a node above it or a node below it.
pub fn key_subtree_applies(
    key_grants: &[Grant],
    owner_grants: &[Grant],
    action: &str,
    node: &NodePath,
) -> bool {
    let comparable = |a: &NodePath, b: &NodePath| a.is_prefix_of(b) || b.is_prefix_of(a);
    key_grants.iter().filter(|g| g.action == action).any(|kg| {
        owner_grants
            .iter()
            .filter(|g| g.action == action)
            .any(|og| {
                // A node below both grant nodes exists only when the two are on one line.
                // The deepest of the two is then the best candidate.
                comparable(&kg.resource, &og.resource) && {
                    let deepest = if kg.resource.depth() >= og.resource.depth() {
                        &kg.resource
                    } else {
                        &og.resource
                    };
                    comparable(deepest, node)
                }
            })
    })
}

/// The ceilings of an answer for one side (7.3).
/// The function takes each ceiling that the action lists and that a grant gives.
/// Its value is the lowest among the grants of the asked action that cover the node.
/// A budget never appears here.
pub fn ceilings_of_side(
    document: &ActionDocument,
    grants: &[Grant],
    action: &str,
    node: &NodePath,
) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let Some(declared) = document.action(action) else {
        return out;
    };
    for name in &declared.limits {
        let is_ceiling = document
            .limit(name)
            .is_some_and(|l| l.kind == LimitKind::Ceiling);
        if !is_ceiling {
            continue;
        }
        let values = grants
            .iter()
            .filter(|g| g.action == action && covers(&g.resource, node))
            .filter_map(|g| match g.limits.get(name) {
                Some(LimitValue::Ceiling(value)) => Some(*value),
                _ => None,
            });
        if let Some(lowest) = lowest(values) {
            out.insert(name.clone(), lowest);
        }
    }
    out
}

/// The ceilings of an answer for a key (7.3, 8.1).
/// The function combines the ceilings of the key and of its owner.
/// A ceiling that both give has the lower value.
pub fn ceilings_of_key(
    document: &ActionDocument,
    key_grants: &[Grant],
    owner_grants: &[Grant],
    action: &str,
    node: &NodePath,
) -> BTreeMap<String, u64> {
    combine_sides(
        &ceilings_of_side(document, key_grants, action, node),
        &ceilings_of_side(document, owner_grants, action, node),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::{JsonPath, Report};
    use crate::grants::{ServiceLookup, read_grants};
    use serde_json::{Value, json};

    fn path(text: &str) -> NodePath {
        NodePath::parse(text).unwrap()
    }

    fn document() -> ActionDocument {
        ActionDocument::from_value(&json!({
            "server": "datastore",
            "resource_types": [
                {"name": "host", "parent": "service", "description": "H."},
                {"name": "database", "parent": "host", "description": "D."},
                {"name": "table", "parent": "database", "description": "T."}
            ],
            "actions": [
                {"name": "data.read", "resource_types": ["service", "host", "database", "table"],
                 "description": "R.", "limits": ["requests", "max_rows", "max_duration"]},
                {"name": "data.write", "resource_types": ["service", "host", "database", "table"],
                 "description": "W.", "limits": ["requests", "max_duration"]}
            ],
            "limits": [
                {"name": "requests", "label": "R", "description": "R.", "unit": "request", "kind": "budget"},
                {"name": "max_rows", "label": "R", "description": "R.", "unit": "row", "kind": "ceiling", "min": 1, "max": 1000000},
                {"name": "max_duration", "label": "D", "description": "D.", "unit": "second", "kind": "ceiling", "min": 1, "max": 600}
            ]
        }))
        .unwrap()
    }

    fn grants(value: &Value, doc: &ActionDocument) -> Vec<Grant> {
        let mut report = Report::new();
        let lookup = |_: &str| ServiceLookup::Document(doc);
        let grants = read_grants(value, &JsonPath::root(), &lookup, &mut report);
        assert!(!report.has_errors(), "{report:?}");
        grants
    }

    /// The grants of Alice in protocol section 13.
    fn alice(doc: &ActionDocument) -> Vec<Grant> {
        grants(
            &json!([
                {"action": "access", "resource": "service:datastore",
                 "limits": {"requests": [{"amount": 10, "window": "second"}, {"amount": 300, "window": "minute"}]}},
                {"action": "data.read", "resource": "service:datastore/host:prod/database:test1", "limits": {"max_rows": 1000}},
                {"action": "data.read", "resource": "service:datastore/host:prod/database:test2", "limits": {"max_rows": 5000, "max_duration": 30}},
                {"action": "data.read", "resource": "service:datastore/host:prod/database:test2/table:orders", "limits": {"max_rows": 100}},
                {"action": "data.write", "resource": "service:datastore/host:prod/database:test2", "limits": {"max_duration": 10}}
            ]),
            doc,
        )
    }

    #[test]
    fn p_4_3_a_grant_covers_its_node_and_each_node_below() {
        let host = path("service:datastore/host:prod");
        assert!(covers(&host, &host));
        assert!(covers(
            &host,
            &path("service:datastore/host:prod/database:test1")
        ));
        assert!(covers(
            &host,
            &path("service:datastore/host:prod/database:new/table:t")
        ));
        assert!(!covers(
            &host,
            &path("service:datastore/host:dev/database:test1")
        ));
        assert!(covers(&path("service:datastore"), &host));
    }

    #[test]
    fn p_4_3_a_grant_on_a_database_does_not_cover_its_host() {
        let database = path("service:datastore/host:prod/database:test1");
        assert!(!covers(&database, &path("service:datastore/host:prod")));
    }

    #[test]
    fn p_4_2_an_id_is_unique_only_below_its_parent() {
        let a = path("service:datastore/host:a/database:x");
        let b = path("service:datastore/host:b/database:x");
        assert!(!covers(&a, &b));
    }

    #[test]
    fn p_13_alice_decisions() {
        let doc = document();
        let grants = alice(&doc);
        let orders = path("service:datastore/host:prod/database:test2/table:orders");
        assert!(granted(&grants, "data.read", &orders));
        assert!(granted(&grants, "data.write", &orders));
        let test1 = path("service:datastore/host:prod/database:test1");
        assert!(granted(&grants, "data.read", &test1));
        assert!(!granted(&grants, "data.write", &test1));
        assert!(!granted(
            &grants,
            "data.read",
            &path("service:datastore/host:prod")
        ));
    }

    #[test]
    fn p_13_a_ceiling_takes_the_lowest_value_among_the_grants_of_the_asked_action() {
        let doc = document();
        let grants = alice(&doc);
        let orders = path("service:datastore/host:prod/database:test2/table:orders");
        let ceilings = ceilings_of_side(&doc, &grants, "data.read", &orders);
        assert_eq!(
            ceilings,
            BTreeMap::from([
                ("max_rows".to_owned(), 100),
                ("max_duration".to_owned(), 30)
            ])
        );
    }

    #[test]
    fn p_7_3_a_value_on_a_grant_of_another_action_does_not_apply() {
        let doc = document();
        let grants = alice(&doc);
        let orders = path("service:datastore/host:prod/database:test2/table:orders");
        let ceilings = ceilings_of_side(&doc, &grants, "data.write", &orders);
        assert_eq!(ceilings, BTreeMap::from([("max_duration".to_owned(), 10)]));
    }

    #[test]
    fn p_7_3_a_budget_never_appears_in_the_ceilings() {
        let doc = document();
        let grants = alice(&doc);
        let ceilings = ceilings_of_side(&doc, &grants, "data.read", &path("service:datastore"));
        assert!(ceilings.is_empty());
    }

    /// The key of Alice in protocol section 13.
    fn key(doc: &ActionDocument) -> Vec<Grant> {
        grants(
            &json!([
                {"action": "access", "resource": "service:datastore",
                 "limits": {"requests": [{"amount": 100, "window": "minute"}]}},
                {"action": "data.read", "resource": "service:datastore/host:prod/database:test2", "limits": {"max_rows": 10000}}
            ]),
            doc,
        )
    }

    #[test]
    fn p_3_5_a_key_needs_a_grant_of_the_key_and_a_right_of_the_owner() {
        let doc = document();
        let (alice, key) = (alice(&doc), key(&doc));
        let orders = path("service:datastore/host:prod/database:test2/table:orders");
        assert!(key_granted(&key, &alice, "data.read", &orders));
        // The key has no grant of data.write.
        assert!(!key_granted(&key, &alice, "data.write", &orders));
        // The owner has no grant on the host, and the key has none either.
        assert!(!key_granted(
            &key,
            &alice,
            "data.read",
            &path("service:datastore/host:prod")
        ));
        // A grant of the key that the rights of the owner do not cover gives nothing.
        let test1 = path("service:datastore/host:prod/database:test1");
        let wide_key = grants(
            &json!([{"action": "data.read", "resource": "service:datastore/host:prod"}]),
            &doc,
        );
        assert!(key_granted(&wide_key, &alice, "data.read", &test1));
        assert!(!key_granted(&wide_key, &[], "data.read", &test1));
    }

    #[test]
    fn p_8_4_the_value_of_a_key_above_its_owner_has_no_effect() {
        let doc = document();
        let (alice, key) = (alice(&doc), key(&doc));
        let test2 = path("service:datastore/host:prod/database:test2");
        let ceilings = ceilings_of_key(&doc, &key, &alice, "data.read", &test2);
        assert_eq!(
            ceilings,
            BTreeMap::from([
                ("max_rows".to_owned(), 5000),
                ("max_duration".to_owned(), 30)
            ])
        );
    }

    #[test]
    fn p_4_4_subtree_for_a_person() {
        let doc = document();
        let alice = alice(&doc);
        let service = path("service:datastore");
        assert!(subtree_applies(&alice, "data.read", &service));
        assert!(subtree_applies(
            &alice,
            "data.read",
            &path("service:datastore/host:prod")
        ));
        assert!(!subtree_applies(
            &alice,
            "data.write",
            &path("service:datastore/host:prod/database:test1")
        ));
        assert!(!subtree_applies(
            &alice,
            "data.read",
            &path("service:datastore/host:dev")
        ));
    }

    #[test]
    fn p_4_4_key_with_test2_and_owner_with_test1_gets_false_for_subtree_on_the_service() {
        let doc = document();
        let key = grants(
            &json!([{"action": "data.read", "resource": "service:datastore/host:prod/database:test2"}]),
            &doc,
        );
        let owner = grants(
            &json!([{"action": "data.read", "resource": "service:datastore/host:prod/database:test1"}]),
            &doc,
        );
        let service = path("service:datastore");
        assert!(subtree_applies(&key, "data.read", &service));
        assert!(subtree_applies(&owner, "data.read", &service));
        assert!(!key_subtree_applies(&key, &owner, "data.read", &service));
    }

    #[test]
    fn p_4_4_key_subtree_is_true_when_one_node_is_covered_by_both_sides() {
        let doc = document();
        let key = grants(
            &json!([{"action": "data.read", "resource": "service:datastore/host:prod/database:test2"}]),
            &doc,
        );
        let owner = grants(
            &json!([{"action": "data.read", "resource": "service:datastore/host:prod"}]),
            &doc,
        );
        let service = path("service:datastore");
        // The database test2 is below the service and both sides cover it.
        assert!(key_subtree_applies(&key, &owner, "data.read", &service));
        // The node of the question is above the grant node of the key.
        assert!(key_subtree_applies(
            &key,
            &owner,
            "data.read",
            &path("service:datastore/host:prod")
        ));
        // The node of the question is on another branch.
        assert!(!key_subtree_applies(
            &key,
            &owner,
            "data.read",
            &path("service:datastore/host:dev")
        ));
        assert!(!key_subtree_applies(&key, &owner, "data.write", &service));
    }
}
