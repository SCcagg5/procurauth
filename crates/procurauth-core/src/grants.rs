//! Grants: a right to do an action on a node, with limit values.
//!
//! The format is the one of the test PDP data (`fake-pdp-data`) and of the
//! grant file of `access-lint`: `{"action": "data.read", "resource":
//! "service:datastore/host:prod", "limits": {"max_rows": 1000}}`. The
//! resource uses the notation of protocol section 13.

use serde_json::{Map, Value, json};

use crate::action_document::{ActionDocument, LimitKind};
use crate::finding::{JsonPath, Report, show};
use crate::limits::{LimitValue, LimitValues, limit_values_to_value, read_limit_values};
use crate::names::{ACCESS_ACTION, is_action_name};
use crate::path::NodePath;
use crate::read::{Obj, Unknown};

/// A grant (3.5, section 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grant {
    /// The action. The action `access` opens the service to the subject (8.3).
    pub action: String,
    /// The node. The grant covers this node and each node below it (4.3).
    pub resource: NodePath,
    /// The limit values of the grant.
    pub limits: LimitValues,
}

impl Grant {
    /// The grant as JSON.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert("action".into(), json!(self.action));
        m.insert("resource".into(), json!(self.resource.to_string()));
        if !self.limits.is_empty() {
            m.insert("limits".into(), limit_values_to_value(&self.limits));
        }
        Value::Object(m)
    }
}

/// What a reader of grants knows about the service of a grant.
pub enum ServiceLookup<'a> {
    /// The service does not exist: the grant is bad.
    Unknown,
    /// The service exists, but it has no good action document: the reader checks no more.
    NoDocument,
    /// The service has this document: the reader checks the grant against it.
    Document(&'a ActionDocument),
}

/// Read a list of grants.
/// The function `lookup` gives the document of the service that a grant names.
/// The reader checks the grant against the tree of types (4.1) and the types of the action (5.2).
/// It also checks the limit values (6.1, 6.10).
pub fn read_grants<'a>(
    value: &Value,
    path: &JsonPath,
    lookup: &dyn Fn(&str) -> ServiceLookup<'a>,
    report: &mut Report,
) -> Vec<Grant> {
    let Some(items) = value.as_array() else {
        report.error(
            path,
            "3.5",
            "wrong_type",
            format!("Expected an array of grants, found {}.", show(value)),
        );
        return Vec::new();
    };
    items
        .iter()
        .enumerate()
        .filter_map(|(index, item)| read_grant(item, &path.index(index), lookup, report))
        .collect()
}

/// Read one grant. See [`read_grants`].
pub fn read_grant<'a>(
    value: &Value,
    path: &JsonPath,
    lookup: &dyn Fn(&str) -> ServiceLookup<'a>,
    report: &mut Report,
) -> Option<Grant> {
    let start = report.error_count();
    let mut obj = Obj::new(value, path, "3.5", Unknown::Error, report)?;
    let action = obj.string("action", report);
    let resource_text = obj.string("resource", report);
    let limits_value = obj.optional("limits");
    obj.finish(report);

    if let Some(action) = action
        && action != ACCESS_ACTION
        && !is_action_name(action)
    {
        report.error(
            &path.key("action"),
            "5.2",
            "bad_action_name",
            format!("Action name {}: expected 1 to 64 characters, parts of a to z, 0 to 9 and underscore, with `.` between the parts.", show(&json!(action))),
        );
    }
    let resource = resource_text.and_then(|text| match NodePath::parse(text) {
        Ok(path_value) => Some(path_value),
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

    let mut document = None;
    if let Some(resource) = &resource {
        match lookup(resource.service_id()) {
            ServiceLookup::Unknown => report.error(
                &path.key("resource"),
                "4.1",
                "unknown_service",
                format!("The service `{}` is not known here.", resource.service_id()),
            ),
            ServiceLookup::NoDocument => {}
            ServiceLookup::Document(found) => document = Some(found),
        }
    }
    if let (Some(doc), Some(resource), Some(action)) = (document, &resource, action) {
        check_against_document(doc, action, resource, path, report);
    }

    let limits =
        limits_value.map(|value| read_limit_values(value, &path.key("limits"), document, report));
    if let (Some(limits), Some(action)) = (&limits, action) {
        warn_about_ignored_values(document, action, limits, &path.key("limits"), report);
    }
    if report.error_count() != start {
        return None;
    }
    Some(Grant {
        action: action?.to_owned(),
        resource: resource?,
        limits: limits.unwrap_or_default(),
    })
}

fn check_against_document(
    doc: &ActionDocument,
    action: &str,
    resource: &NodePath,
    path: &JsonPath,
    report: &mut Report,
) {
    if let Err(error) = doc.check_path(resource) {
        report.error(
            &path.key("resource"),
            "4.1",
            "invalid_node",
            format!("Resource `{resource}`: {error}."),
        );
        return;
    }
    if action == ACCESS_ACTION {
        if resource.depth() != 0 {
            report.error(
                &path.key("resource"),
                "8.3",
                "access_not_on_service",
                format!("The action `access` is valid only on the service, and the resource is `{resource}`."),
            );
        }
        return;
    }
    let Some(declared) = doc.action(action) else {
        report.error(
            &path.key("action"),
            "5.2",
            "undeclared_action",
            format!("Action `{action}` is not declared in the document."),
        );
        return;
    };
    let node_type = &resource.node().node_type;
    if !declared.resource_types.contains(node_type) {
        report.error(
            &path.key("resource"),
            "5.2",
            "action_not_valid_on_type",
            format!("Action `{action}` is not valid on the type `{node_type}`."),
        );
    }
}

fn warn_about_ignored_values(
    document: Option<&ActionDocument>,
    action: &str,
    limits: &LimitValues,
    path: &JsonPath,
    report: &mut Report,
) {
    for (name, value) in limits {
        let item_path = path.key(name);
        match value {
            LimitValue::Budget(_) if action != ACCESS_ACTION => report.warning(
                &item_path,
                "8.3",
                "budget_ignored",
                format!("The budget `{name}` is on a grant of `{action}`. The PDP ignores it. A budget is on the grant of `access`."),
            ),
            LimitValue::Ceiling(_) if action == ACCESS_ACTION => report.warning(
                &item_path,
                "7.3",
                "ceiling_ignored",
                format!("The ceiling `{name}` is on a grant of `access`. The PDP ignores it."),
            ),
            LimitValue::Ceiling(_) => {
                let listed = document
                    .and_then(|d| d.action(action))
                    .map(|a| a.limits.iter().any(|l| l == name));
                let declared_ceiling = document
                    .and_then(|d| d.limit(name))
                    .is_some_and(|l| l.kind == LimitKind::Ceiling);
                if listed == Some(false) && declared_ceiling {
                    report.warning(
                        &item_path,
                        "7.3",
                        "ceiling_ignored",
                        format!("Action `{action}` does not list the ceiling `{name}`. The PDP ignores the value."),
                    );
                }
            }
            LimitValue::Budget(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn document() -> ActionDocument {
        ActionDocument::from_value(&json!({
            "server": "datastore",
            "resource_types": [
                {"name": "host", "parent": "service", "description": "H."},
                {"name": "database", "parent": "host", "description": "D."}
            ],
            "actions": [
                {"name": "data.read", "resource_types": ["host", "database"], "description": "R.",
                 "limits": ["requests", "max_rows"]},
                {"name": "data.write", "resource_types": ["database"], "description": "W."}
            ],
            "limits": [
                {"name": "requests", "label": "R", "description": "R.", "unit": "request", "kind": "budget"},
                {"name": "max_rows", "label": "R", "description": "R.", "unit": "row", "kind": "ceiling", "min": 1, "max": 100}
            ]
        }))
        .unwrap()
    }

    fn read_one(value: &Value) -> (Option<Grant>, Vec<(String, &'static str, Severity)>) {
        let doc = document();
        let lookup = |id: &str| {
            if id == "datastore" {
                ServiceLookup::Document(&doc)
            } else {
                ServiceLookup::Unknown
            }
        };
        let mut report = Report::new();
        let grant = read_grant(value, &JsonPath::root(), &lookup, &mut report);
        let found = report
            .findings()
            .iter()
            .map(|f| (f.path.as_str().to_owned(), f.code, f.severity))
            .collect();
        (grant, found)
    }

    #[test]
    fn p_3_5_a_good_grant() {
        let value = json!({"action": "data.read", "resource": "service:datastore/host:prod/database:test1",
                           "limits": {"max_rows": 100}});
        let (grant, found) = read_one(&value);
        assert!(found.is_empty(), "{found:?}");
        assert_eq!(grant.unwrap().to_value(), value);
    }

    #[test]
    fn p_8_3_the_access_grant_gives_a_budget_on_the_service() {
        let value = json!({"action": "access", "resource": "service:datastore",
                           "limits": {"requests": [{"amount": 10, "window": "second"}]}});
        let (grant, found) = read_one(&value);
        assert!(found.is_empty());
        assert!(grant.is_some());
    }

    #[test]
    fn p_8_3_access_is_valid_only_on_the_service() {
        let value = json!({"action": "access", "resource": "service:datastore/host:prod"});
        let (grant, found) = read_one(&value);
        assert!(grant.is_none());
        assert_eq!(found[0].1, "access_not_on_service");
    }

    #[test]
    fn p_8_3_a_budget_on_another_grant_is_ignored() {
        let value = json!({"action": "data.read", "resource": "service:datastore/host:prod",
                           "limits": {"requests": [{"amount": 10, "window": "second"}]}});
        let (grant, found) = read_one(&value);
        assert!(grant.is_some());
        assert_eq!(
            found,
            vec![(
                "$.limits.requests".to_owned(),
                "budget_ignored",
                Severity::Warning
            )]
        );
    }

    #[test]
    fn p_7_3_a_ceiling_that_the_action_does_not_list_is_ignored() {
        let doc_value = json!({"action": "data.write", "resource": "service:datastore/host:prod/database:a",
                               "limits": {"max_rows": 5}});
        let (grant, found) = read_one(&doc_value);
        assert!(grant.is_some());
        assert_eq!(
            found,
            vec![(
                "$.limits.max_rows".to_owned(),
                "ceiling_ignored",
                Severity::Warning
            )]
        );
    }

    #[test]
    fn p_6_10_a_limit_that_the_document_does_not_declare_is_ignored() {
        let value = json!({"action": "data.read", "resource": "service:datastore/host:prod",
                           "limits": {"ghost": 5}});
        let (grant, found) = read_one(&value);
        assert!(grant.is_some());
        assert_eq!(
            found,
            vec![(
                "$.limits.ghost".to_owned(),
                "undeclared_limit",
                Severity::Warning
            )]
        );
    }

    #[test]
    fn p_5_2_an_action_is_valid_only_on_its_types() {
        let value = json!({"action": "data.write", "resource": "service:datastore/host:prod"});
        let (grant, found) = read_one(&value);
        assert!(grant.is_none());
        assert_eq!(found[0].1, "action_not_valid_on_type");
        let value = json!({"action": "data.erase", "resource": "service:datastore/host:prod"});
        assert_eq!(read_one(&value).1[0].1, "undeclared_action");
    }

    #[test]
    fn p_4_1_a_resource_must_follow_the_tree_of_types() {
        let value = json!({"action": "data.read", "resource": "service:datastore/database:x"});
        assert_eq!(read_one(&value).1[0].1, "invalid_node");
        let value = json!({"action": "data.read", "resource": "service:other/host:x"});
        assert_eq!(read_one(&value).1[0].1, "unknown_service");
        let value = json!({"action": "data.read", "resource": "host:x"});
        assert_eq!(read_one(&value).1[0].1, "bad_path");
    }

    #[test]
    fn p_3_5_a_grant_is_a_closed_object() {
        let value = json!({"action": "data.read", "resource": "service:datastore", "extra": 1});
        assert_eq!(read_one(&value).1[0].1, "unknown_member");
        let value = json!({"resource": "service:datastore"});
        assert_eq!(read_one(&value).1[0].1, "missing_member");
    }

    #[test]
    fn p_3_5_a_service_without_a_document_gets_no_check_of_the_tree() {
        let lookup = |_: &str| ServiceLookup::NoDocument;
        let mut report = Report::new();
        let value = json!({"action": "data.read", "resource": "service:s/anything:x"});
        assert!(read_grant(&value, &JsonPath::root(), &lookup, &mut report).is_some());
        assert!(report.findings().is_empty());
    }
}
