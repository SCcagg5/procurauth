//! The query of a request to the options route (protocol 5.7).
//!
//! The options file can hold the query string of the request. The tool checks the
//! parameters, and it checks the answer against them and against the document.

use std::collections::HashSet;

use procurauth_core::action_document::ActionDocument;
use procurauth_core::finding::{JsonPath, Report, Severity, show};
use procurauth_core::names::{SERVICE, decode_id, is_type_or_limit_name};
use procurauth_core::options::OptionsAnswer;
use procurauth_core::path::{NodePath, NodeRef};
use serde_json::json;

use crate::check::LintFinding;

/// The parameters that 5.7 names.
const KNOWN: [&str; 5] = ["parent", "type", "q", "limit", "after"];

/// The values of the query that the checks of the answer need.
#[derive(Debug, Default)]
pub(crate) struct Query {
    /// The type of the children.
    node_type: Option<String>,
    /// The maximum number of items.
    limit: Option<u64>,
}

/// Check the query string. The string has no `?`.
pub(crate) fn check_query(
    text: &str,
    path: &JsonPath,
    document: Option<&ActionDocument>,
    report: &mut Report,
) -> Query {
    let mut query = Query::default();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut parent: Option<Vec<NodeRef>> = None;
    for part in text.split('&').filter(|part| !part.is_empty()) {
        let (name, raw) = part.split_once('=').unwrap_or((part, ""));
        if !KNOWN.contains(&name) {
            continue;
        }
        if !seen.insert(name) {
            report.error(
                path,
                "5.7",
                "duplicate_parameter",
                format!("Parameter `{name}` occurs more than one time."),
            );
            continue;
        }
        let decoded = match decode_id(raw) {
            Ok(decoded) => decoded,
            Err(error) => {
                bad_value(
                    report,
                    path,
                    name,
                    raw,
                    &format!("it is not encoded as 5.2 says: {error}"),
                );
                continue;
            }
        };
        match name {
            "parent" => parent = read_parent(&decoded, raw, path, document, report),
            "type" => {
                if is_type_or_limit_name(&decoded) {
                    query.node_type = Some(decoded);
                } else {
                    bad_value(report, path, name, raw, "expected a type name");
                }
            }
            "limit" => match whole_from_one(&decoded) {
                Some(number) => query.limit = Some(number),
                None => bad_value(report, path, name, raw, "expected a whole number from 1"),
            },
            _ => {}
        }
    }
    if !seen.contains("type") {
        report.error(
            path,
            "5.7",
            "missing_type",
            "Parameter `type` is mandatory, and the query does not have it.",
        );
    }
    if let (Some(node_type), Some(document)) = (&query.node_type, document) {
        check_type(node_type, parent.as_deref(), document, path, report);
    }
    query
}

fn bad_value(report: &mut Report, path: &JsonPath, name: &str, raw: &str, why: &str) {
    report.error(
        path,
        "5.7",
        "bad_parameter_value",
        format!(
            "Parameter `{name}` has the value {}, and {why}.",
            show(&json!(raw))
        ),
    );
}

fn whole_from_one(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>().ok().filter(|number| *number >= 1)
}

fn read_parent(
    decoded: &str,
    raw: &str,
    path: &JsonPath,
    document: Option<&ActionDocument>,
    report: &mut Report,
) -> Option<Vec<NodeRef>> {
    let nodes = match NodePath::parse_below_service(decoded) {
        Ok(nodes) => nodes,
        Err(error) => {
            bad_value(
                report,
                path,
                "parent",
                raw,
                &format!("it is not a path: {error}"),
            );
            return None;
        }
    };
    if let Some(document) = document {
        let mut all = vec![NodeRef::service(&document.server)];
        all.extend(nodes.iter().cloned());
        if let Ok(full) = NodePath::from_nodes(all)
            && let Err(error) = document.check_path(&full)
        {
            bad_value(
                report,
                path,
                "parent",
                raw,
                &format!("the path does not follow the document: {error}"),
            );
            return None;
        }
    }
    Some(nodes)
}

fn check_type(
    node_type: &str,
    parent: Option<&[NodeRef]>,
    document: &ActionDocument,
    path: &JsonPath,
    report: &mut Report,
) {
    let Some(declared) = document.resource_type(node_type) else {
        report.error(
            path,
            "5.7",
            "undeclared_type",
            format!("Type `{node_type}` is not a declared type of the document."),
        );
        return;
    };
    let expected = match parent {
        Some(nodes) => match nodes.last() {
            Some(last) => last.node_type.as_str(),
            None => return,
        },
        None => SERVICE,
    };
    if declared.parent != expected {
        report.error(
            path,
            "5.7",
            "wrong_parent_type",
            format!(
                "Type `{node_type}` has the parent `{}` in the document, but the query asks for the children of a node of type `{expected}`.",
                declared.parent
            ),
        );
    }
}

/// Check the answer against the query and the document.
pub(crate) fn check_answer(
    answer: &OptionsAnswer,
    query: &Query,
    document: Option<&ActionDocument>,
    base: &JsonPath,
) -> Vec<LintFinding> {
    let mut out = Vec::new();
    if let Some(limit) = query.limit
        && answer.items.len() as u64 > limit
    {
        out.push(LintFinding {
            severity: Severity::Error,
            path: base.key("items").to_string(),
            rule: "5.7",
            code: "answer_above_limit",
            message: format!(
                "The answer has {} items, and the parameter `limit` is {limit}.",
                answer.items.len()
            ),
        });
    }
    if let (Some(node_type), Some(document)) = (&query.node_type, document)
        && document.resource_type(node_type).is_some()
        && !document
            .resource_types
            .iter()
            .any(|t| &t.parent == node_type)
    {
        for (index, item) in answer.items.iter().enumerate() {
            if item.has_children {
                out.push(LintFinding {
                    severity: Severity::Warning,
                    path: base
                        .key("items")
                        .index(index)
                        .key("has_children")
                        .to_string(),
                    rule: "5.8",
                    code: "has_children_without_types",
                    message: format!(
                        "Member `has_children` is true, and the document declares no type below `{node_type}`."
                    ),
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn codes(text: &str) -> Vec<&'static str> {
        let mut report = Report::new();
        check_query(text, &JsonPath::root().key("query"), None, &mut report);
        report.findings().iter().map(|f| f.code).collect()
    }

    #[test]
    fn p_5_7_the_example_query_is_good() {
        assert!(codes("parent=host%3Aprod&type=database&q=test&limit=2").is_empty());
    }

    #[test]
    fn p_5_7_type_is_mandatory() {
        assert_eq!(codes("q=test"), vec!["missing_type"]);
        assert_eq!(codes(""), vec!["missing_type"]);
    }

    #[test]
    fn p_5_7_a_parameter_occurs_one_time() {
        assert_eq!(codes("type=a&type=b"), vec!["duplicate_parameter"]);
    }

    #[test]
    fn p_5_7_a_value_is_encoded_as_5_2_says() {
        assert_eq!(codes("type=a&q=a b"), vec!["bad_parameter_value"]);
        assert_eq!(codes("type=a&q=a%2fb"), vec!["bad_parameter_value"]);
        assert!(codes("type=a&q=a%20b").is_empty());
    }

    #[test]
    fn p_5_7_limit_is_a_whole_number_from_1() {
        for bad in ["0", "-1", "1.5", "x", "", "99999999999999999999999"] {
            assert_eq!(
                codes(&format!("type=a&limit={bad}")),
                vec!["bad_parameter_value"],
                "{bad}"
            );
        }
        assert!(codes("type=a&limit=1").is_empty());
    }

    #[test]
    fn p_5_7_an_unknown_parameter_is_ignored() {
        assert!(codes("type=a&color=red&color=blue").is_empty());
    }
}
