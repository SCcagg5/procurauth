//! The checks of the three inputs: the action document, the file of grants and the options file.
//!
//! The core crate reads the documents and gives the findings. This module adds
//! the checks that need two inputs, and the checks of the file formats of the tool.

use std::collections::HashSet;

use procurauth_core::action_document::{
    ActionDocument, LimitKind, analyze_str as analyze_document,
};
use procurauth_core::finding::{Finding, JsonPath, Report, Severity};
use procurauth_core::grants::{ServiceLookup, read_grant};
use procurauth_core::json::{JsonError, parse_str};
use procurauth_core::limits::LimitValue;
use procurauth_core::names::ACCESS_ACTION;
use procurauth_core::options::{
    CALLER_MIN_BYTES, OptionsAnswer, analyze_str as analyze_options_text,
    analyze_value as analyze_answer,
};
use procurauth_core::read::{Obj, Unknown};
use serde_json::Value;

use crate::query;

/// One finding of the tool. The path is text, because a finding in an envelope has a moved path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LintFinding {
    /// Error or warning.
    pub severity: Severity,
    /// The JSON path of the member, for example `$.limits[0].min`.
    pub path: String,
    /// The paragraph of the protocol.
    pub rule: &'static str,
    /// The stable code of the finding.
    pub code: &'static str,
    /// The full message, with the names and the values.
    pub message: String,
}

impl From<Finding> for LintFinding {
    fn from(finding: Finding) -> Self {
        Self {
            severity: finding.severity,
            path: finding.path.to_string(),
            rule: finding.rule,
            code: finding.code,
            message: finding.message,
        }
    }
}

fn convert(report: Report) -> Vec<LintFinding> {
    report.into_findings().into_iter().map(Into::into).collect()
}

/// Move the findings of an inner document under `base`. The path `$.items[0]` becomes `$.answer.items[0]`.
fn rebase(findings: Vec<LintFinding>, base: &JsonPath) -> Vec<LintFinding> {
    findings
        .into_iter()
        .map(|mut finding| {
            let rest = finding.path.strip_prefix('$').unwrap_or(&finding.path);
            finding.path = format!("{base}{rest}");
            finding
        })
        .collect()
}

fn bad_json(report: &mut Report, rule: &'static str, error: &JsonError) {
    report.error(
        &error.path,
        rule,
        "bad_json",
        format!(
            "The text is not valid JSON, line {}, column {}: {}.",
            error.line, error.column, error.kind
        ),
    );
}

/// Check an action document. Give the typed document when it has no error.
pub fn check_document(text: &str) -> (Option<ActionDocument>, Vec<LintFinding>) {
    let analysis = analyze_document(text);
    let mut report = analysis.report;
    if let Some(document) = &analysis.document {
        budget_names(document, &mut report);
    }
    (analysis.document, convert(report))
}

/// The words that give a window or a unit to a name (6.1).
const WINDOW_WORDS: [&str; 9] = [
    "per", "second", "seconds", "minute", "minutes", "hour", "hours", "day", "days",
];

/// A budget name has no unit and no window (6.1).
fn budget_names(document: &ActionDocument, report: &mut Report) {
    for (index, limit) in document.limits.iter().enumerate() {
        if limit.kind == LimitKind::Budget
            && limit
                .name
                .split('_')
                .any(|part| WINDOW_WORDS.contains(&part))
        {
            report.warning(
                &JsonPath::root().key("limits").index(index).key("name"),
                "6.1",
                "budget_name_window",
                format!(
                    "Budget name `{}` has a window or a unit. A budget name is a plural noun, with no unit and no window.",
                    limit.name
                ),
            );
        }
    }
}

/// Check a file of grants against the document.
/// Without a good document, the function checks the form of the values only.
pub fn check_grants(text: &str, document: Option<&ActionDocument>) -> Vec<LintFinding> {
    let mut report = Report::new();
    let root = JsonPath::root();
    let value = match parse_str(text) {
        Ok(value) => value,
        Err(error) => {
            bad_json(&mut report, "3.5", &error);
            return convert(report);
        }
    };
    let Some(mut top) = Obj::new(&value, &root, "3.5", Unknown::Error, &mut report) else {
        return convert(report);
    };
    let list = top.array("grants", &mut report);
    top.finish(&mut report);
    let Some(items) = list else {
        return convert(report);
    };
    let lookup = |id: &str| match document {
        Some(found) if found.server == id => ServiceLookup::Document(found),
        Some(_) => ServiceLookup::Unknown,
        None => ServiceLookup::NoDocument,
    };
    let mut budgets: HashSet<String> = HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let path = root.key("grants").index(index);
        let Some(grant) = read_grant(item, &path, &lookup, &mut report) else {
            continue;
        };
        if grant.action != ACCESS_ACTION || grant.resource.depth() != 0 {
            continue;
        }
        for (name, value) in &grant.limits {
            if matches!(value, LimitValue::Budget(_)) && !budgets.insert(name.clone()) {
                report.warning(
                    &path.key("limits").key(name),
                    "8.3",
                    "duplicate_budget_value",
                    format!(
                        "Budget `{name}` has a value in an earlier grant of `access`. A subject has one value for each budget."
                    ),
                );
            }
        }
    }
    convert(report)
}

/// Check an options file: an answer of the route, or an answer with its query.
pub fn check_options(text: &str, document: Option<&ActionDocument>) -> Vec<LintFinding> {
    let value = match parse_str(text) {
        Ok(value) => value,
        Err(error) => {
            let mut report = Report::new();
            bad_json(&mut report, "5.8", &error);
            return convert(report);
        }
    };
    if value.get("answer").is_some() {
        check_envelope(&value, document)
    } else {
        let (answer, report) = analyze_options_text(text);
        let mut findings = convert(report);
        if let Some(answer) = &answer {
            findings.extend(duplicate_ids(answer, &JsonPath::root()));
        }
        findings
    }
}

fn check_envelope(value: &Value, document: Option<&ActionDocument>) -> Vec<LintFinding> {
    let mut report = Report::new();
    let root = JsonPath::root();
    let Some(mut top) = Obj::new(value, &root, "5.8", Unknown::Ignore, &mut report) else {
        return convert(report);
    };
    let query_text = top.string_opt("query", &mut report);
    let answer_value = top.optional("answer");
    for key in value
        .as_object()
        .map(|map| map.keys())
        .into_iter()
        .flatten()
    {
        if key != "query" && key != "answer" {
            report.error(
                &root.key(key),
                "5.8",
                "unknown_envelope_member",
                format!("Member `{key}` is not known here. The members are `query` and `answer`."),
            );
        }
    }
    let mut findings = convert(report);
    let answer_path = root.key("answer");
    let Some(answer_value) = answer_value else {
        return findings;
    };
    let (answer, answer_report) = analyze_answer(answer_value);
    findings.extend(rebase(convert(answer_report), &answer_path));
    if answer_value.to_string().len() > CALLER_MIN_BYTES {
        findings.push(LintFinding {
            severity: Severity::Warning,
            path: answer_path.to_string(),
            rule: "5.8",
            code: "above_caller_minimum",
            message: format!(
                "The answer has {} bytes. A caller must accept {CALLER_MIN_BYTES} bytes.",
                answer_value.to_string().len()
            ),
        });
    }
    let mut report = Report::new();
    let parsed =
        query_text.map(|text| query::check_query(text, &root.key("query"), document, &mut report));
    findings.extend(convert(report));
    if let Some(answer) = &answer {
        findings.extend(duplicate_ids(answer, &answer_path));
        if let Some(parsed) = &parsed {
            findings.extend(query::check_answer(answer, parsed, document, &answer_path));
        }
    }
    findings
}

/// Two items of one answer have the same id (4.2).
fn duplicate_ids(answer: &OptionsAnswer, base: &JsonPath) -> Vec<LintFinding> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for (index, item) in answer.items.iter().enumerate() {
        if !seen.insert(item.id.as_str()) {
            out.push(LintFinding {
                severity: Severity::Warning,
                path: base.key("items").index(index).key("id").to_string(),
                rule: "4.2",
                code: "duplicate_id",
                message: format!(
                    "Id {} occurs more than one time. An id is unique below its parent.",
                    serde_json::Value::String(item.id.clone())
                ),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_5_3_a_bad_text_gives_one_finding() {
        let (document, findings) = check_document("{");
        assert!(document.is_none());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "bad_json");
    }

    #[test]
    fn p_8_3_two_values_for_one_budget_are_a_warning() {
        let grant = r#"{"action": "access", "resource": "service:s", "limits": {"requests": [{"amount": 1, "window": "second"}]}}"#;
        let text = format!(r#"{{"grants": [{grant}, {grant}]}}"#);
        let findings = check_grants(&text, None);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, "duplicate_budget_value");
        assert_eq!(findings[0].path, "$.grants[1].limits.requests");
    }

    #[test]
    fn p_5_8_a_moved_path_starts_at_the_answer() {
        let findings = rebase(
            vec![LintFinding {
                severity: Severity::Error,
                path: "$.items[0]".to_owned(),
                rule: "5.8",
                code: "wrong_type",
                message: String::new(),
            }],
            &JsonPath::root().key("answer"),
        );
        assert_eq!(findings[0].path, "$.answer.items[0]");
    }
}
