//! Findings: the errors and the warnings that a check reports.
//!
//! A finding names a place in a document (a JSON path), the number of the
//! rule that the document breaks, and a short message. The tools print
//! findings as text or as JSON.

use std::fmt;

use serde::{Serialize, Serializer};
use serde_json::Value;

/// A place in a JSON document, written as `$.actions[1].limits[2]`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct JsonPath(String);

impl JsonPath {
    /// The root of the document: `$`.
    pub fn root() -> Self {
        Self("$".to_owned())
    }

    /// The path of the member `name` of the object at this path.
    #[must_use]
    pub fn key(&self, name: &str) -> Self {
        let simple = !name.is_empty()
            && name
                .chars()
                .enumerate()
                .all(|(i, c)| c == '_' || c.is_ascii_alphabetic() || (i > 0 && c.is_ascii_digit()));
        if simple {
            Self(format!("{}.{name}", self.0))
        } else {
            let escaped = name.replace('\\', "\\\\").replace('"', "\\\"");
            Self(format!("{}[\"{escaped}\"]", self.0))
        }
    }

    /// The path of the item `index` of the array at this path.
    #[must_use]
    pub fn index(&self, index: usize) -> Self {
        Self(format!("{}[{index}]", self.0))
    }

    /// The path as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for JsonPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for JsonPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

/// How serious a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// The document is bad, or the check fails.
    Error,
    /// The document is good, but a rule of the protocol advises a change.
    Warning,
}

/// One result of a check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// Error or warning.
    pub severity: Severity,
    /// The place of the member that the finding is about.
    pub path: JsonPath,
    /// The number of the paragraph of the protocol, for example `5.2`.
    pub rule: &'static str,
    /// A stable name for the kind of finding, for example `undeclared_limit`.
    pub code: &'static str,
    /// A message in Simplified Technical English. It names the key and the value.
    pub message: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let label = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
        };
        write!(
            f,
            "{label}: {}: rule {}: {}",
            self.path, self.rule, self.message
        )
    }
}

/// A list of findings, filled by a check.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    findings: Vec<Finding>,
}

impl Report {
    /// An empty report.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an error.
    pub fn error(
        &mut self,
        path: &JsonPath,
        rule: &'static str,
        code: &'static str,
        message: impl Into<String>,
    ) {
        self.push(Severity::Error, path, rule, code, message.into());
    }

    /// Add a warning.
    pub fn warning(
        &mut self,
        path: &JsonPath,
        rule: &'static str,
        code: &'static str,
        message: impl Into<String>,
    ) {
        self.push(Severity::Warning, path, rule, code, message.into());
    }

    fn push(
        &mut self,
        severity: Severity,
        path: &JsonPath,
        rule: &'static str,
        code: &'static str,
        message: String,
    ) {
        self.findings.push(Finding {
            severity,
            path: path.clone(),
            rule,
            code,
            message,
        });
    }

    /// Add a finding that another check made.
    pub fn extend(&mut self, findings: impl IntoIterator<Item = Finding>) {
        self.findings.extend(findings);
    }

    /// The number of errors in the report.
    pub fn error_count(&self) -> usize {
        self.findings
            .iter()
            .filter(|finding| finding.severity == Severity::Error)
            .count()
    }

    /// True when the report has at least one error.
    pub fn has_errors(&self) -> bool {
        self.findings
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    }

    /// The findings, in the order of the check.
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }

    /// Take the findings out of the report.
    pub fn into_findings(self) -> Vec<Finding> {
        self.findings
    }
}

/// A short text for a value in a message: compact JSON, cut at 60 characters.
pub fn show(value: &Value) -> String {
    let text = value.to_string();
    if text.chars().count() > 60 {
        let cut: String = text.chars().take(57).collect();
        format!("{cut}...")
    } else {
        text
    }
}

/// The JSON type of a value, as a word for a message.
pub fn type_word(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "a boolean",
        Value::Number(_) => "a number",
        Value::String(_) => "a string",
        Value::Array(_) => "an array",
        Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_key_and_index() {
        let path = JsonPath::root().key("actions").index(1).key("limits");
        assert_eq!(path.as_str(), "$.actions[1].limits");
    }

    #[test]
    fn path_key_with_odd_characters_is_quoted() {
        let path = JsonPath::root().key("a b").key("c\"d");
        assert_eq!(path.as_str(), "$[\"a b\"][\"c\\\"d\"]");
    }

    #[test]
    fn show_cuts_long_values() {
        let long = Value::String("x".repeat(200));
        assert!(show(&long).ends_with("..."));
        assert!(show(&long).chars().count() <= 60);
    }

    #[test]
    fn report_tells_errors_from_warnings() {
        let mut report = Report::new();
        report.warning(&JsonPath::root(), "5.3c", "w", "A warning.");
        assert!(!report.has_errors());
        report.error(&JsonPath::root(), "5.2", "e", "An error.");
        assert!(report.has_errors());
        assert_eq!(report.findings().len(), 2);
    }
}
