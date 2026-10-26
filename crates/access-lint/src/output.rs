//! The output of the tool: text and JSON.

use std::fmt::Write as _;

use procurauth_core::finding::Severity;
use serde::Serialize;

use crate::check::LintFinding;
use crate::rules::{Scope, summary};

/// The result for one input.
#[derive(Clone, Debug)]
pub struct InputResult {
    /// The input that the findings are about.
    pub scope: Scope,
    /// The file or the URL, as the user gave it.
    pub source: String,
    /// The findings, in the order of the check.
    pub findings: Vec<LintFinding>,
}

impl InputResult {
    /// The number of errors.
    pub fn errors(&self) -> usize {
        self.count(Severity::Error)
    }

    /// The number of warnings.
    pub fn warnings(&self) -> usize {
        self.count(Severity::Warning)
    }

    fn count(&self, severity: Severity) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == severity)
            .count()
    }
}

/// True when no input has an error.
pub fn passes(results: &[InputResult]) -> bool {
    results.iter().all(|r| r.errors() == 0)
}

fn short(finding: &LintFinding) -> String {
    summary(finding.rule, finding.code)
        .map_or_else(|| finding.code.replace('_', " "), str::to_owned)
}

fn plural(count: usize, word: &str) -> String {
    if count == 1 {
        format!("{count} {word}")
    } else {
        format!("{count} {word}s")
    }
}

/// The text output. Each input has a head line and one line for each finding.
pub fn render_text(results: &[InputResult]) -> String {
    let mut out = String::new();
    for result in results {
        let (errors, warnings) = (result.errors(), result.warnings());
        let counts = match (errors, warnings) {
            (0, 0) => "no finding".to_owned(),
            (_, 0) => plural(errors, "error"),
            (0, _) => plural(warnings, "warning"),
            _ => format!(
                "{}, {}",
                plural(errors, "error"),
                plural(warnings, "warning")
            ),
        };
        let _ = writeln!(out, "{}: {counts}", result.source);
        let path_width = result
            .findings
            .iter()
            .map(|f| f.path.chars().count())
            .max()
            .unwrap_or(0);
        let rule_width = result
            .findings
            .iter()
            .map(|f| f.rule.len())
            .max()
            .unwrap_or(0);
        for finding in &result.findings {
            let mark = match finding.severity {
                Severity::Error => "",
                Severity::Warning => "warning: ",
            };
            let _ = writeln!(
                out,
                "  {:<path_width$}  rule {:<rule_width$}  {mark}{}",
                finding.path,
                finding.rule,
                short(finding),
            );
        }
    }
    out
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    severity: &'static str,
    path: &'a str,
    rule: &'a str,
    code: &'a str,
    summary: String,
    message: &'a str,
}

#[derive(Serialize)]
struct JsonInput<'a> {
    kind: &'static str,
    source: &'a str,
    errors: usize,
    warnings: usize,
    findings: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonOutput<'a> {
    tool: &'static str,
    version: &'static str,
    ok: bool,
    inputs: Vec<JsonInput<'a>>,
}

/// The JSON output, with two spaces of indent and a line end.
pub fn render_json(results: &[InputResult]) -> String {
    let inputs = results
        .iter()
        .map(|result| JsonInput {
            kind: result.scope.as_str(),
            source: &result.source,
            errors: result.errors(),
            warnings: result.warnings(),
            findings: result
                .findings
                .iter()
                .map(|f| JsonFinding {
                    severity: match f.severity {
                        Severity::Error => "error",
                        Severity::Warning => "warning",
                    },
                    path: &f.path,
                    rule: f.rule,
                    code: f.code,
                    summary: short(f),
                    message: &f.message,
                })
                .collect(),
        })
        .collect();
    let output = JsonOutput {
        tool: "access-lint",
        version: env!("CARGO_PKG_VERSION"),
        ok: passes(results),
        inputs,
    };
    let mut text = serde_json::to_string_pretty(&output).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(
        severity: Severity,
        path: &str,
        rule: &'static str,
        code: &'static str,
    ) -> LintFinding {
        LintFinding {
            severity,
            path: path.to_owned(),
            rule,
            code,
            message: "Message.".to_owned(),
        }
    }

    fn result(findings: Vec<LintFinding>) -> InputResult {
        InputResult {
            scope: Scope::Document,
            source: "actions.json".to_owned(),
            findings,
        }
    }

    #[test]
    fn p_5_2_the_text_of_the_site_example() {
        let text = render_text(&[result(vec![
            finding(
                Severity::Error,
                "$.actions[1].limits[2]",
                "5.2",
                "undeclared_limit",
            ),
            finding(Severity::Error, "$.limits[0].min", "6.1", "budget_with_min"),
        ])]);
        assert_eq!(
            text,
            "actions.json: 2 errors\n  $.actions[1].limits[2]  rule 5.2  undeclared limit\n  $.limits[0].min         rule 6.1  budget with \"min\"\n"
        );
    }

    #[test]
    fn p_5_3c_a_warning_has_a_mark_and_the_head_counts_it() {
        let text = render_text(&[result(vec![finding(
            Severity::Warning,
            "$.actions",
            "5.3c",
            "above_reader_minimum",
        )])]);
        assert_eq!(
            text,
            "actions.json: 1 warning\n  $.actions  rule 5.3c  warning: above the minimum of a reader\n"
        );
    }

    #[test]
    fn p_5_2_no_finding_has_one_line() {
        assert_eq!(render_text(&[result(vec![])]), "actions.json: no finding\n");
    }

    #[test]
    fn p_5_2_an_unknown_code_shows_its_words() {
        let text = render_text(&[result(vec![finding(
            Severity::Error,
            "$",
            "5.2",
            "odd_thing",
        )])]);
        assert!(text.contains("odd thing"));
    }

    #[test]
    fn p_5_2_the_json_output_has_the_counts() {
        let json = render_json(&[result(vec![finding(
            Severity::Error,
            "$",
            "5.2",
            "bad_server",
        )])]);
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["ok"], false);
        assert_eq!(value["inputs"][0]["errors"], 1);
        assert_eq!(
            value["inputs"][0]["findings"][0]["summary"],
            "bad id of the service"
        );
        assert!(json.ends_with("}\n"));
    }
}
