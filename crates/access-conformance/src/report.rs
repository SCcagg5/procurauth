//! The result of a run, and its two forms: text and JSON.
//!
//! The text form has one line for each case and one summary line. The JSON
//! form is one document. The schema is `schemas/conformance-report.schema.json`.

use serde_json::{Value, json};

use crate::model::{Case, Requirement};

/// The result of one case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    /// Every step passed.
    Pass,
    /// A step failed, and the rule is a MUST.
    Fail,
    /// The case does not apply.
    Skip,
    /// A step failed, and the rule is a SHOULD.
    Warn,
}

impl Status {
    /// The word in the output.
    pub(crate) fn word(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skip => "skip",
            Self::Warn => "warn",
        }
    }
}

/// One failed check.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Failure {
    /// The name of the step, or its number.
    pub(crate) step: Option<String>,
    /// What went wrong, with the expected value and the value found.
    pub(crate) message: String,
}

/// The result of a case, with the data that the output needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CaseResult {
    /// The id.
    pub(crate) id: String,
    /// The title.
    pub(crate) title: String,
    /// The paragraphs.
    pub(crate) paragraphs: Vec<String>,
    /// The level of the rule.
    pub(crate) requirement: Requirement,
    /// The status.
    pub(crate) status: Status,
    /// Why the runner skipped the case.
    pub(crate) reason: Option<String>,
    /// The failed checks.
    pub(crate) failures: Vec<Failure>,
}

impl CaseResult {
    /// A result with no failure, for a case.
    pub(crate) fn of(case: &Case, status: Status) -> Self {
        Self {
            id: case.id.clone(),
            title: case.title.clone(),
            paragraphs: case.paragraphs.clone(),
            requirement: case.requirement,
            status,
            reason: None,
            failures: Vec::new(),
        }
    }

    /// A skipped case.
    pub(crate) fn skipped(case: &Case, reason: impl Into<String>) -> Self {
        let mut result = Self::of(case, Status::Skip);
        result.reason = Some(reason.into());
        result
    }

    /// The result of a case from its failures: a pass when there is none.
    pub(crate) fn from_failures(case: &Case, failures: Vec<Failure>) -> Self {
        if failures.is_empty() {
            Self::of(case, Status::Pass)
        } else {
            Self::failed(case, failures)
        }
    }

    /// A case with failures. A failure of a SHOULD is a warning.
    pub(crate) fn failed(case: &Case, failures: Vec<Failure>) -> Self {
        let status = match case.requirement {
            Requirement::Must => Status::Fail,
            Requirement::Should => Status::Warn,
        };
        let mut result = Self::of(case, status);
        result.failures = failures;
        result
    }
}

/// The counts of a run.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Summary {
    /// The cases that the run lists.
    pub(crate) total: usize,
    /// The cases that passed.
    pub(crate) passed: usize,
    /// The cases that failed.
    pub(crate) failed: usize,
    /// The cases that the run skipped.
    pub(crate) skipped: usize,
    /// The cases with a failed SHOULD.
    pub(crate) warned: usize,
}

impl Summary {
    /// Count the results.
    pub(crate) fn of(results: &[CaseResult]) -> Self {
        let mut summary = Self {
            total: results.len(),
            ..Self::default()
        };
        for result in results {
            match result.status {
                Status::Pass => summary.passed += 1,
                Status::Fail => summary.failed += 1,
                Status::Skip => summary.skipped += 1,
                Status::Warn => summary.warned += 1,
            }
        }
        summary
    }

    /// The summary line. It names the warnings only when there are some.
    pub(crate) fn line(&self) -> String {
        let mut line = format!(
            "{} cases: {} passed, {} failed, {} skipped",
            self.total, self.passed, self.failed, self.skipped
        );
        if self.warned > 0 {
            line.push_str(&format!(", {} warned", self.warned));
        }
        line
    }

    /// The exit code: 1 when a case failed, else 0. A warning and a skip do not count.
    pub(crate) fn exit_code(&self) -> u8 {
        u8::from(self.failed > 0)
    }
}

fn one_line(text: &str) -> String {
    text.chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

/// The text at the end of the line of a case.
fn detail(result: &CaseResult) -> String {
    match result.status {
        Status::Pass => one_line(&result.title),
        Status::Skip => one_line(
            result
                .reason
                .as_deref()
                .unwrap_or("the case does not apply"),
        ),
        Status::Fail | Status::Warn => {
            let Some(first) = result.failures.first() else {
                return one_line(&result.title);
            };
            let mut text = match &first.step {
                Some(step) => format!("step \"{step}\": {}", first.message),
                None => first.message.clone(),
            };
            let more = result.failures.len() - 1;
            if more > 0 {
                text.push_str(&format!(" (and {more} more)"));
            }
            one_line(&text)
        }
    }
}

/// The text form: one line for each case, then the summary line.
pub(crate) fn render_text(results: &[CaseResult]) -> String {
    let id_width = results.iter().map(|r| r.id.len()).max().unwrap_or(0);
    let paragraphs: Vec<String> = results.iter().map(|r| r.paragraphs.join(",")).collect();
    let paragraph_width = paragraphs.iter().map(String::len).max().unwrap_or(0);
    let mut out = String::new();
    for (result, paragraph) in results.iter().zip(&paragraphs) {
        out.push_str(&format!(
            "{:<id_width$}  {}  {:<paragraph_width$}  {}\n",
            result.id,
            result.status.word(),
            paragraph,
            detail(result),
        ));
    }
    out.push_str(&Summary::of(results).line());
    out.push('\n');
    out
}

/// The JSON form: one document.
pub(crate) fn render_json(
    role: &str,
    target: Option<&str>,
    version: &str,
    results: &[CaseResult],
) -> String {
    let summary = Summary::of(results);
    let cases: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "title": r.title,
                "paragraphs": r.paragraphs,
                "requirement": r.requirement.word(),
                "status": r.status.word(),
                "reason": r.reason,
                "failures": r.failures.iter().map(|f| json!({"step": f.step, "message": f.message})).collect::<Vec<_>>(),
            })
        })
        .collect();
    let document = json!({
        "tool": "access-conformance",
        "version": version,
        "role": role,
        "target": target,
        "summary": {
            "cases": summary.total,
            "passed": summary.passed,
            "failed": summary.failed,
            "skipped": summary.skipped,
            "warned": summary.warned,
        },
        "cases": cases,
    });
    let mut text = serde_json::to_string_pretty(&document).unwrap_or_default();
    text.push('\n');
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(id: &str, status: Status, paragraphs: &[&str], text: &str) -> CaseResult {
        CaseResult {
            id: id.to_owned(),
            title: text.to_owned(),
            paragraphs: paragraphs.iter().map(|p| (*p).to_owned()).collect(),
            requirement: Requirement::Must,
            status,
            reason: (status == Status::Skip).then(|| text.to_owned()),
            failures: if matches!(status, Status::Fail | Status::Warn) {
                vec![Failure {
                    step: Some("Use".to_owned()),
                    message: text.to_owned(),
                }]
            } else {
                Vec::new()
            },
        }
    }

    #[test]
    fn the_text_form_has_a_line_for_each_case_and_a_summary() {
        let results = vec![
            result("U01", Status::Pass, &["3.3"], "subject type user"),
            result(
                "U04",
                Status::Fail,
                &["10.3"],
                "status: expected 429, found 403",
            ),
            result(
                "U05",
                Status::Skip,
                &["5.6"],
                "the service has no options route",
            ),
        ];
        assert_eq!(
            render_text(&results),
            "U01  pass  3.3   subject type user\n\
             U04  fail  10.3  step \"Use\": status: expected 429, found 403\n\
             U05  skip  5.6   the service has no options route\n\
             3 cases: 1 passed, 1 failed, 1 skipped\n"
        );
    }

    #[test]
    fn the_summary_names_the_warnings_only_when_there_are_some() {
        let mut warned = result("U69", Status::Warn, &["10.7"], "x");
        warned.requirement = Requirement::Should;
        let results = vec![result("U01", Status::Pass, &["3.3"], "t"), warned];
        let summary = Summary::of(&results);
        assert_eq!(
            summary.line(),
            "2 cases: 1 passed, 0 failed, 0 skipped, 1 warned"
        );
        assert_eq!(summary.exit_code(), 0);
        assert_eq!(
            Summary::of(&results[..1]).line(),
            "1 cases: 1 passed, 0 failed, 0 skipped"
        );
    }

    #[test]
    fn a_failed_case_gives_the_exit_code_1() {
        let results = vec![result("U04", Status::Fail, &["10.3"], "x")];
        assert_eq!(Summary::of(&results).exit_code(), 1);
    }

    #[test]
    fn a_failure_line_counts_the_other_failures_and_has_one_line() {
        let mut r = result("U04", Status::Fail, &["10.3"], "a\nb");
        r.failures.push(Failure {
            step: None,
            message: "second".to_owned(),
        });
        let text = render_text(&[r]);
        assert!(
            text.starts_with("U04  fail  10.3  step \"Use\": a b (and 1 more)\n"),
            "{text}"
        );
        assert_eq!(text.lines().count(), 2);
    }

    #[test]
    fn the_json_form_is_one_document() {
        let results = vec![
            result("U01", Status::Pass, &["3.3", "9.6"], "t"),
            result("U05", Status::Skip, &["5.6"], "no route"),
        ];
        let text = render_json("pep", Some("http://127.0.0.1:1"), "1.0.0", &results);
        let value: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["summary"]["cases"], 2);
        assert_eq!(value["cases"][1]["reason"], "no route");
        assert_eq!(value["cases"][0]["reason"], Value::Null);
        assert_eq!(value["role"], "pep");
        assert!(text.ends_with("}\n"));
    }
}
