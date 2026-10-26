//! The check of the result of a step against its expectation.
//!
//! The function [`check`] reads what the runner saw. This is the answer, the
//! questions of the test PDP, and the request that reached the service
//! behind the edge. It returns one message for each failed check.

use procurauth_core::action_document::analyze_str as analyze_actions;
use procurauth_core::finding::{Report, Severity};
use procurauth_core::options::analyze_str as analyze_options;
use serde_json::{Map, Value, json};

use crate::http::{Headers, Reply, header_value};
use crate::model::{Expect, HeaderMatchers, Matcher, PointerMatchers, ValidAs};
use crate::testpdp::Question;
use crate::tokens::{Decoded, Verifier};
use crate::upstream::Received;

/// What the runner saw during a step.
pub(crate) struct Observed<'a> {
    /// The answer of the target. `None` when the request failed.
    pub(crate) reply: Option<&'a Reply>,
    /// The questions that the test PDP received during the step. `None` outside a PEP run.
    pub(crate) questions: Option<&'a [Question]>,
    /// The connections that the test PDP accepted since the start of the case.
    pub(crate) connections: Option<usize>,
    /// The requests that reached the service behind the edge. `None` outside an edge run.
    pub(crate) upstream: Option<&'a [Received]>,
    /// The checks of the identity token that the edge makes.
    pub(crate) verifier: Option<&'a Verifier>,
    /// The name of the header with the identity token.
    pub(crate) token_header: Option<&'a str>,
    /// The time, in seconds since the Unix epoch.
    pub(crate) now: u64,
}

/// The JSON form of a matcher, for a message.
pub(crate) fn matcher_json(matcher: &Matcher) -> Value {
    match matcher {
        Matcher::Equals(v) => json!({"equals": v}),
        Matcher::Absent => json!({"absent": true}),
        Matcher::Present => json!({"present": true}),
        Matcher::Regex(r) => json!({"regex": r}),
        Matcher::NotRegex(r) => json!({"not_regex": r}),
        Matcher::OneOf(items) => json!({"one_of": items}),
    }
}

fn pointer_json(matchers: &PointerMatchers) -> Value {
    Value::Object(
        matchers
            .iter()
            .map(|(k, m)| (k.clone(), matcher_json(m)))
            .collect::<Map<_, _>>(),
    )
}

/// Check the matchers of a JSON document, by JSON Pointer.
fn check_pointers(
    label: &str,
    matchers: &PointerMatchers,
    document: &Value,
    out: &mut Vec<String>,
) {
    for (pointer, matcher) in matchers {
        let found = document.pointer(pointer);
        if let Some(message) = matcher.verdict(&format!("{label} {pointer}"), found) {
            out.push(message);
        }
    }
}

fn check_headers(label: &str, matchers: &HeaderMatchers, headers: &Headers, out: &mut Vec<String>) {
    for (name, matcher) in matchers {
        let found = header_value(headers, name).map(Value::String);
        if let Some(message) = matcher.verdict(&format!("{label} {name}"), found.as_ref()) {
            out.push(message);
        }
    }
}

fn report_text(report: &Report, strict: bool) -> Option<String> {
    let bad: Vec<String> = report
        .findings()
        .iter()
        .filter(|f| f.severity == Severity::Error || strict)
        .map(|f| format!("{}: {}", f.path, f.message))
        .collect();
    (!bad.is_empty()).then(|| bad.join("; "))
}

fn check_valid_as(kind: ValidAs, text: &str, out: &mut Vec<String>) {
    let (name, strict, report) = match kind {
        ValidAs::ActionDocument | ValidAs::ActionDocumentNoWarning => (
            "an action document",
            kind == ValidAs::ActionDocumentNoWarning,
            analyze_actions(text).report,
        ),
        ValidAs::OptionsAnswer | ValidAs::OptionsAnswerNoWarning => (
            "an answer of the options route",
            kind == ValidAs::OptionsAnswerNoWarning,
            analyze_options(text).1,
        ),
    };
    if let Some(problems) = report_text(&report, strict) {
        out.push(format!(
            "the body must be {name}{}, found findings: {problems}",
            if strict { " with no warning" } else { "" }
        ));
    }
}

fn question_matches(
    entry_json: &PointerMatchers,
    entry_headers: &HeaderMatchers,
    q: &Question,
) -> bool {
    entry_json
        .iter()
        .all(|(pointer, m)| m.check(q.json.pointer(pointer)))
        && entry_headers
            .iter()
            .all(|(name, m)| m.check(header_value(&q.headers, name).map(Value::String).as_ref()))
}

fn check_upstream(
    expect: &crate::model::UpstreamExpect,
    observed: &Observed<'_>,
    out: &mut Vec<String>,
) {
    let Some(received) = observed.upstream else {
        out.push("the step expects an upstream request, and this run has no upstream".to_owned());
        return;
    };
    if let Some(count) = &expect.count
        && let Some(message) = count.verdict(
            "requests that reached the service",
            Some(&json!(received.len())),
        )
    {
        out.push(message);
    }
    let needs_request = !expect.headers.is_empty()
        || !expect.token_header.is_empty()
        || !expect.token_claims.is_empty();
    if !needs_request {
        return;
    }
    let Some(first) = received.first() else {
        out.push(
            "no request reached the service, so its headers and its token cannot be checked"
                .to_owned(),
        );
        return;
    };
    check_headers("upstream header", &expect.headers, &first.headers, out);
    if expect.token_header.is_empty() && expect.token_claims.is_empty() {
        return;
    }
    let (Some(verifier), Some(token_header)) = (observed.verifier, observed.token_header) else {
        out.push("the run has no key set to check the identity token".to_owned());
        return;
    };
    let Some(token) = header_value(&first.headers, token_header) else {
        out.push(format!(
            "the request that reached the service has no header {token_header}, and the identity token is absent"
        ));
        return;
    };
    match verifier.check(&token, observed.now) {
        Ok(Decoded { header, claims, .. }) => {
            check_pointers("token header", &expect.token_header, &header, out);
            check_pointers("token claims", &expect.token_claims, &claims, out);
        }
        Err(why) => out.push(format!(
            "the identity token in the header {token_header} is not good: {why}"
        )),
    }
}

/// Check the expectation of a step. The expectation has no variable left.
pub(crate) fn check(expect: &Expect, observed: &Observed<'_>) -> Vec<String> {
    let mut out = Vec::new();
    let needs_reply = expect.status.is_some()
        || !expect.headers.is_empty()
        || expect.body_text.is_some()
        || !expect.json.is_empty()
        || expect.valid_as.is_some();
    match observed.reply {
        None => {
            if needs_reply {
                out.push("the request failed, so the answer cannot be checked".to_owned());
            }
        }
        Some(reply) => {
            if let Some(matcher) = &expect.status
                && let Some(message) = matcher.verdict("status", Some(&json!(reply.status)))
            {
                out.push(message);
            }
            check_headers("header", &expect.headers, &reply.headers, &mut out);
            let text = reply.text();
            if let Some(matcher) = &expect.body_text
                && let Some(message) = matcher.verdict("body", Some(&Value::String(text.clone())))
            {
                out.push(message);
            }
            if !expect.json.is_empty() {
                match serde_json::from_slice::<Value>(&reply.body) {
                    Ok(document) => check_pointers("json", &expect.json, &document, &mut out),
                    Err(why) => out.push(format!(
                        "the body must be JSON for the checks of `json`, found a body that is not JSON: {why}"
                    )),
                }
            }
            if let Some(kind) = expect.valid_as {
                check_valid_as(kind, &text, &mut out);
            }
        }
    }
    if let Some(matcher) = &expect.pdp_connections {
        match observed.connections {
            Some(count) => {
                if let Some(message) =
                    matcher.verdict("connections of the PDP", Some(&json!(count)))
                {
                    out.push(message);
                }
            }
            None => out
                .push("the step expects pdp_connections, and this run has no test PDP".to_owned()),
        }
    }
    if !expect.pdp_questions.is_empty() {
        match observed.questions {
            Some(questions) => {
                for entry in &expect.pdp_questions {
                    let count = questions
                        .iter()
                        .filter(|q| question_matches(&entry.json, &entry.headers, q))
                        .count();
                    let matcher = entry.count.clone().unwrap_or(Matcher::Equals(json!(1)));
                    let mut label = format!("questions that match {}", pointer_json(&entry.json));
                    if !entry.headers.is_empty() {
                        label.push_str(&format!(" with headers {}", pointer_json(&entry.headers)));
                    }
                    if let Some(message) = matcher.verdict(&label, Some(&json!(count))) {
                        out.push(message);
                    }
                }
            }
            None => {
                out.push("the step expects pdp_questions, and this run has no test PDP".to_owned())
            }
        }
    }
    if let Some(upstream) = &expect.upstream {
        check_upstream(upstream, observed, &mut out);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Expect, QuestionExpect, UpstreamExpect};
    use std::collections::BTreeMap;

    fn expect() -> Expect {
        Expect {
            status: None,
            headers: BTreeMap::new(),
            body_text: None,
            json: BTreeMap::new(),
            valid_as: None,
            pdp_connections: None,
            pdp_questions: Vec::new(),
            upstream: None,
        }
    }

    fn reply(status: u16, headers: &[(&str, &str)], body: &str) -> Reply {
        Reply {
            status,
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            body: body.as_bytes().to_vec(),
        }
    }

    fn observed(reply: Option<&Reply>) -> Observed<'_> {
        Observed {
            reply,
            questions: None,
            connections: None,
            upstream: None,
            verifier: None,
            token_header: None,
            now: 0,
        }
    }

    fn question(json: Value, headers: &[(&str, &str)]) -> Question {
        Question {
            headers: headers
                .iter()
                .map(|(n, v)| ((*n).to_owned(), (*v).to_owned()))
                .collect(),
            json,
        }
    }

    #[test]
    fn the_status_the_headers_and_the_body_are_checked() {
        let mut e = expect();
        e.status = Some(Matcher::Equals(json!(401)));
        e.headers
            .insert("www-authenticate".into(), Matcher::Regex("^Bearer".into()));
        e.headers.insert("Location".into(), Matcher::Absent);
        e.body_text = Some(Matcher::Equals(json!("")));
        let ok = reply(401, &[("WWW-Authenticate", "Bearer realm=\"x\"")], "");
        assert!(check(&e, &observed(Some(&ok))).is_empty());
        let bad = reply(200, &[("Location", "/x")], "hi");
        let out = check(&e, &observed(Some(&bad)));
        assert_eq!(out.len(), 5, "{out:?}");
        assert!(
            out[0].starts_with("status: expected 401, found 200"),
            "{out:?}"
        );
    }

    #[test]
    fn a_failed_request_fails_each_check_of_the_answer_once() {
        let mut e = expect();
        e.status = Some(Matcher::Equals(json!(200)));
        e.body_text = Some(Matcher::Present);
        let out = check(&e, &observed(None));
        assert_eq!(
            out,
            vec!["the request failed, so the answer cannot be checked"]
        );
    }

    #[test]
    fn the_members_of_a_json_body_are_checked_by_pointer() {
        let mut e = expect();
        e.json
            .insert("/error/code".into(), Matcher::Equals(json!(-32020)));
        e.json.insert("".into(), Matcher::Present);
        e.json.insert("/x".into(), Matcher::Absent);
        let r = reply(400, &[], r#"{"error":{"code":-32020}}"#);
        assert!(check(&e, &observed(Some(&r))).is_empty());
        let r = reply(400, &[], r#"{"error":{"code":1},"x":null}"#);
        assert_eq!(check(&e, &observed(Some(&r))).len(), 2);
        let r = reply(400, &[], "not json");
        assert!(check(&e, &observed(Some(&r)))[0].contains("not JSON"));
    }

    #[test]
    fn a_valid_action_document_passes_valid_as() {
        let doc = r#"{"server":"s","resource_types":[],"actions":[{"name":"data.read","resource_types":["service"],"description":"Read."}]}"#;
        let mut e = expect();
        e.valid_as = Some(ValidAs::ActionDocument);
        assert!(check(&e, &observed(Some(&reply(200, &[], doc)))).is_empty());
        let out = check(&e, &observed(Some(&reply(200, &[], "{\"server\": 5}"))));
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("an action document"), "{out:?}");
    }

    #[test]
    fn the_suffix_no_warning_needs_a_report_with_no_warning() {
        // An unknown member is a warning for the reader of the action document.
        let doc = r#"{"server":"s","resource_types":[],"actions":[],"x_extra":1}"#;
        let mut e = expect();
        e.valid_as = Some(ValidAs::ActionDocument);
        assert!(check(&e, &observed(Some(&reply(200, &[], doc)))).is_empty());
        e.valid_as = Some(ValidAs::ActionDocumentNoWarning);
        assert_eq!(check(&e, &observed(Some(&reply(200, &[], doc)))).len(), 1);
    }

    #[test]
    fn an_options_answer_is_checked_with_the_reader_of_the_core() {
        let mut e = expect();
        e.valid_as = Some(ValidAs::OptionsAnswer);
        let good = r#"{"items":[{"id":"a","label":"A","has_children":false}],"next":null}"#;
        assert!(check(&e, &observed(Some(&reply(200, &[], good)))).is_empty());
        assert_eq!(check(&e, &observed(Some(&reply(200, &[], "{}")))).len(), 1);
    }

    #[test]
    fn the_questions_are_counted_for_each_entry() {
        let questions = vec![
            question(
                json!({"context": {"usage": {"units": 1}}, "subject": {"id": "a"}}),
                &[("Authorization", "Bearer x")],
            ),
            question(json!({"subject": {"id": "a"}}), &[]),
        ];
        let mut with_usage = BTreeMap::new();
        with_usage.insert("/context/usage".to_owned(), Matcher::Present);
        let mut e = expect();
        e.pdp_questions.push(QuestionExpect {
            json: with_usage.clone(),
            headers: BTreeMap::new(),
            count: None,
        });
        e.pdp_questions.push(QuestionExpect {
            json: BTreeMap::new(),
            headers: BTreeMap::new(),
            count: Some(Matcher::Equals(json!(2))),
        });
        let mut auth = BTreeMap::new();
        auth.insert(
            "authorization".to_owned(),
            Matcher::Regex("^Bearer .+$".into()),
        );
        e.pdp_questions.push(QuestionExpect {
            json: BTreeMap::new(),
            headers: auth,
            count: Some(Matcher::Equals(json!(0))),
        });
        let mut o = observed(None);
        o.questions = Some(&questions);
        let out = check(&e, &o);
        // The third entry finds one question with a credential, and expects none.
        assert_eq!(out.len(), 1, "{out:?}");
        assert!(out[0].contains("expected 0, found 1"), "{out:?}");
        assert!(out[0].contains("with headers"), "{out:?}");
    }

    #[test]
    fn the_connections_of_the_pdp_are_checked() {
        let mut e = expect();
        e.pdp_connections = Some(Matcher::OneOf(vec![json!(1), json!(2)]));
        let mut o = observed(None);
        o.connections = Some(4);
        assert_eq!(check(&e, &o).len(), 1);
        o.connections = Some(2);
        assert!(check(&e, &o).is_empty());
    }

    #[test]
    fn an_upstream_count_is_checked_without_a_request() {
        let mut e = expect();
        e.upstream = Some(UpstreamExpect {
            count: Some(Matcher::Equals(json!(0))),
            headers: BTreeMap::new(),
            token_header: BTreeMap::new(),
            token_claims: BTreeMap::new(),
        });
        let mut o = observed(None);
        let none: Vec<Received> = Vec::new();
        o.upstream = Some(&none);
        assert!(check(&e, &o).is_empty());
        let one = vec![Received { headers: vec![] }];
        o.upstream = Some(&one);
        assert_eq!(check(&e, &o).len(), 1);
    }

    #[test]
    fn upstream_headers_are_checked_on_the_first_request() {
        let mut headers = BTreeMap::new();
        headers.insert("Authorization".to_owned(), Matcher::Absent);
        let mut e = expect();
        e.upstream = Some(UpstreamExpect {
            count: None,
            headers,
            token_header: BTreeMap::new(),
            token_claims: BTreeMap::new(),
        });
        let mut o = observed(None);
        let clean = vec![Received {
            headers: vec![("X".into(), "1".into())],
        }];
        o.upstream = Some(&clean);
        assert!(check(&e, &o).is_empty());
        let leaky = vec![Received {
            headers: vec![("authorization".into(), "Bearer k".into())],
        }];
        o.upstream = Some(&leaky);
        assert_eq!(check(&e, &o).len(), 1);
        let nothing: Vec<Received> = Vec::new();
        o.upstream = Some(&nothing);
        assert!(check(&e, &o)[0].contains("no request reached"));
    }
}
