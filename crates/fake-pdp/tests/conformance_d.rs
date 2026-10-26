//! Run the cases of the series D of `conformance/D/` against the server over HTTP.
//!
//! The runner is local and small. It reads the case as JSON and uses the
//! matchers of `conformance/README.md`. The real runner is `access-conformance`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::PathBuf;

use common::*;
use procurauth_core::json::parse_str;
use serde_json::{Value, json};

fn conformance_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../conformance")
}

/// The check of one matcher against a value, with the vocabulary of the data model.
fn matches(matcher: &Value, actual: Option<&Value>) -> bool {
    let (kind, expected) = matcher.as_object().unwrap().iter().next().unwrap();
    match kind.as_str() {
        "equals" => actual == Some(expected),
        "absent" => actual.is_none(),
        "present" => actual.is_some(),
        "one_of" => actual.is_some_and(|a| expected.as_array().unwrap().contains(a)),
        "regex" => {
            let text = match actual {
                Some(Value::String(s)) => s.clone(),
                Some(other) => other.to_string(),
                None => return false,
            };
            regex::Regex::new(expected.as_str().unwrap())
                .unwrap()
                .is_match(&text)
        }
        other => panic!("unknown matcher {other}"),
    }
}

/// The data of the PDP for a case: the directory, with the clock and the counters of `given`.
fn data_of(given: &Value) -> Value {
    let mut data = match &given["directory"] {
        Value::String(name) => {
            let text =
                fs::read_to_string(conformance_dir().join("directories").join(name)).unwrap();
            parse_str(&text).unwrap()
        }
        Value::Object(_) => given["directory"].clone(),
        other => panic!("the case has no directory: {other}"),
    };
    if let Some(clock) = given.get("clock") {
        data["clock"] = clock.clone();
    }
    if let Some(counters) = given.get("counters").and_then(Value::as_array) {
        let mut merged: Vec<Value> = data
            .get("counters")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        for counter in counters {
            merged.retain(|c| {
                !(c["subject"] == counter["subject"]
                    && c["limit"] == counter["limit"]
                    && c["window"] == counter["window"])
            });
            merged.push(counter.clone());
        }
        data["counters"] = Value::Array(merged);
    }
    data
}

fn run_case(path: &std::path::Path) -> usize {
    let case = parse_str(&fs::read_to_string(path).unwrap()).unwrap();
    let id = case["id"].as_str().unwrap().to_owned();
    let server = start(&data_of(&case["given"]));
    let mut client = Client::connect(server.local_addr());
    let mut steps = 0;
    for step in case["steps"].as_array().unwrap() {
        let name = step["name"].as_str().unwrap_or("step");
        let request = &step["request"];
        let (method, target) = match request["endpoint"].as_str() {
            Some("evaluation") => ("POST".to_owned(), EVALUATION.to_owned()),
            Some("evaluations") => ("POST".to_owned(), EVALUATIONS.to_owned()),
            Some("metadata") => (
                "GET".to_owned(),
                "/.well-known/authzen-configuration".to_owned(),
            ),
            Some(other) => panic!("{id}: unknown endpoint {other}"),
            None => (
                request["method"].as_str().unwrap().to_owned(),
                request["path"].as_str().unwrap().to_owned(),
            ),
        };
        let mut headers: Vec<(String, String)> = Vec::new();
        if method == "POST" {
            headers.push(("Content-Type".to_owned(), "application/json".to_owned()));
        }
        if let Some(extra) = request.get("headers").and_then(Value::as_object) {
            for (name, value) in extra {
                headers.push((name.clone(), value.as_str().unwrap().to_owned()));
            }
        }
        let body: Option<Vec<u8>> = match (request.get("body"), request.get("body_text")) {
            (Some(body), _) => Some(body.to_string().into_bytes()),
            (None, Some(text)) => Some(text.as_str().unwrap().as_bytes().to_vec()),
            (None, None) => None,
        };
        let header_refs: Vec<(&str, &str)> = headers
            .iter()
            .map(|(n, v)| (n.as_str(), v.as_str()))
            .collect();
        let reply = client.send(&method, &target, &header_refs, body.as_deref());
        let expect = &step["expect"];
        if let Some(matcher) = expect.get("status") {
            assert!(
                matches(matcher, Some(&json!(reply.status))),
                "{id}: step {name:?}: status {} does not match {matcher}",
                reply.status
            );
        }
        if let Some(expected) = expect.get("headers").and_then(Value::as_object) {
            for (header, matcher) in expected {
                let actual = reply.header(header).map(|v| json!(v));
                assert!(
                    matches(matcher, actual.as_ref()),
                    "{id}: step {name:?}: header {header}"
                );
            }
        }
        if let Some(matcher) = expect.get("body_text") {
            assert!(
                matches(matcher, Some(&json!(reply.text()))),
                "{id}: step {name:?}: body text"
            );
        }
        if let Some(expected) = expect.get("json").and_then(Value::as_object) {
            let answer = reply.json();
            for (pointer, matcher) in expected {
                assert!(
                    matches(matcher, answer.pointer(pointer)),
                    "{id}: step {name:?}: the answer {answer} does not match {pointer} {matcher}"
                );
            }
        }
        steps += 1;
    }
    steps
}

#[test]
fn the_server_passes_every_case_of_the_series_d() {
    let mut paths: Vec<_> = fs::read_dir(conformance_dir().join("D"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    paths.sort();
    assert!(paths.len() >= 6, "the cases of the series D are missing");
    let mut steps = 0;
    for path in &paths {
        steps += run_case(path);
    }
    assert!(steps >= paths.len());
}

#[test]
fn the_matchers_of_the_runner_follow_the_data_model() {
    assert!(matches(&json!({"equals": 1}), Some(&json!(1))));
    assert!(!matches(&json!({"equals": 1}), None));
    assert!(matches(&json!({"absent": true}), None));
    assert!(matches(&json!({"present": true}), Some(&json!(null))));
    assert!(matches(&json!({"one_of": [1, 2]}), Some(&json!(2))));
    assert!(matches(&json!({"regex": "^2[0-9]{2}$"}), Some(&json!(204))));
}
