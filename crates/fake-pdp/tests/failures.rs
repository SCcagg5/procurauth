//! Failure injection (6.9, 6.12, 10.3, 10.6). The kinds are HTTP 503, a delay,
//! no answer, a closed connection, a body that is not JSON, and a `true` without units.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::{Duration, Instant};

use common::*;
use fake_pdp::Options;
use fake_pdp::faults::read_faults_str;
use serde_json::json;

fn faults(text: &str) -> Vec<fake_pdp::Fault> {
    read_faults_str(text).unwrap()
}

fn with_faults(text: &str) -> fake_pdp::RunningServer {
    start_with(
        &datastore(),
        Options {
            extra_faults: faults(text),
            ..Options::default()
        },
    )
}

fn used(server: &fake_pdp::RunningServer, window: &str) -> Option<u64> {
    server
        .counters()
        .iter()
        .find(|c| c.subject == "alice" && c.window.as_str() == window)
        .map(|c| c.used)
}

#[test]
fn p_6_9_a_503_gives_no_decision_and_counts_nothing() {
    let mut data = datastore();
    data["failures"] = json!([{"kind": "error_503", "when": {"usage": true}, "times": 2}]);
    let server = start(&data);
    let q = question("alice", "data.read", TEST1, true);
    for _ in 0..2 {
        let reply = once_json(server.local_addr(), EVALUATION, &q);
        assert_eq!(reply.status, 503);
        assert_eq!(reply.header("content-type"), Some("application/json"));
        assert!(reply.json().get("decision").is_none());
    }
    assert!(server.counters().is_empty());
    // A question without usage did not match, and the third question with usage gets its answer.
    assert_eq!(
        ask(&server, &question("alice", "data.read", TEST1, false))["decision"],
        true
    );
    assert_eq!(ask(&server, &q)["decision"], true);
    assert_eq!(used(&server, "second"), Some(1));
    // The log shows the failure.
    let log = server.log();
    assert_eq!(log[0].fault.as_deref(), Some("error_503"));
    assert_eq!(log[0].answer, None);
}

#[test]
fn p_6_9_a_rule_applies_only_to_the_questions_that_it_names() {
    let mut data = datastore();
    data["failures"] = json!([
        {"kind": "error_503", "when": {"subject": "bob"}},
        {"kind": "error_503", "when": {"action": "data.write", "resource": "service:datastore/host:prod/database:test2"}},
        {"kind": "error_503", "when": {"endpoint": "evaluations"}}
    ]);
    let server = start(&data);
    let status =
        |body: &serde_json::Value, path: &str| once_json(server.local_addr(), path, body).status;
    assert_eq!(
        status(&question("alice", "data.read", TEST1, false), EVALUATION),
        200
    );
    assert_eq!(
        status(&question("bob", "data.read", TEST1, false), EVALUATION),
        503
    );
    assert_eq!(
        status(&question("alice", "data.write", TEST2, false), EVALUATION),
        503
    );
    assert_eq!(
        status(&question("alice", "data.read", TEST2, false), EVALUATION),
        200
    );
    assert_eq!(
        status(&question("alice", "data.read", TEST1, false), EVALUATIONS),
        503
    );
}

#[test]
fn p_6_9_a_503_on_the_metadata() {
    let mut data = datastore();
    data["failures"] = json!([{"kind": "error_503", "when": {"endpoint": "metadata"}, "times": 1}]);
    let server = start(&data);
    let addr = server.local_addr();
    assert_eq!(
        once(addr, "GET", "/.well-known/authzen-configuration", &[], None).status,
        503
    );
    assert_eq!(
        once(addr, "GET", "/.well-known/authzen-configuration", &[], None).status,
        200
    );
}

#[test]
fn p_6_9_a_delay_waits_and_then_answers_as_usual() {
    let mut data = datastore();
    data["failures"] = json!([{"kind": "delay", "delay_ms": 300, "times": 1}]);
    let server = start(&data);
    let q = question("alice", "data.read", TEST1, true);
    let start_time = Instant::now();
    let reply = once_json(server.local_addr(), EVALUATION, &q);
    assert!(start_time.elapsed() >= Duration::from_millis(280));
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["context"]["usage"]["units"], 1);
    let start_time = Instant::now();
    once_json(server.local_addr(), EVALUATION, &q);
    assert!(start_time.elapsed() < Duration::from_millis(250));
    assert_eq!(server.log()[0].fault.as_deref(), Some("delay 300"));
}

#[test]
fn p_10_6_no_answer_counts_the_use_and_never_answers() {
    let data = datastore();
    let server = start_with(
        &data,
        Options {
            extra_faults: faults(r#"{"failures": [{"kind": "no_answer", "times": 1}]}"#),
            ..Options::default()
        },
    );
    let mut client = Client::connect(server.local_addr());
    let body = question("alice", "data.read", TEST1, true).to_string();
    client.write_raw(
        format!(
            "POST {EVALUATION} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        )
        .as_bytes(),
    );
    assert_eq!(client.probe(600), Probe::Silent);
    // The units of a lost answer stay counted (10.6).
    assert_eq!(used(&server, "second"), Some(1));
    // The server still stops, with a connection that it holds open.
    let started = Instant::now();
    server.shutdown();
    assert!(started.elapsed() < Duration::from_secs(3));
    assert_eq!(client.probe(1000), Probe::Closed);
}

#[test]
fn p_10_6_a_closed_connection_counts_the_use_and_sends_no_byte() {
    let server = with_faults(r#"{"failures": [{"kind": "close", "times": 1}]}"#);
    let mut client = Client::connect(server.local_addr());
    let body = question("alice", "data.read", TEST1, true);
    client.write_raw(
        format!(
            "POST {EVALUATION} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.to_string().len()
        )
        .as_bytes(),
    );
    assert_eq!(client.probe(2000), Probe::Closed);
    assert_eq!(used(&server, "second"), Some(1));
    // The next question gets its answer.
    assert_eq!(ask(&server, &body)["decision"], true);
}

#[test]
fn p_10_3_a_body_that_is_not_json_gets_status_200() {
    let server = with_faults(r#"{"failures": [{"kind": "invalid_json"}]}"#);
    let reply = once_json(
        server.local_addr(),
        EVALUATION,
        &question("alice", "data.read", TEST1, true),
    );
    assert_eq!(reply.status, 200);
    assert!(serde_json::from_slice::<serde_json::Value>(&reply.body).is_err());
    assert_eq!(used(&server, "second"), Some(1));
}

#[test]
fn p_6_12_a_true_answer_without_units() {
    let server = with_faults(r#"{"failures": [{"kind": "no_units", "when": {"usage": true}}]}"#);
    let counted = ask(&server, &question("alice", "data.read", TEST1, true));
    assert_eq!(
        counted,
        json!({"decision": true, "context": {"limits": {"max_rows": 1000}}})
    );
    assert_eq!(used(&server, "second"), Some(1), "the PDP counted the use");
    // A false answer is not changed.
    let denied = ask(&server, &question("alice", "data.write", TEST1, true));
    assert_eq!(denied, json!({"decision": false}));
    // A question without usage did not match.
    let plain = ask(&server, &question("alice", "data.read", TEST1, false));
    assert_eq!(plain["decision"], true);
}

#[test]
fn p_6_12_no_units_leaves_no_empty_context() {
    let server = with_faults(r#"{"failures": [{"kind": "no_units"}]}"#);
    let answer = ask(&server, &question("bob", "data.read", TEST1, true));
    assert_eq!(answer, json!({"decision": true}));
}

#[test]
fn the_failures_of_the_data_file_come_before_the_failures_of_the_failure_file() {
    let mut data = datastore();
    data["failures"] = json!([{"kind": "error_503", "times": 1}]);
    let server = start_with(
        &data,
        Options {
            extra_faults: faults(r#"{"failures": [{"kind": "invalid_json", "times": 1}]}"#),
            ..Options::default()
        },
    );
    let q = question("alice", "data.read", TEST1, false);
    assert_eq!(once_json(server.local_addr(), EVALUATION, &q).status, 503);
    assert!(
        once_json(server.local_addr(), EVALUATION, &q)
            .json_checked()
            .is_none()
    );
    assert_eq!(once_json(server.local_addr(), EVALUATION, &q).status, 200);
}

trait JsonChecked {
    fn json_checked(&self) -> Option<serde_json::Value>;
}

impl JsonChecked for Reply {
    fn json_checked(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

#[test]
fn the_library_can_replace_the_failures_while_the_server_runs() {
    let server = start(&datastore());
    let q = question("alice", "data.read", TEST1, false);
    assert_eq!(once_json(server.local_addr(), EVALUATION, &q).status, 200);
    server.set_faults(faults(r#"{"failures": [{"kind": "error_503"}]}"#));
    assert_eq!(once_json(server.local_addr(), EVALUATION, &q).status, 503);
    server.set_faults(Vec::new());
    assert_eq!(once_json(server.local_addr(), EVALUATION, &q).status, 200);
}
