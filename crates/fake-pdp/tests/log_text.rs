//! The text log: one block for each question, as the page `docs/tools.html` shows it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use fake_pdp::Options;
use serde_json::json;

fn logged(data: &serde_json::Value) -> (fake_pdp::RunningServer, Capture, Capture) {
    let out = Capture::default();
    let diagnostics = Capture::default();
    let server = start_with(
        data,
        Options {
            log: Some(Box::new(out.clone())),
            diagnostics: Some(Box::new(diagnostics.clone())),
            ..Options::default()
        },
    );
    (server, out, diagnostics)
}

#[test]
fn the_page_example_of_the_log() {
    // The counters before the use are one unit below the values on the page.
    let mut data = datastore();
    data["counters"] = json!([
        {"subject": KEY_ALICE, "limit": "requests", "window": "minute", "used": 98},
        {"subject": "alice", "limit": "requests", "window": "second", "used": 8},
        {"subject": "alice", "limit": "requests", "window": "minute", "used": 298}
    ]);
    let (server, out, _) = logged(&data);
    ask(&server, &question(KEY_ALICE, "data.read", TEST2, true));
    assert_eq!(
        out.text(),
        "q1  key:9b1c…  data.read  host:prod/database:test2\n\
         \x20   true  limits {\"max_duration\":30,\"max_rows\":5000}  units 1\n\
         \x20   counters  key/minute 99  alice/second 9\n\
         \x20             alice/minute 299\n"
    );
}

#[test]
fn the_log_has_one_block_for_each_question_in_the_order_of_arrival() {
    let (server, out, _) = logged(&datastore());
    ask(&server, &question("alice", "data.read", TEST1, false));
    ask(&server, &question("carol", "data.read", TEST1, false));
    ask(&server, &question("alice", "data.write", TEST1, true));
    ask(&server, &question("alice", "access", "", false));
    let text = out.text();
    let heads: Vec<&str> = text.lines().filter(|l| l.starts_with('q')).collect();
    assert_eq!(
        heads,
        [
            "q1  alice  data.read  host:prod/database:test1",
            "q2  carol  data.read  host:prod/database:test1",
            "q3  alice  data.write  host:prod/database:test1",
            "q4  alice  access  service:datastore",
        ]
    );
    assert!(text.contains("\n    false  unknown_subject\n"));
    assert!(
        text.contains("\n    true  limits {\"max_rows\":1000}\n"),
        "{text}"
    );
}

#[test]
fn the_log_shows_a_budget_refusal_with_the_counters() {
    let (server, out, _) = logged(&datastore());
    let q = question("alice", "data.read", TEST1, true);
    for _ in 0..11 {
        ask(&server, &q);
    }
    let text = out.text();
    let last: Vec<&str> = text.lines().rev().take(2).collect();
    assert_eq!(last[0], "    counters  alice/second 10  alice/minute 10");
    assert_eq!(last[1], "    false  budget_exceeded  retry_after 1");
}

#[test]
fn the_log_shows_each_item_of_an_evaluations_request() {
    let (server, out, _) = logged(&datastore());
    let item = question("alice", "data.read", TEST1, false);
    once_json(
        server.local_addr(),
        EVALUATIONS,
        &json!({"evaluations": [item.clone(), item]}),
    );
    let text = out.text();
    assert_eq!(text.lines().filter(|l| l.starts_with('q')).count(), 2);
}

#[test]
fn the_log_shows_a_failure() {
    let mut data = datastore();
    data["failures"] =
        json!([{"kind": "error_503", "times": 1}, {"kind": "delay", "delay_ms": 5, "times": 1}]);
    let (server, out, _) = logged(&data);
    let q = question("alice", "data.read", TEST1, false);
    once_json(server.local_addr(), EVALUATION, &q);
    once_json(server.local_addr(), EVALUATION, &q);
    let text = out.text();
    assert!(
        text.contains("q1  alice  data.read  host:prod/database:test1\n    fault error_503\n"),
        "{text}"
    );
    assert!(
        text.contains("    true  limits {\"max_rows\":1000}  fault delay 5\n"),
        "{text}"
    );
}

#[test]
fn a_rejected_request_goes_to_the_diagnostics_with_the_path_and_no_value() {
    let (server, out, diagnostics) = logged(&datastore());
    let mut bad = question("alice-visible-id", "data.read", TEST1, false);
    bad["context"] = json!({"match": "secret-looking-value"});
    let reply = once_json(server.local_addr(), EVALUATION, &bad);
    assert_eq!(reply.status, 400);
    assert_eq!(out.text(), "", "a bad request is not a question");
    let text = diagnostics.text();
    assert!(
        text.contains("rejected 400 POST /access/v1/evaluation"),
        "{text}"
    );
    assert!(text.contains("$.context.match"), "{text}");
    assert!(!text.contains("secret-looking-value"));
    assert!(!text.contains("alice-visible-id"));
}

#[test]
fn a_control_character_in_a_subject_cannot_forge_a_line() {
    let (server, out, _) = logged(&datastore());
    let mut q = question("alice", "data.read", TEST1, false);
    q["subject"]["id"] = json!("x\nq99  mallory  data.read  host:prod");
    ask(&server, &q);
    let text = out.text();
    assert_eq!(
        text.lines().filter(|l| l.starts_with('q')).count(),
        1,
        "{text}"
    );
    assert!(text.starts_with("q1  x?q99  mallory"), "{text}");
}
