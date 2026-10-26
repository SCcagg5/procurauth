//! Budgets and counters over real HTTP, with the clock of the server (6.3 to 6.12).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;
use std::thread;

use common::*;
use serde_json::{Value, json};

fn used(server: &fake_pdp::RunningServer, subject: &str, window: &str) -> Option<u64> {
    server
        .counters()
        .iter()
        .find(|c| c.subject == subject && c.window.as_str() == window)
        .map(|c| c.used)
}

#[test]
fn p_6_5_the_eleventh_use_in_one_second_is_refused() {
    let server = start(&datastore());
    let q = question("alice", "data.read", TEST1, true);
    for n in 1..=10 {
        let answer = ask(&server, &q);
        assert_eq!(answer["decision"], true, "use {n}");
        assert_eq!(answer["context"]["usage"]["units"], 1);
    }
    let refused = ask(&server, &q);
    assert_eq!(
        refused,
        json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 1}})
    );
    // The refused use took no unit from the minute counter (6.5).
    assert_eq!(used(&server, "alice", "minute"), Some(10));
    assert_eq!(used(&server, "alice", "second"), Some(10));
}

#[test]
fn p_6_6_a_question_without_usage_counts_nothing() {
    let server = start(&datastore());
    let q = question("alice", "data.read", TEST1, false);
    for _ in 0..40 {
        let answer = ask(&server, &q);
        assert_eq!(answer["decision"], true);
        assert!(answer["context"].get("usage").is_none());
    }
    assert!(server.counters().is_empty());
}

#[test]
fn p_6_3_a_new_second_gives_the_units_back() {
    let server = start(&datastore());
    let q = question("alice", "data.read", TEST1, true);
    for _ in 0..10 {
        ask(&server, &q);
    }
    assert_eq!(ask(&server, &q)["decision"], false);
    server.clock().advance(1).unwrap();
    assert_eq!(ask(&server, &q)["decision"], true);
    assert_eq!(used(&server, "alice", "second"), Some(1));
    assert_eq!(used(&server, "alice", "minute"), Some(11));
}

#[test]
fn p_11_1_retry_after_is_the_seconds_to_the_end_of_the_minute() {
    // The case D06: 300 of 300 units in the minute, and 12 seconds remain.
    let mut data = datastore();
    data["counters"] =
        json!([{"subject": "alice", "limit": "requests", "window": "minute", "used": 300}]);
    let server = start(&data);
    let q = question("alice", "data.read", TEST1, true);
    assert_eq!(
        ask(&server, &q),
        json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 12}})
    );
    // The clock moves 11 seconds: 1 second remains.
    server.clock().advance(11).unwrap();
    assert_eq!(ask(&server, &q)["context"]["retry_after"], 1);
    // At the start of the next minute the counter is new.
    server.clock().advance(1).unwrap();
    assert_eq!(ask(&server, &q)["decision"], true);
    assert_eq!(used(&server, "alice", "minute"), Some(1));
}

#[test]
fn p_11_1_retry_after_is_the_latest_end_among_the_refusing_windows() {
    let mut data = datastore();
    data["counters"] = json!([
        {"subject": "alice", "limit": "requests", "window": "second", "used": 10},
        {"subject": "alice", "limit": "requests", "window": "minute", "used": 300}
    ]);
    let server = start(&data);
    let q = question("alice", "data.read", TEST1, true);
    assert_eq!(ask(&server, &q)["context"]["retry_after"], 12);
}

#[test]
fn p_6_3_the_windows_hour_and_day_follow_the_epoch() {
    let mut data = datastore();
    data["subjects"][0]["grants"][0]["limits"] = json!({
        "requests": [{"amount": 2, "window": "hour"}, {"amount": 3, "window": "day"}]
    });
    let server = start(&data);
    let q = question("alice", "data.read", TEST1, true);
    assert_eq!(ask(&server, &q)["decision"], true);
    assert_eq!(ask(&server, &q)["decision"], true);
    let refused = ask(&server, &q);
    assert_eq!(refused["context"]["reason"], "budget_exceeded");
    assert_eq!(refused["context"]["retry_after"], 3600 - NOW % 3600);
    // The next hour: the hour counter is new, the day counter has 2 of 3.
    server.clock().advance(3600 - NOW % 3600).unwrap();
    assert_eq!(ask(&server, &q)["decision"], true);
    let refused = ask(&server, &q);
    assert_eq!(refused["decision"], false, "the day counter is spent");
    assert_eq!(
        refused["context"]["retry_after"],
        86_400 - (NOW + 3600 - NOW % 3600) % 86_400
    );
}

#[test]
fn p_6_7_a_use_of_a_key_shares_the_counters_of_its_owner() {
    let server = start(&datastore());
    let alice = question("alice", "data.read", TEST1, true);
    for _ in 0..10 {
        ask(&server, &alice);
    }
    // Alice spent her second: her key is refused, and takes no unit from its own counter.
    let key = question(KEY_ALICE, "data.read", TEST2, true);
    let refused = ask(&server, &key);
    assert_eq!(refused["context"]["reason"], "budget_exceeded");
    assert_eq!(used(&server, KEY_ALICE, "minute"), None);
    server.clock().advance(1).unwrap();
    let allowed = ask(&server, &key);
    assert_eq!(allowed["context"]["usage"]["units"], 1);
    assert_eq!(used(&server, KEY_ALICE, "minute"), Some(1));
    assert_eq!(used(&server, "alice", "second"), Some(1));
    assert_eq!(used(&server, "alice", "minute"), Some(11));
}

#[test]
fn p_6_7_the_budget_of_a_key_has_its_own_counters() {
    // Alice has 10 a second and 300 a minute. Her key has 100 a minute.
    let mut data = datastore();
    data["subjects"][0]["grants"][0]["limits"] =
        json!({"requests": [{"amount": 300, "window": "minute"}]});
    let server = start(&data);
    let key = question(KEY_ALICE, "data.read", TEST2, true);
    for _ in 0..100 {
        assert_eq!(ask(&server, &key)["decision"], true);
    }
    let refused = ask(&server, &key);
    assert_eq!(refused["context"]["reason"], "budget_exceeded");
    // The key is refused by its own counter: Alice still has 200 units.
    assert_eq!(used(&server, "alice", "minute"), Some(100));
    let alice = question("alice", "data.read", TEST1, true);
    assert_eq!(ask(&server, &alice)["decision"], true);
}

#[test]
fn p_6_12_a_use_with_no_counter_gets_zero_units() {
    let mut data = datastore();
    data["subjects"][2]["grants"][0] = json!({"action": "access", "resource": "service:datastore"});
    data["subjects"][3]["grants"] = json!([
        {"action": "access", "resource": "service:datastore"},
        {"action": "data.read", "resource": "service:datastore/host:prod/database:test1"}
    ]);
    let server = start(&data);
    let answer = ask(&server, &question(KEY_BOB, "data.read", TEST1, true));
    assert_eq!(answer["decision"], true);
    assert_eq!(answer["context"]["usage"]["units"], 0);
    assert!(server.counters().is_empty());
}

#[test]
fn p_6_11_an_evaluations_request_with_items_and_usage_gets_http_400() {
    let server = start(&datastore());
    let item = question("alice", "data.read", TEST1, false);
    // usage at the top level
    let body = json!({"context": {"usage": {"units": 1}}, "evaluations": [item.clone()]});
    let reply = once_json(server.local_addr(), EVALUATIONS, &body);
    assert_eq!(reply.status, 400);
    // usage in an item
    let with_usage = question("alice", "data.read", TEST1, true);
    let body = json!({"evaluations": [item.clone(), with_usage]});
    let reply = once_json(server.local_addr(), EVALUATIONS, &body);
    assert_eq!(reply.status, 400);
    assert!(server.counters().is_empty(), "the PDP counts nothing");
    assert!(server.log().is_empty());
    // The same items without usage are good.
    let body = json!({"evaluations": [item.clone(), item]});
    let reply = once_json(server.local_addr(), EVALUATIONS, &body);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["evaluations"].as_array().unwrap().len(), 2);
}

#[test]
fn p_6_11_an_evaluations_request_without_items_may_carry_usage() {
    let server = start(&datastore());
    let reply = once_json(
        server.local_addr(),
        EVALUATIONS,
        &question("alice", "data.read", TEST1, true),
    );
    assert_eq!(reply.status, 200);
    // The answer has the form of one Access Evaluation answer.
    assert_eq!(
        reply.json(),
        json!({"decision": true, "context": {"limits": {"max_rows": 1000}, "usage": {"units": 1}}})
    );
    // An empty array of items is the same.
    let mut body = question("alice", "data.read", TEST1, true);
    body["evaluations"] = json!([]);
    let reply = once_json(server.local_addr(), EVALUATIONS, &body);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["context"]["usage"]["units"], 1);
    assert_eq!(used(&server, "alice", "second"), Some(2));
}

#[test]
fn p_6_4_a_bad_usage_gets_http_400_and_counts_nothing() {
    let server = start(&datastore());
    for usage in [
        json!({"units": 2}),
        json!({"units": 0}),
        json!({}),
        json!(5),
        json!({"units": "1"}),
    ] {
        let mut q = question("alice", "data.read", TEST1, false);
        q["context"] = json!({"usage": usage});
        let reply = once_json(server.local_addr(), EVALUATION, &q);
        assert_eq!(reply.status, 400, "{usage}");
    }
    // usage with subtree
    let mut q = question("alice", "data.read", TEST1, true);
    q["context"]["match"] = json!("subtree");
    assert_eq!(once_json(server.local_addr(), EVALUATION, &q).status, 400);
    assert!(server.counters().is_empty());
}

#[test]
fn p_6_8_the_units_of_all_threads_never_exceed_the_amount() {
    let server = Arc::new(start(&datastore()));
    let addr = server.local_addr();
    let mut threads = Vec::new();
    for _ in 0..8 {
        threads.push(thread::spawn(move || {
            let mut client = Client::connect(addr);
            let q = question("alice", "data.read", TEST1, true);
            let mut allowed = 0;
            for _ in 0..8 {
                let reply = client.post_json(EVALUATION, &q);
                let answer: Value = reply.json();
                if answer["decision"] == true {
                    allowed += 1;
                }
            }
            allowed
        }));
    }
    let total: u32 = threads.into_iter().map(|t| t.join().unwrap()).sum();
    assert_eq!(
        total, 10,
        "alice has 10 units a second, and the clock is fixed"
    );
    assert_eq!(used(&server, "alice", "second"), Some(10));
}

#[test]
fn p_6_3_the_reset_puts_the_counters_back_to_the_first_values() {
    let mut data = datastore();
    data["counters"] =
        json!([{"subject": "alice", "limit": "requests", "window": "second", "used": 9}]);
    let server = start(&data);
    let q = question("alice", "data.read", TEST1, true);
    assert_eq!(ask(&server, &q)["decision"], true);
    assert_eq!(ask(&server, &q)["decision"], false);
    server.reset_counters();
    assert_eq!(used(&server, "alice", "second"), Some(9));
    assert_eq!(ask(&server, &q)["decision"], true);
}
