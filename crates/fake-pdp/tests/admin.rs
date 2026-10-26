//! The admin endpoints under `/__fake/`: clock, reset, counters, log and failures.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{Value, json};

fn post(server: &fake_pdp::RunningServer, path: &str, body: &str) -> Reply {
    Client::connect(server.local_addr()).send("POST", path, &[], Some(body.as_bytes()))
}

fn get(server: &fake_pdp::RunningServer, path: &str) -> Reply {
    Client::connect(server.local_addr()).get(path)
}

#[test]
fn the_admin_endpoints_are_off_unless_the_option_is_on() {
    let server = start(&datastore());
    for (method, path) in [
        ("GET", "/__fake/clock"),
        ("POST", "/__fake/clock"),
        ("POST", "/__fake/reset"),
        ("GET", "/__fake/counters"),
        ("GET", "/__fake/log"),
        ("GET", "/__fake/failures"),
        ("GET", "/__fake/anything"),
    ] {
        let reply = Client::connect(server.local_addr()).send(method, path, &[], Some(b"{}"));
        assert_eq!(reply.status, 404, "{method} {path}");
    }
    assert_eq!(server.clock().now_seconds(), NOW, "the clock did not move");
}

#[test]
fn the_admin_prefix_needs_the_exact_path_and_the_right_method() {
    let server = start_admin(&datastore());
    assert_eq!(get(&server, "/__fake/").status, 404);
    assert_eq!(get(&server, "/__fake/nothing").status, 404);
    assert_eq!(get(&server, "/__fake").status, 404);
    let reply = post(&server, "/__fake/counters", "");
    assert_eq!(reply.status, 405);
    assert_eq!(reply.header("allow"), Some("GET"));
    let reply = get(&server, "/__fake/reset");
    assert_eq!(reply.status, 405);
}

#[test]
fn the_clock_endpoint_reads_advances_and_sets_the_clock() {
    let server = start_admin(&datastore());
    assert_eq!(get(&server, "/__fake/clock").json()["now"], NOW);
    assert_eq!(get(&server, "/__fake/clock").json()["fixed"], true);
    let reply = post(&server, "/__fake/clock", r#"{"advance": 90}"#);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["now"], NOW + 90);
    assert_eq!(server.clock().now_seconds(), NOW + 90);
    let reply = post(&server, "/__fake/clock", r#"{"set": 100}"#);
    assert_eq!(reply.json()["now"], 100);
    assert_eq!(reply.json()["now_millis"], 100_000);
    assert_eq!(server.clock().now_seconds(), 100);
}

#[test]
fn the_clock_endpoint_refuses_a_bad_body_with_the_path_of_each_finding() {
    let server = start_admin(&datastore());
    for body in [
        "",
        "{",
        "[]",
        "{}",
        r#"{"advance": 1, "set": 2}"#,
        r#"{"advance": -1}"#,
        r#"{"advance": 1.5}"#,
        r#"{"advance": "10"}"#,
        r#"{"advance": 1, "extra": 1}"#,
        r#"{"advance": 1, "advance": 2}"#,
        &format!(r#"{{"set": {}}}"#, u64::MAX),
        &format!(r#"{{"advance": {}}}"#, u64::MAX),
    ] {
        let reply = post(&server, "/__fake/clock", body);
        assert_eq!(reply.status, 400, "{body}");
    }
    assert_eq!(
        server.clock().now_seconds(),
        NOW,
        "a bad request never moves the clock"
    );
    let reply = post(&server, "/__fake/clock", r#"{"advance": 1, "extra": 1}"#);
    assert_eq!(reply.json()["findings"][0]["path"], "$.extra");
}

#[test]
fn the_clock_moves_the_windows_of_the_counters() {
    let server = start_admin(&datastore());
    let q = question("alice", "data.read", TEST1, true);
    for _ in 0..10 {
        ask(&server, &q);
    }
    assert_eq!(ask(&server, &q)["decision"], false);
    assert_eq!(
        post(&server, "/__fake/clock", r#"{"advance": 1}"#).status,
        200
    );
    assert_eq!(ask(&server, &q)["decision"], true);
}

#[test]
fn a_system_clock_becomes_fixed_when_the_admin_endpoint_moves_it() {
    let mut data = datastore();
    data.as_object_mut().unwrap().remove("clock");
    let server = start_admin(&data);
    assert_eq!(get(&server, "/__fake/clock").json()["fixed"], false);
    let reply = post(&server, "/__fake/clock", r#"{"set": 1792569648}"#);
    assert_eq!(reply.json()["fixed"], true);
    assert_eq!(server.clock().now_seconds(), NOW);
}

#[test]
fn the_reset_endpoint_puts_the_counters_back() {
    let mut data = datastore();
    data["counters"] =
        json!([{"subject": "alice", "limit": "requests", "window": "second", "used": 5}]);
    let server = start_admin(&data);
    let q = question("alice", "data.read", TEST1, true);
    for _ in 0..3 {
        ask(&server, &q);
    }
    let counters = get(&server, "/__fake/counters").json();
    let second = counters["counters"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["window"] == "second")
        .unwrap()
        .clone();
    assert_eq!(second["used"], 8);
    assert_eq!(second["service"], "datastore");
    assert_eq!(second["subject"], "alice");
    assert_eq!(second["limit"], "requests");
    assert_eq!(second["window_start"], NOW);
    assert_eq!(counters["now"], NOW);
    let reply = post(&server, "/__fake/reset", "");
    assert_eq!(reply.status, 200);
    let counters = get(&server, "/__fake/counters").json();
    assert_eq!(counters["counters"].as_array().unwrap().len(), 1);
    assert_eq!(counters["counters"][0]["used"], 5);
    assert_eq!(post(&server, "/__fake/reset", "{}").status, 200);
    assert_eq!(post(&server, "/__fake/reset", r#"{"x": 1}"#).status, 400);
}

#[test]
fn the_log_endpoint_lists_the_questions_and_the_delete_clears_it() {
    let server = start_admin(&datastore());
    let reply = Client::connect(server.local_addr()).post_json_with(
        EVALUATION,
        &[("X-Request-ID", "r-1")],
        &question(KEY_ALICE, "data.read", TEST2, true),
    );
    assert_eq!(reply.status, 200);
    ask(&server, &question("carol", "data.read", TEST1, false));
    let log = get(&server, "/__fake/log").json();
    let entries = log["entries"].as_array().unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0]["seq"], 1);
    assert_eq!(entries[0]["subject"], KEY_ALICE);
    assert_eq!(entries[0]["action"], "data.read");
    assert_eq!(
        entries[0]["resource"],
        "service:datastore/host:prod/database:test2"
    );
    assert_eq!(entries[0]["usage"], true);
    assert_eq!(entries[0]["request_id"], "r-1");
    assert_eq!(entries[0]["answer"]["decision"], true);
    assert_eq!(entries[0]["counters"].as_array().unwrap().len(), 3);
    assert_eq!(entries[1]["answer"]["context"]["reason"], "unknown_subject");
    assert_eq!(entries[1]["request_id"], Value::Null);
    let reply = Client::connect(server.local_addr()).send("DELETE", "/__fake/log", &[], None);
    assert_eq!(reply.json()["cleared"], 2);
    assert_eq!(get(&server, "/__fake/log").json()["entries"], json!([]));
}

#[test]
fn the_failures_endpoint_replaces_and_lists_the_rules() {
    let server = start_admin(&datastore());
    let q = question("alice", "data.read", TEST1, false);
    assert_eq!(
        get(&server, "/__fake/failures").json(),
        json!({"failures": []})
    );
    let reply = post(
        &server,
        "/__fake/failures",
        r#"{"failures": [{"kind": "close", "times": 1, "when": {"subject": "alice"}}, {"kind": "delay", "delay_ms": 5}]}"#,
    );
    assert_eq!(reply.json(), json!({"failures": 2}));
    let listed = get(&server, "/__fake/failures").json();
    assert_eq!(listed["failures"][0]["kind"], "close");
    assert_eq!(listed["failures"][0]["left"], 1);
    assert_eq!(listed["failures"][0]["when"], json!({"subject": "alice"}));
    assert_eq!(listed["failures"][1]["delay_ms"], 5);
    assert_eq!(listed["failures"][1]["left"], Value::Null);
    // The first rule closes one connection.
    let mut client = Client::connect(server.local_addr());
    client.write_raw(
        format!(
            "POST {EVALUATION} HTTP/1.1\r\nHost: t\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{q}",
            q.to_string().len()
        )
        .as_bytes(),
    );
    assert_eq!(client.probe(2000), Probe::Closed);
    assert_eq!(
        get(&server, "/__fake/failures").json()["failures"][0]["left"],
        0
    );
    // An empty list removes the rules.
    assert_eq!(
        post(&server, "/__fake/failures", r#"{"failures": []}"#).json(),
        json!({"failures": 0})
    );
    assert_eq!(ask(&server, &q)["decision"], true);
}

#[test]
fn the_failures_endpoint_refuses_a_bad_rule_and_keeps_the_old_rules() {
    let server = start_admin(&datastore());
    post(
        &server,
        "/__fake/failures",
        r#"{"failures": [{"kind": "error_503"}]}"#,
    );
    let reply = post(
        &server,
        "/__fake/failures",
        r#"{"failures": [{"kind": "explode"}, {"kind": "delay"}]}"#,
    );
    assert_eq!(reply.status, 400);
    let findings = reply.json()["findings"].clone();
    assert_eq!(findings[0]["path"], "$.failures[0].kind");
    assert_eq!(findings[1]["path"], "$.failures[1]");
    assert_eq!(
        get(&server, "/__fake/failures").json()["failures"][0]["kind"],
        "error_503"
    );
    assert_eq!(post(&server, "/__fake/failures", "{").status, 400);
}

#[test]
fn the_admin_endpoints_share_the_listener_with_the_pdp() {
    let server = start_admin(&datastore());
    let mut client = Client::connect(server.local_addr());
    assert_eq!(client.get("/__fake/clock").status, 200);
    assert_eq!(
        client
            .post_json(EVALUATION, &question("alice", "data.read", TEST1, false))
            .status,
        200
    );
    assert_eq!(client.get("/.well-known/authzen-configuration").status, 200);
}

#[test]
fn the_load_endpoint_replaces_the_directory_the_counters_and_the_clock() {
    let server = start_admin(&datastore());
    let q = question("alice", "data.read", TEST1, true);
    assert_eq!(ask(&server, &q)["decision"], true);
    // A data file with no subject: nobody has a right.
    let mut empty = datastore();
    empty["subjects"] = json!([]);
    empty["clock"] = json!({"now": 1_792_569_700_u64});
    let reply = Client::connect(server.local_addr()).send(
        "PUT",
        "/__fake/load",
        &[],
        Some(empty.to_string().as_bytes()),
    );
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(reply.json()["loaded"], true);
    assert_eq!(ask(&server, &q)["decision"], false);
    assert_eq!(server.clock().now_seconds(), 1_792_569_700);
    // The old data comes back with a second load. POST works as PUT.
    let reply = post(&server, "/__fake/load", &datastore().to_string());
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(ask(&server, &q)["decision"], true);
}

#[test]
fn the_load_endpoint_refuses_bad_data_and_keeps_the_old_data() {
    let server = start_admin(&datastore());
    let q = question("alice", "data.read", TEST1, true);
    assert_eq!(post(&server, "/__fake/load", "{not json").status, 400);
    let reply = post(&server, "/__fake/load", r#"{"services": 1}"#);
    assert_eq!(reply.status, 400);
    assert!(reply.json()["findings"].is_array());
    let mut moved = datastore();
    moved["metadata"] = json!({"usage_max_seconds": 77});
    assert_eq!(
        post(&server, "/__fake/load", &moved.to_string()).status,
        400
    );
    assert_eq!(ask(&server, &q)["decision"], true);
    let reply = Client::connect(server.local_addr()).send("GET", "/__fake/load", &[], None);
    assert_eq!(reply.status, 405);
}

#[test]
fn p_12_the_load_endpoint_installs_the_credentials_of_the_services() {
    let server = start_admin(&datastore());
    let mut data = datastore();
    let digest = {
        use sha2::{Digest as _, Sha256};
        Sha256::digest(b"datastore-secret")
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    };
    data["services"][0]["credential_sha256"] = json!(digest);
    assert_eq!(post(&server, "/__fake/load", &data.to_string()).status, 200);
    let q = question("alice", "data.read", TEST1, false);
    let denied = Client::connect(server.local_addr()).post_json("/access/v1/evaluation", &q);
    assert_eq!(denied.status, 401);
    let allowed = Client::connect(server.local_addr()).post_json_with(
        "/access/v1/evaluation",
        &[("Authorization", "Bearer datastore-secret")],
        &q,
    );
    assert_eq!(allowed.status, 200);
}
