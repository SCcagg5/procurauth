//! The example of protocol section 13 and 4.4, over real HTTP.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::json;

#[test]
fn p_13_alice_reads_test1_and_gets_her_ceiling() {
    let server = start(&datastore());
    let answer = ask(&server, &question("alice", "data.read", TEST1, false));
    assert_eq!(
        answer,
        json!({"decision": true, "context": {"limits": {"max_rows": 1000}}})
    );
}

#[test]
fn p_13_alice_reads_the_table_orders_with_one_use() {
    let server = start(&datastore());
    let answer = ask(
        &server,
        &question(
            "alice",
            "data.read",
            "host:prod/database:test2/table:orders",
            true,
        ),
    );
    assert_eq!(
        answer,
        json!({"decision": true, "context": {"limits": {"max_rows": 100, "max_duration": 30}, "usage": {"units": 1}}})
    );
}

#[test]
fn p_13_alice_reads_and_writes_test2_and_has_no_other_right() {
    let server = start(&datastore());
    let read = ask(&server, &question("alice", "data.read", TEST2, false));
    assert_eq!(
        read["context"]["limits"],
        json!({"max_rows": 5000, "max_duration": 30})
    );
    let write = ask(&server, &question("alice", "data.write", TEST2, false));
    assert_eq!(write["context"]["limits"], json!({"max_duration": 10}));
    // data.write on test1 and data.read on the host: false, with no reason.
    assert_eq!(
        ask(&server, &question("alice", "data.write", TEST1, true)),
        json!({"decision": false})
    );
    assert_eq!(
        ask(&server, &question("alice", "data.read", "host:prod", true)),
        json!({"decision": false})
    );
    // The two refusals took no unit.
    assert!(server.counters().is_empty());
}

#[test]
fn p_13_the_key_of_alice_never_goes_above_alice() {
    let server = start(&datastore());
    let answer = ask(&server, &question(KEY_ALICE, "data.read", TEST2, true));
    assert_eq!(
        answer,
        json!({"decision": true, "context": {"limits": {"max_rows": 5000, "max_duration": 30}, "usage": {"units": 1}}})
    );
    // The use takes one unit from three counters (6.7). The list is sorted by subject.
    let names: Vec<_> = server
        .counters()
        .iter()
        .map(|c| format!("{}/{}={}", c.subject, c.window.as_str(), c.used))
        .collect();
    assert_eq!(
        names,
        [
            "alice/second=1".to_owned(),
            "alice/minute=1".to_owned(),
            format!("{KEY_ALICE}/minute=1"),
        ]
    );
}

#[test]
fn p_3_5_bob_has_test1_and_his_key_has_test2_but_the_key_gets_nothing() {
    let server = start(&datastore());
    assert_eq!(
        ask(&server, &question("bob", "data.read", TEST1, false))["decision"],
        true
    );
    assert_eq!(
        ask(&server, &question("bob", "data.read", TEST2, false))["decision"],
        false
    );
    // The key of Bob has a grant on test2, but Bob has none.
    assert_eq!(
        ask(&server, &question(KEY_BOB, "data.read", TEST2, false)),
        json!({"decision": false})
    );
    // Bob has a grant on test1, but his key has none.
    assert_eq!(
        ask(&server, &question(KEY_BOB, "data.read", TEST1, false)),
        json!({"decision": false})
    );
}

#[test]
fn p_4_4_the_intersection_test_for_subtree() {
    let server = start(&datastore());
    let subtree = |subject: &str| {
        let mut q = question(subject, "data.read", "", false);
        q["context"] = json!({"match": "subtree"});
        q
    };
    assert_eq!(ask(&server, &subtree(KEY_BOB)), json!({"decision": false}));
    assert_eq!(ask(&server, &subtree("bob")), json!({"decision": true}));
    assert_eq!(ask(&server, &subtree(KEY_ALICE)), json!({"decision": true}));
    // A node below the service: a grant on a node below it applies for the display.
    let mut host = question("bob", "data.read", "host:prod", false);
    host["context"] = json!({"match": "subtree"});
    assert_eq!(ask(&server, &host)["decision"], true);
    // The default is `node`: the same question gets false.
    host["context"] = json!({"match": "node"});
    assert_eq!(ask(&server, &host)["decision"], false);
}

#[test]
fn p_4_3_a_node_that_the_directory_does_not_list_is_covered() {
    let server = start(&datastore());
    let answer = ask(
        &server,
        &question(
            "alice",
            "data.read",
            "host:prod/database:test1/table:ledger",
            false,
        ),
    );
    assert_eq!(answer["decision"], true);
    assert_eq!(answer["context"]["limits"]["max_rows"], 1000);
}

#[test]
fn p_11_1_the_reasons_for_a_false_answer() {
    let server = start(&datastore());
    let reason = |body: serde_json::Value| ask(&server, &body)["context"]["reason"].clone();
    assert_eq!(
        reason(question("carol", "data.read", TEST1, false)),
        "unknown_subject"
    );
    let mut other_type = question("alice", "data.read", TEST1, false);
    other_type["subject"]["type"] = json!("service");
    assert_eq!(reason(other_type), "unknown_subject");
    let mut no_chain = question("alice", "data.read", TEST1, false);
    no_chain["resource"]["properties"] = json!({});
    assert_eq!(reason(no_chain), "invalid_resource");
    let mut other_service = question("alice", "data.read", TEST1, false);
    other_service["resource"]["properties"]["ancestors"][0]["id"] = json!("elsewhere");
    assert_eq!(reason(other_service), "invalid_resource");
    let mut bad_type = question("alice", "data.read", TEST1, false);
    bad_type["resource"]["type"] = json!("schema");
    assert_eq!(reason(bad_type), "invalid_resource");
    // No reason when no grant covers the resource (11.2).
    assert_eq!(
        ask(&server, &question("alice", "data.read", "host:dev", false)),
        json!({"decision": false})
    );
}

#[test]
fn p_11_1_a_key_that_is_revoked_expired_or_without_owner_is_an_unknown_subject() {
    let mut data = datastore();
    data["subjects"].as_array_mut().unwrap().extend([
        json!({"id": "key:revoked1", "owner": "alice", "state": "revoked", "grants": []}),
        json!({"id": "key:expired1", "owner": "alice", "state": "expired", "grants": []}),
        json!({"id": "key:orphan1", "owner": "nobody", "grants": []}),
    ]);
    let server = start(&data);
    for id in ["key:revoked1", "key:expired1", "key:orphan1"] {
        let answer = ask(&server, &question(id, "data.read", TEST1, false));
        assert_eq!(answer["context"]["reason"], "unknown_subject", "{id}");
    }
}

#[test]
fn p_10_7_the_server_keeps_the_connection_open_between_questions() {
    let server = start(&datastore());
    let mut client = Client::connect(server.local_addr());
    for _ in 0..5 {
        let reply = client.post_json(EVALUATION, &question("alice", "data.read", TEST1, false));
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("connection"), Some("keep-alive"));
        assert_eq!(reply.header("keep-alive"), Some("timeout=30"));
        assert_eq!(reply.header("content-type"), Some("application/json"));
    }
    let reply = client.send(
        "POST",
        EVALUATION,
        &[
            ("Content-Type", "application/json"),
            ("Connection", "close"),
        ],
        Some(
            question("alice", "data.read", TEST1, false)
                .to_string()
                .as_bytes(),
        ),
    );
    assert_eq!(reply.header("connection"), Some("close"));
    assert!(
        client.read_reply().is_none(),
        "the server closes the connection"
    );
}

#[test]
fn the_server_echoes_the_request_id() {
    let server = start(&datastore());
    let body = question("alice", "data.read", TEST1, false);
    let reply = Client::connect(server.local_addr()).post_json_with(
        EVALUATION,
        &[("X-Request-ID", "bfe9eb29-ab87-4ca3-be83-a1d5d8305716")],
        &body,
    );
    assert_eq!(
        reply.header("x-request-id"),
        Some("bfe9eb29-ab87-4ca3-be83-a1d5d8305716")
    );
    // Also for an error, and for the metadata.
    let reply = Client::connect(server.local_addr()).send(
        "POST",
        EVALUATION,
        &[
            ("X-Request-ID", "abc"),
            ("Content-Type", "application/json"),
        ],
        Some(b"{"),
    );
    assert_eq!(reply.status, 400);
    assert_eq!(reply.header("x-request-id"), Some("abc"));
    let reply = Client::connect(server.local_addr()).send(
        "GET",
        "/.well-known/authzen-configuration",
        &[("X-Request-ID", "m1")],
        None,
    );
    assert_eq!(reply.header("x-request-id"), Some("m1"));
    // Without an id, the answer has none.
    let reply = Client::connect(server.local_addr()).post_json(EVALUATION, &body);
    assert_eq!(reply.header("x-request-id"), None);
}

#[test]
fn the_server_shuts_down_and_closes_the_port() {
    let server = start(&datastore());
    let addr = server.local_addr();
    assert_eq!(
        Client::connect(addr)
            .get("/.well-known/authzen-configuration")
            .status,
        200
    );
    server.shutdown();
    assert!(std::net::TcpStream::connect(addr).is_err());
}
