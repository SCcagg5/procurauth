//! The routes of the service with a test PDP, over real HTTP on the loopback address.
//! The tests cover success, 401, 403, 429 and 503. They also cover the ceilings, the options
//! route and the action document.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use access_token::cli::AlgName;
use access_token::make::Shape;
use common::*;
use fake_pdp::Options;
use fake_pdp::faults::read_faults_str;
use procurauth_core::action_document::ActionDocument;
use serde_json::{Value, json};

fn rows_path(extra: &str) -> String {
    format!("{ORDERS}/rows{extra}")
}

// ---- The action document (5.1) -------------------------------------------------------------------

#[test]
fn p_5_1_the_action_document_needs_no_token_and_is_a_good_document() {
    let s = stack();
    let reply = s.get("/.well-known/procurauth/actions", None);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.header("content-type"), Some("application/json"));
    let document = ActionDocument::parse_str(&reply.text()).unwrap();
    assert_eq!(document.server, SERVICE);
    assert!(document.action_lists_budget("data.read"));
    // No question to the PDP.
    assert!(s.pdp.log().is_empty());
}

#[test]
fn p_5_1_the_action_document_is_served_with_a_bad_token_too() {
    let s = stack();
    let mut shape = Shape {
        alg: None,
        typ: None,
        kid: None,
        crit: None,
        bad_signature: true,
    };
    shape.kid = Some("edge-ed25519".into());
    let token = s.edge.sign_with(&shape, &s.edge.claims("alice", None));
    assert_eq!(
        s.get("/.well-known/procurauth/actions", Some(&token))
            .status,
        200
    );
    assert_eq!(
        s.post("/.well-known/procurauth/actions", None, &json!({}))
            .status,
        405
    );
}

#[cfg(feature = "mcp")]
#[test]
fn p_13_the_document_of_the_service_is_the_document_of_the_test_data() {
    let data = pdp_data();
    let from_data = ActionDocument::from_value(&data["services"][0]["document"]).unwrap();
    let ours = reference_service::document::reference_document(SERVICE).unwrap();
    assert_eq!(ours, from_data);
}

// ---- The identity token (9.4) -----------------------------------------------------------------------------

#[test]
fn p_9_4_a_request_without_a_valid_token_gets_401_with_no_body_and_no_question() {
    let s = stack();
    let mut bad_signature = Shape {
        alg: None,
        typ: None,
        kid: Some("edge-ed25519".into()),
        crit: None,
        bad_signature: true,
    };
    let bad = s
        .edge
        .sign_with(&bad_signature, &s.edge.claims("alice", None));
    bad_signature.bad_signature = false;
    bad_signature.alg = Some(AlgName::Hs256);
    let hs = s
        .edge
        .sign_with(&bad_signature, &s.edge.claims("alice", None));
    for path in [
        ORDERS.to_owned() + "/rows",
        ORDERS.to_owned() + "/schema",
        "/hosts".to_owned(),
        "/.well-known/procurauth/resources?type=host".to_owned(),
        "/mcp".to_owned(),
        "/nothing".to_owned(),
    ] {
        for token in [
            None,
            Some(bad.as_str()),
            Some(hs.as_str()),
            Some("not a token"),
        ] {
            let reply = s.get(&path, token);
            assert_eq!(reply.status, 401, "{path}");
            assert!(reply.body.is_empty(), "{path}");
        }
    }
    assert!(s.pdp.log().is_empty());
}

#[test]
fn p_9_4_the_token_is_taken_only_from_the_header_of_the_edge() {
    let s = stack();
    let token = s.edge.token("alice");
    let addr = s.service.local_addr();
    let bearer = format!("Bearer {token}");
    let cookie = format!("token={token}");
    assert_eq!(
        send(
            addr,
            "GET",
            &rows_path(""),
            &[("Authorization", &bearer)],
            None
        )
        .status,
        401
    );
    assert_eq!(
        send(addr, "GET", &rows_path(""), &[("Cookie", &cookie)], None).status,
        401
    );
    assert_eq!(
        send(
            addr,
            "GET",
            &format!("{}&access_token={token}", rows_path("?limit=1")),
            &[],
            None
        )
        .status,
        401
    );
    assert!(s.pdp.log().is_empty());
}

#[test]
fn p_9_4_a_token_with_a_good_header_and_a_standalone_key_in_authorization_is_good() {
    let s = stack();
    let token = s.edge.token("alice");
    let reply = send(
        s.service.local_addr(),
        "GET",
        &rows_path("?limit=1"),
        &[
            ("X-Identity-Token", &token),
            (
                "Authorization",
                "Bearer mcp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
        ],
        None,
    );
    assert_eq!(reply.status, 200);
}

// ---- A use (6.4, 10.3) -------------------------------------------------------------------------------------------

#[test]
fn p_13_alice_reads_the_table_orders_with_max_rows_100() {
    let s = stack();
    let reply = s.get(&rows_path(""), Some(&s.edge.token("alice")));
    assert_eq!(reply.status, 200);
    let body = reply.json();
    // The default is 100 rows. The ceiling of Alice on this table is 100 rows too.
    assert_eq!(body["count"], 100);
    assert_eq!(body["limit"], 100);
    assert_eq!(body["truncated"], true);
    assert_eq!(body["timeout_seconds"], 30);
    assert_eq!(s.used("alice", "second"), 1);
    assert_eq!(s.used("alice", "minute"), 1);
}

#[test]
fn p_7_5_the_ceiling_max_rows_lowers_a_request_and_leaves_a_lower_one() {
    let s = stack();
    let token = s.edge.token("alice");
    // The request asks for 5000 rows. The ceiling is 100.
    let body = s.get(&rows_path("?limit=5000"), Some(&token)).json();
    assert_eq!(
        (body["count"].as_u64(), body["limit"].as_u64()),
        (Some(100), Some(100))
    );
    let body = s.get(&rows_path("?limit=7"), Some(&token)).json();
    assert_eq!(
        (body["count"].as_u64(), body["truncated"].clone()),
        (Some(7), json!(true))
    );
    // On `test1`, the ceiling is 1000, and the table has 30 rows.
    let body = s
        .get(
            "/hosts/prod/databases/test1/tables/orders/rows?limit=5000",
            Some(&token),
        )
        .json();
    assert_eq!(
        (
            body["count"].as_u64(),
            body["limit"].as_u64(),
            body["truncated"].clone()
        ),
        (Some(30), Some(1000), json!(false))
    );
}

#[test]
fn p_7_5_the_ceiling_max_duration_lowers_the_timeout_and_a_write_above_it_is_refused() {
    let s = stack();
    let token = s.edge.token("alice");
    let body = s
        .get(&rows_path("?timeout_seconds=99"), Some(&token))
        .json();
    assert_eq!(body["timeout_seconds"], 30);
    let body = s.get(&rows_path("?timeout_seconds=3"), Some(&token)).json();
    assert_eq!(body["timeout_seconds"], 3);
    // A write on `test2`: the ceiling is 10 seconds. The route refuses a request above it.
    let write = "/hosts/prod/databases/test2/tables/orders/rows?timeout_seconds=11";
    let reply = s.post(write, Some(&token), &json!({"rows": [{"id": 1}]}));
    assert_eq!(reply.status, 422);
    assert_eq!(
        reply.json(),
        json!({"error": "ceiling_exceeded", "name": "max_duration", "limit": 10})
    );
    let reply = s.post(
        "/hosts/prod/databases/test2/tables/orders/rows?timeout_seconds=10",
        Some(&token),
        &json!({"rows": [{"id": 1}, {"id": 2}]}),
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json(), json!({"appended": 2, "total": 2002}));
}

#[test]
fn p_13_the_key_of_alice_reads_with_the_lowest_ceiling() {
    let s = stack();
    let token = s.edge.key_token(KEY_ALICE, "alice");
    let reply = s.get(
        "/hosts/prod/databases/test2/tables/customers/rows?limit=1000",
        Some(&token),
    );
    assert_eq!(reply.status, 200);
    // The key has 10000, and Alice has 5000: the lowest value applies. The table has 50 rows.
    let body = reply.json();
    assert_eq!(
        (body["count"].as_u64(), body["limit"].as_u64()),
        (Some(50), Some(1000))
    );
    let reply = s.get(&rows_path("?limit=1000"), Some(&token));
    assert_eq!(
        reply.json()["limit"],
        100,
        "the grant of Alice on the table orders gives 100"
    );
}

#[test]
fn p_10_3_a_false_answer_gives_403_and_the_body_never_shows_the_reason() {
    let s = stack();
    // Alice has `data.read` on `test1` and no `data.write`. The other two subjects are unknown to the PDP.
    let path = "/hosts/prod/databases/test1/tables/orders/rows";
    for sub in ["alice", "nobody", "robot:7"] {
        let reply = s.post(path, Some(&s.edge.token(sub)), &json!({"rows": []}));
        assert_eq!(reply.status, 403, "{sub}");
        assert_eq!(reply.json(), json!({"error": "forbidden"}));
        assert!(!reply.text().contains("unknown_subject"));
    }
}

#[test]
fn p_6_5_a_spent_budget_gives_429_with_retry_after_and_a_body_without_the_reason() {
    let s = stack();
    let token = s.edge.token("alice");
    for _ in 0..10 {
        assert_eq!(s.get(&rows_path("?limit=1"), Some(&token)).status, 200);
    }
    let reply = s.get(&rows_path("?limit=1"), Some(&token));
    assert_eq!(reply.status, 429);
    let seconds: u64 = reply.header("retry-after").unwrap().parse().unwrap();
    assert!((1..=60).contains(&seconds));
    assert_eq!(reply.json(), json!({"error": "rate_limited"}));
    assert!(!reply.text().contains("budget_exceeded"));
    // A refused use took no unit.
    assert_eq!(s.used("alice", "second"), 10);
}

#[test]
fn p_10_3_a_pdp_that_gives_no_valid_answer_gives_503() {
    let s = stack_with(
        &pdp_data(),
        Options {
            extra_faults: read_faults_str(r#"{"failures":[{"kind":"error_503"}]}"#).unwrap(),
            ..Options::default()
        },
        |_| {},
    );
    let reply = s.get(&rows_path(""), Some(&s.edge.token("alice")));
    assert_eq!(reply.status, 503);
    assert_eq!(reply.json(), json!({"error": "unavailable"}));
}

#[test]
fn p_10_6_a_lost_answer_to_a_use_is_not_asked_again() {
    let s = stack_with(
        &pdp_data(),
        Options {
            extra_faults: read_faults_str(
                r#"{"failures":[{"kind":"close","when":{"usage":true},"times":1}]}"#,
            )
            .unwrap(),
            ..Options::default()
        },
        |_| {},
    );
    let token = s.edge.token("alice");
    assert_eq!(s.get(&rows_path("?limit=1"), Some(&token)).status, 503);
    // One question with usage, and the unit stays counted.
    assert_eq!(s.pdp.log().iter().filter(|e| e.usage).count(), 1);
    assert_eq!(s.used("alice", "second"), 1);
    assert_eq!(s.get(&rows_path("?limit=1"), Some(&token)).status, 200);
}

#[test]
fn p_6_12_a_true_answer_without_units_gives_403() {
    let s = stack_with(
        &pdp_data(),
        Options {
            extra_faults: read_faults_str(
                r#"{"failures":[{"kind":"no_units","when":{"usage":true}}]}"#,
            )
            .unwrap(),
            ..Options::default()
        },
        |_| {},
    );
    assert_eq!(
        s.get(&rows_path(""), Some(&s.edge.token("alice"))).status,
        403
    );
}

#[test]
fn p_10_1_the_service_asks_one_question_with_usage_for_a_use_that_lists_a_budget() {
    let s = stack();
    s.get(&rows_path("?limit=1"), Some(&s.edge.token("alice")));
    let log = s.pdp.log();
    assert_eq!(log.len(), 1);
    assert!(log[0].usage);
    assert_eq!(log[0].action, "data.read");
    assert_eq!(
        log[0].resource,
        "service:datastore/host:prod/database:test2/table:orders"
    );
}

#[test]
fn p_6_4_a_use_of_an_action_without_a_budget_sends_no_usage() {
    let s = stack();
    let reply = s.get(
        "/hosts/prod/databases/test2/tables/orders/schema",
        Some(&s.edge.token("alice")),
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["rows"], 2000);
    let log = s.pdp.log();
    assert_eq!(log.len(), 1);
    assert!(!log[0].usage);
    assert_eq!(log[0].action, "data.inspect");
}

#[test]
fn p_15_a_use_of_the_service_itself_asks_an_action_on_the_type_service() {
    let s = stack();
    let reply = s.get("/hosts", Some(&s.edge.token("alice")));
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json(), json!({"hosts": ["prod", "staging"]}));
    let log = s.pdp.log();
    assert_eq!(log[0].resource, "service:datastore");
    // Bob has `data.inspect` on `test1` only.
    assert_eq!(s.get("/hosts", Some(&s.edge.token("bob"))).status, 403);
}

#[test]
fn p_4_5_the_chain_comes_from_the_service_and_an_id_with_a_slash_is_one_id() {
    let s = stack();
    let reply = s.get(
        "/hosts/prod/databases/a%2Fb/tables/t/schema",
        Some(&s.edge.token("alice")),
    );
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json()["rows"], 3);
    let log = s.pdp.log();
    assert_eq!(
        log[0].resource,
        "service:datastore/host:prod/database:a%2Fb/table:t"
    );
}

#[test]
fn a_node_that_does_not_exist_gets_404_after_the_permission() {
    let s = stack();
    let token = s.edge.token("alice");
    assert_eq!(
        s.get(
            "/hosts/prod/databases/test2/tables/none/schema",
            Some(&token)
        )
        .status,
        404
    );
    assert_eq!(s.get("/nothing", Some(&token)).status, 404);
    // Bob has no right on `test2`: he gets 403, and not 404, so he learns nothing about the node.
    assert_eq!(
        s.get(
            "/hosts/prod/databases/test2/tables/none/schema",
            Some(&s.edge.token("bob"))
        )
        .status,
        403
    );
}

#[test]
fn a_bad_parameter_gets_400_before_any_question() {
    let s = stack();
    let token = s.edge.token("alice");
    for query in [
        "?limit=0",
        "?limit=abc",
        "?limit=1&limit=2",
        "?limit=1.5",
        "?limit=%zz",
    ] {
        assert_eq!(
            s.get(&rows_path(query), Some(&token)).status,
            400,
            "{query}"
        );
    }
    assert!(s.pdp.log().is_empty());
}

#[test]
fn a_method_that_the_route_does_not_know_gets_405() {
    let s = stack();
    let token = s.edge.token("alice");
    let reply = send(
        s.service.local_addr(),
        "DELETE",
        &rows_path(""),
        &[("X-Identity-Token", &token)],
        None,
    );
    assert_eq!(reply.status, 405);
    assert_eq!(reply.header("allow"), Some("GET, POST"));
}

// ---- Two permissions (5.5a, 10.1a) -----------------------------------------------------------------------------------

#[test]
fn p_10_1a_a_copy_reads_the_source_without_usage_and_writes_the_target_with_usage() {
    let s = stack();
    let token = s.edge.token("alice");
    let body = json!({"from": {"host": "prod", "database": "test1", "table": "orders"}, "to": {"host": "prod", "database": "test2"}});
    let reply = s.post("/copy", Some(&token), &body);
    assert_eq!(reply.status, 200);
    // `max_rows` is 1000 on `test1`, and the table has 30 rows.
    assert_eq!(reply.json(), json!({"copied": 30, "truncated": false}));
    let log = s.pdp.log();
    assert_eq!(log.len(), 2);
    assert_eq!((log[0].action.as_str(), log[0].usage), ("data.read", false));
    assert_eq!((log[1].action.as_str(), log[1].usage), ("data.write", true));
    assert_eq!(s.used("alice", "second"), 1);
}

#[test]
fn p_10_1a_when_the_other_permission_is_false_the_copy_is_refused_and_no_question_has_usage() {
    let s = stack();
    // The key of Alice has no grant on `test1`.
    let token = s.edge.key_token(KEY_ALICE, "alice");
    let body = json!({"from": {"host": "prod", "database": "test1", "table": "orders"}, "to": {"host": "prod", "database": "test2"}});
    assert_eq!(s.post("/copy", Some(&token), &body).status, 403);
    assert!(s.pdp.log().iter().all(|e| !e.usage));
}

#[test]
fn p_7_5_the_ceiling_of_the_read_lowers_the_number_of_rows_of_a_copy() {
    let s = stack();
    let token = s.edge.token("alice");
    // The read of `test2` has 5000 rows at most, and the table `orders` has 100 as the ceiling.
    let body = json!({"from": {"host": "prod", "database": "test2", "table": "orders"}, "to": {"host": "prod", "database": "test2"}});
    let reply = s.post("/copy", Some(&token), &body);
    assert_eq!(reply.status, 200);
    assert_eq!(reply.json(), json!({"copied": 100, "truncated": true}));
}

// ---- The options route (5.6 to 5.8) -----------------------------------------------------------------------------------

#[test]
fn p_5_8_the_options_route_lists_the_children_that_the_subject_can_see() {
    let s = stack();
    let token = s.edge.token("alice");
    let reply = s.get("/.well-known/procurauth/resources?type=host", Some(&token));
    assert_eq!(reply.status, 200);
    let answer = reply.json();
    assert_eq!(
        answer["items"],
        json!([{"id": "prod", "label": "prod", "has_children": true}])
    );
    assert_eq!(answer["next"], Value::Null);
    let reply = s.get(
        "/.well-known/procurauth/resources?parent=host%3Aprod&type=database&q=test&limit=2",
        Some(&token),
    );
    let ids: Vec<_> = reply.json()["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|i| i["id"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(ids, ["test1", "test2"]);
    // The questions have `context.match` equal to `subtree` and no usage.
    assert!(s.pdp.log().iter().all(|e| !e.usage));
}

#[test]
fn p_5_7_a_bad_query_gets_400() {
    let s = stack();
    let token = s.edge.token("alice");
    for query in [
        "",
        "limit=5",
        "type=host&type=host",
        "type=host&limit=2&limit=2",
        "type=host&limit=0",
        "type=host&limit=-1",
        "type=host&limit=abc",
        "type=host&limit=1.5",
        "parent=host%3Ax&type=host",
        "parent=%zz&type=host",
        "type=database",
    ] {
        let reply = s.get(
            &format!("/.well-known/procurauth/resources?{query}"),
            Some(&token),
        );
        assert_eq!(reply.status, 400, "{query}");
    }
    assert!(s.pdp.log().is_empty());
    // An unknown parameter is ignored.
    assert_eq!(
        s.get(
            "/.well-known/procurauth/resources?type=host&x_unknown=1",
            Some(&token)
        )
        .status,
        200
    );
}

#[test]
fn p_5_6_a_pdp_that_gives_an_error_gives_503_on_the_options_route() {
    let s = stack_with(
        &pdp_data(),
        Options {
            extra_faults: read_faults_str(r#"{"failures":[{"kind":"error_503"}]}"#).unwrap(),
            ..Options::default()
        },
        |_| {},
    );
    assert_eq!(
        s.get(
            "/.well-known/procurauth/resources?type=host",
            Some(&s.edge.token("alice"))
        )
        .status,
        503
    );
}

// ---- The log -------------------------------------------------------------------------------------------------------------------

#[test]
fn the_log_has_the_method_the_path_and_the_status_and_never_a_token_or_a_query() {
    let s = stack();
    let token = s.edge.token("alice");
    s.get(&rows_path("?limit=1&secret=zzz"), Some(&token));
    s.get(&rows_path(""), None);
    let text = s.log.text();
    assert!(text.contains(&format!("GET {ORDERS}/rows 200")), "{text}");
    assert!(text.contains(&format!("GET {ORDERS}/rows 401")), "{text}");
    assert!(!text.contains(&token));
    assert!(!text.contains("zzz"));
    assert!(!text.contains(CREDENTIAL));
}
