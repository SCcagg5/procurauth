//! Strict validation of the requests, and the Access Evaluations API (AuthZEN 1.0; protocol 4.4, 6.4, 11.1).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{Value, json};

const FIXED_400: &str = r#"{"error":"Bad Request"}"#;

fn post(
    server: &fake_pdp::RunningServer,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Reply {
    Client::connect(server.local_addr()).send("POST", path, headers, Some(body))
}

fn json_headers() -> [(&'static str, &'static str); 1] {
    [("Content-Type", "application/json")]
}

#[test]
fn a_bad_request_gets_http_400_with_a_fixed_body_that_leaks_nothing() {
    let server = start(&datastore());
    let mut no_subject = question("alice", "data.read", TEST1, false);
    no_subject.as_object_mut().unwrap().remove("subject");
    let mut bad_context = question("alice-secret-id", "data.read", TEST1, false);
    bad_context["context"] = json!({"match": "everything"});
    let mut bad_chain = question("alice", "data.read", TEST1, false);
    bad_chain["resource"]["properties"]["ancestors"] = json!("host:prod");
    let mut bad_item = question("alice", "data.read", TEST1, false);
    bad_item["resource"]["properties"]["ancestors"] = json!([{"type": "service"}]);
    let bodies: Vec<Vec<u8>> = vec![
        no_subject.to_string().into_bytes(),
        bad_context.to_string().into_bytes(),
        bad_chain.to_string().into_bytes(),
        bad_item.to_string().into_bytes(),
        b"{".to_vec(),
        b"[]".to_vec(),
        b"\"text\"".to_vec(),
        b"".to_vec(),
        br#"{"subject": {"type": "user", "id": "a"}, "subject": {"type": "user", "id": "b"}}"#.to_vec(),
        b"\xff\xfe".to_vec(),
        // A subject with a type that is not a string.
        br#"{"subject": {"type": 1, "id": "a"}, "action": {"name": "x"}, "resource": {"type": "service", "id": "datastore"}}"#.to_vec(),
    ];
    for body in bodies {
        let reply = post(&server, EVALUATION, &json_headers(), &body);
        assert_eq!(reply.status, 400, "{}", String::from_utf8_lossy(&body));
        assert_eq!(reply.text(), FIXED_400, "the body gives no detail");
    }
    assert!(server.log().is_empty(), "a bad request is not a question");
}

#[test]
fn the_content_type_must_be_application_json() {
    let server = start(&datastore());
    let body = question("alice", "data.read", TEST1, false).to_string();
    assert_eq!(post(&server, EVALUATION, &[], body.as_bytes()).status, 415);
    assert_eq!(
        post(
            &server,
            EVALUATION,
            &[("Content-Type", "text/plain")],
            body.as_bytes()
        )
        .status,
        415
    );
    for good in [
        "application/json",
        "Application/JSON",
        "application/json; charset=utf-8",
    ] {
        assert_eq!(
            post(
                &server,
                EVALUATION,
                &[("Content-Type", good)],
                body.as_bytes()
            )
            .status,
            200,
            "{good}"
        );
    }
}

#[test]
fn authzen_a_receiver_ignores_an_unknown_member() {
    let server = start(&datastore());
    let mut q = question("alice", "data.read", TEST1, false);
    q["extra"] = json!({"anything": true});
    q["subject"]["properties"] = json!({"department": "x"});
    q["action"]["properties"] = json!({"method": "GET"});
    q["context"] = json!({"time": "2024-05-31T15:22-07:00"});
    assert_eq!(ask(&server, &q)["decision"], true);
}

#[test]
fn p_4_4_a_bad_match_gets_http_400_for_one_evaluation() {
    let server = start(&datastore());
    for value in [json!("tree"), json!(1), json!(null)] {
        let mut q = question("alice", "data.read", TEST1, false);
        q["context"] = json!({"match": value});
        assert_eq!(
            once_json(server.local_addr(), EVALUATION, &q).status,
            400,
            "{value}"
        );
    }
}

#[test]
fn p_11_1_a_bad_member_of_an_item_gets_invalid_request_and_the_other_items_go_on() {
    let server = start(&datastore());
    let good = question("alice", "data.read", TEST1, false);
    let mut bad_match = question("alice", "data.read", TEST1, false);
    bad_match["context"] = json!({"match": "tree"});
    let mut bad_chain = question("alice", "data.read", TEST1, false);
    bad_chain["resource"]["properties"]["ancestors"] = json!({"type": "service"});
    let body = json!({"evaluations": [good.clone(), bad_match, bad_chain, good]});
    let reply = once_json(server.local_addr(), EVALUATIONS, &body);
    assert_eq!(reply.status, 200);
    let answers = reply.json();
    let list = answers["evaluations"].as_array().unwrap();
    assert_eq!(list.len(), 4);
    assert_eq!(list[0]["decision"], true);
    assert_eq!(
        list[1],
        json!({"decision": false, "context": {"reason": "invalid_request"}})
    );
    assert_eq!(
        list[2],
        json!({"decision": false, "context": {"reason": "invalid_request"}})
    );
    assert_eq!(list[3]["decision"], true);
    assert!(answers.get("decision").is_none());
}

#[test]
fn authzen_an_item_without_a_required_member_gets_http_400() {
    let server = start(&datastore());
    let mut item = question("alice", "data.read", TEST1, false);
    item.as_object_mut().unwrap().remove("action");
    let body = json!({"evaluations": [item]});
    assert_eq!(
        once_json(server.local_addr(), EVALUATIONS, &body).status,
        400
    );
}

#[test]
fn authzen_the_top_level_members_are_the_defaults_of_the_items() {
    let server = start(&datastore());
    let q1 = question("alice", "data.read", TEST1, false);
    let q2 = question("alice", "data.read", TEST2, false);
    let body = json!({
        "subject": q1["subject"],
        "action": {"name": "data.read"},
        "evaluations": [
            {"resource": q1["resource"]},
            {"resource": q2["resource"]},
            {"action": {"name": "data.write"}, "resource": q2["resource"]},
            {"subject": {"type": "user", "id": "bob"}, "resource": q1["resource"]}
        ]
    });
    let reply = once_json(server.local_addr(), EVALUATIONS, &body);
    assert_eq!(reply.status, 200);
    let answers: Vec<Value> = reply.json()["evaluations"].as_array().unwrap().clone();
    assert_eq!(answers[0]["context"]["limits"]["max_rows"], 1000);
    assert_eq!(answers[1]["context"]["limits"]["max_rows"], 5000);
    assert_eq!(answers[2]["context"]["limits"], json!({"max_duration": 10}));
    assert_eq!(answers[3], json!({"decision": true}));
    // A top-level member that no item replaces is also needed.
    let body = json!({"evaluations": [{"resource": q1["resource"]}]});
    assert_eq!(
        once_json(server.local_addr(), EVALUATIONS, &body).status,
        400
    );
}

#[test]
fn authzen_the_evaluations_semantics() {
    let server = start(&datastore());
    let ok = question("alice", "data.read", TEST1, false);
    let no = question("alice", "data.write", TEST1, false);
    let items = json!([ok.clone(), no.clone(), ok.clone()]);
    let run = |semantic: Option<&str>| {
        let mut body = json!({"evaluations": items});
        if let Some(s) = semantic {
            body["options"] = json!({"evaluations_semantic": s});
        }
        let reply = once_json(server.local_addr(), EVALUATIONS, &body);
        assert_eq!(reply.status, 200);
        reply.json()["evaluations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["decision"].as_bool().unwrap())
            .collect::<Vec<_>>()
    };
    assert_eq!(run(None), [true, false, true]);
    assert_eq!(run(Some("execute_all")), [true, false, true]);
    assert_eq!(run(Some("deny_on_first_deny")), [true, false]);
    assert_eq!(run(Some("permit_on_first_permit")), [true]);
    // An unknown semantic is a bad request.
    let body = json!({"evaluations": items, "options": {"evaluations_semantic": "all"}});
    assert_eq!(
        once_json(server.local_addr(), EVALUATIONS, &body).status,
        400
    );
    let body = json!({"evaluations": items, "options": "x"});
    assert_eq!(
        once_json(server.local_addr(), EVALUATIONS, &body).status,
        400
    );
    // The questions after the short cut are not decided and not logged.
    let logged_before = server.log().len();
    run(Some("deny_on_first_deny"));
    assert_eq!(server.log().len(), logged_before + 2);
}

#[test]
fn p_11_1_a_question_for_the_service_itself_has_no_chain() {
    let server = start(&datastore());
    let q = question("alice", "access", "", false);
    assert_eq!(q["resource"], json!({"type": "service", "id": "datastore"}));
    assert_eq!(ask(&server, &q)["decision"], true);
    let mut with_empty_chain = q.clone();
    with_empty_chain["resource"]["properties"] = json!({"ancestors": []});
    assert_eq!(
        ask(&server, &with_empty_chain)["decision"],
        true,
        "an empty array is no chain (4.1)"
    );
}
