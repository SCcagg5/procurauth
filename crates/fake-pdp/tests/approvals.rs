//! The approval of an effect (protocol section 17).
//! The tests cover the questions with an effect and the narrow API for a PEP.
//! They also cover the test control that stands for the owner.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use common::*;
use fake_pdp::RunningServer;
use procurauth_core::effect::effect_hash;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const KEY: &str = "key:conf0001";
const ANALYTICS: &str = "host:prod/database:analytics";
const REQUESTS: &str = "/approval/v1/requests";

fn directory() -> Value {
    let text = include_str!("../../../conformance/directories/approvals.json");
    serde_json::from_str(text).unwrap()
}

fn op() -> Value {
    json!({"tool": "run_write_query", "database": "analytics", "sql": "DELETE FROM events"})
}

fn view() -> Value {
    json!({"title": "Write", "fields": [["Database", "/database"]], "body": "/sql", "body_label": "SQL"})
}

fn effect(op: &Value) -> String {
    effect_hash("datastore", "data.write", ANALYTICS, op).unwrap()
}

/// A question for the use of `data.write` on the database analytics.
fn ask_effect(subject: &str, effect: Option<&str>, usage: bool) -> Value {
    let mut body = question(subject, "data.write", ANALYTICS, false);
    let mut context = json!({});
    if usage {
        context["usage"] = json!({"units": 1});
    }
    if let Some(effect) = effect {
        context["approval"] = json!({"effect": effect});
    }
    if context != json!({}) {
        body["context"] = context;
    }
    body
}

fn submission(evaluation_id: &str, op: &Value, extra: Value) -> Value {
    let mut body = json!({
        "evaluation_id": evaluation_id,
        "effect": effect(op),
        "op": op,
        "view": view(),
    });
    for (key, value) in extra.as_object().unwrap() {
        body[key] = value.clone();
    }
    body
}

fn evaluation_id(server: &RunningServer, subject: &str, op: &Value) -> String {
    let answer = ask(server, &ask_effect(subject, Some(&effect(op)), false));
    assert_eq!(answer["context"]["reason"], "approval_required", "{answer}");
    answer["context"]["evaluation_id"]
        .as_str()
        .unwrap()
        .to_owned()
}

fn submit(server: &RunningServer, body: &Value) -> Reply {
    Client::connect(server.local_addr()).post_json(REQUESTS, body)
}

fn read(server: &RunningServer, id: &str, query: &str) -> Reply {
    Client::connect(server.local_addr()).get(&format!("{REQUESTS}/{id}?{query}"))
}

fn admin_post(server: &RunningServer, path: &str, body: &Value) -> Reply {
    Client::connect(server.local_addr()).post_json(path, body)
}

fn answer(server: &RunningServer, id: &str, body: &Value) -> Reply {
    admin_post(server, &format!("/__fake/approvals/{id}/answer"), body)
}

/// Make a request that waits, with a lease of 60 seconds. Return its id.
fn waiting_request(server: &RunningServer, op: &Value) -> String {
    let id = evaluation_id(server, KEY, op);
    let reply = submit(server, &submission(&id, op, json!({"lease_s": 60})));
    assert_eq!(reply.status, 201, "{}", reply.text());
    reply.json()["request_id"].as_str().unwrap().to_owned()
}

#[test]
fn p_17_1_a_question_with_no_effect_gets_approval_required_and_no_evaluation_id() {
    let server = start_admin(&directory());
    let answer = ask(&server, &ask_effect(KEY, None, false));
    assert_eq!(
        answer,
        json!({"decision": false, "context": {"reason": "approval_required"}})
    );
}

#[test]
fn p_17_1_the_whole_course_of_an_approval() {
    let server = start_admin(&directory());
    let op = op();
    let effect = effect(&op);

    // No approval: approval_required, with the evaluation_id. No unit is taken.
    let first = ask(&server, &ask_effect(KEY, Some(&effect), true));
    assert_eq!(first["decision"], false);
    assert_eq!(first["context"]["reason"], "approval_required");
    assert!(first["context"].get("usage").is_none());
    let evaluation_id = first["context"]["evaluation_id"].as_str().unwrap();

    // The submission makes a request that waits.
    let body = submission(evaluation_id, &op, json!({"lease_s": 120}));
    let created = submit(&server, &body);
    assert_eq!(created.status, 201);
    let created = created.json();
    assert_eq!(created["verdict"], "pending");
    let request_id = created["request_id"].as_str().unwrap().to_owned();
    assert_eq!(created["code"].as_str().unwrap().len(), 4);
    let object = created.as_object().unwrap();
    assert_eq!(object.len(), 3, "{created}");

    // The same request again: HTTP 200 with the same id and the same code.
    let again = submit(&server, &body);
    assert_eq!(again.status, 200);
    assert_eq!(again.json(), created);

    // The question gets approval_pending, with and without usage.
    for usage in [false, true] {
        let pending = ask(&server, &ask_effect(KEY, Some(&effect), usage));
        assert_eq!(pending["context"]["reason"], "approval_pending");
        assert!(pending["context"]["evaluation_id"].is_string());
    }
    let verdict = read(&server, &request_id, &format!("subject={KEY}"));
    assert_eq!(
        (verdict.status, verdict.json()),
        (200, json!({"verdict": "pending"}))
    );

    // The owner approves.
    let reply = answer(&server, &request_id, &json!({"decision": "approve"}));
    assert_eq!(reply.status, 200, "{}", reply.text());
    let verdict = read(&server, &request_id, &format!("subject={KEY}"));
    assert_eq!(verdict.json(), json!({"verdict": "approved"}));

    // Without usage the answer is true, and nothing is consumed.
    for _ in 0..2 {
        let free = ask(&server, &ask_effect(KEY, Some(&effect), false));
        assert_eq!(free["decision"], true);
        assert!(free["context"].get("usage").is_none());
    }
    // With usage the use takes the approval, in one decision, with the unit (0: no budget).
    let used = ask(&server, &ask_effect(KEY, Some(&effect), true));
    assert_eq!(used["decision"], true);
    assert_eq!(used["context"]["usage"]["units"], 0);
    // One use only.
    let second = ask(&server, &ask_effect(KEY, Some(&effect), true));
    assert_eq!(second["context"]["reason"], "approval_required");
    // The verdict stays approved: the approval is consumed.
    let verdict = read(&server, &request_id, &format!("subject={KEY}"));
    assert_eq!(verdict.json(), json!({"verdict": "approved"}));
}

#[test]
fn p_17_2_a_refusing_budget_leaves_the_approval_usable() {
    let mut data = directory();
    // The seeded approval apr_d81 of the key budget001 exists. Spend its budget.
    data["counters"] =
        json!([{"subject": "key:budget001", "limit": "requests", "window": "minute", "used": 1}]);
    let server = start_admin(&data);
    let effect = "sha256:84fa10f48af3225f0bd9fcdb071860f5a3045a9d651acf14d092da809c45178c";
    let refused = ask(&server, &ask_effect("key:budget001", Some(effect), true));
    assert_eq!(refused["context"]["reason"], "budget_exceeded");
    assert_eq!(refused["context"]["retry_after"], 12);
    // A new minute gives the unit back, and the same approval gives the use.
    admin_post(&server, "/__fake/clock", &json!({"advance": 12}));
    let used = ask(&server, &ask_effect("key:budget001", Some(effect), true));
    assert_eq!(used["decision"], true, "{used}");
    assert_eq!(used["context"]["usage"]["units"], 1);
}

#[test]
fn p_17_6_a_decline_gives_a_deny_time_and_the_pep_never_learns_the_text() {
    let server = start_admin(&directory());
    let op = op();
    let id = evaluation_id(&server, KEY, &op);
    // The intent of the agent has no allow_custom: a text is refused.
    let request_id =
        submit(&server, &submission(&id, &op, json!({"lease_s": 60}))).json()["request_id"]
            .as_str()
            .unwrap()
            .to_owned();
    let refused = answer(
        &server,
        &request_id,
        &json!({"decision": "decline", "text": "use staging", "intent": "change_request"}),
    );
    assert_eq!(refused.status, 422);
    assert_eq!(refused.json(), json!({"error": "text_not_allowed"}));
    // An approve never has a text.
    let refused = answer(
        &server,
        &request_id,
        &json!({"decision": "approve", "text": "ok", "intent": "comment"}),
    );
    assert_eq!(refused.status, 422);
    let done = answer(
        &server,
        &request_id,
        &json!({"decision": "decline", "answered_by": "eliot", "device": "d:1"}),
    );
    assert_eq!(done.status, 200);
    // Only the first valid answer counts.
    let late = answer(&server, &request_id, &json!({"decision": "approve"}));
    assert_eq!(late.status, 409);

    let effect = effect(&op);
    for usage in [false, true] {
        let denied = ask(&server, &ask_effect(KEY, Some(&effect), usage));
        assert_eq!(
            denied,
            json!({"decision": false, "context": {"reason": "approval_denied"}})
        );
    }
    let verdict = read(&server, &request_id, &format!("subject={KEY}"));
    assert_eq!(verdict.text(), r#"{"verdict":"denied"}"#);
    // After the deny time the answer is as for no approval.
    admin_post(&server, "/__fake/clock", &json!({"advance": 300}));
    let after = ask(&server, &ask_effect(KEY, Some(&effect), false));
    assert_eq!(after["context"]["reason"], "approval_required");
}

#[test]
fn p_17_11_a_text_with_a_decline_goes_to_the_admin_view_only_when_the_intent_allows_it() {
    let server = start_admin(&directory());
    let op = op();
    let id = evaluation_id(&server, KEY, &op);
    let reference =
        json!({"ref": "ref_text", "subject": KEY, "lease_s": 600, "allow_custom": true});
    assert_eq!(
        admin_post(&server, "/__fake/approval-refs", &reference).status,
        200
    );
    let created = submit(
        &server,
        &submission(&id, &op, json!({"approval_ref": "ref_text"})),
    );
    assert_eq!(created.status, 201, "{}", created.text());
    let request_id = created.json()["request_id"].as_str().unwrap().to_owned();
    let done = answer(
        &server,
        &request_id,
        &json!({"decision": "decline", "text": "use staging", "intent": "change_request", "answered_by": "eliot"}),
    );
    assert_eq!(done.status, 200, "{}", done.text());
    // Nothing of the text, the owner or the device goes to the PEP, in any route.
    let effect = effect(&op);
    let question = once_json(
        server.local_addr(),
        EVALUATION,
        &ask_effect(KEY, Some(&effect), true),
    );
    let verdict = read(&server, &request_id, &format!("subject={KEY}&renew=true"));
    for text in [question.text(), verdict.text()] {
        assert!(
            !text.contains("staging") && !text.contains("eliot"),
            "{text}"
        );
    }
    let list = Client::connect(server.local_addr())
        .get("/__fake/approvals")
        .json();
    let mine = list["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == request_id.as_str())
        .unwrap();
    assert_eq!(mine["comment"]["text"], "use staging");
    assert_eq!(mine["answered_by"], "eliot");
    assert_eq!(mine["lease_s"], 600);
    assert_eq!(mine["op"], op);
}

#[test]
fn p_17_11_the_answer_needs_the_effect_that_the_owner_saw() {
    let server = start_admin(&directory());
    let request_id = waiting_request(&server, &op());
    let wrong = answer(
        &server,
        &request_id,
        &json!({"decision": "approve", "shown_effect": effect(&json!({"other": 1}))}),
    );
    assert_eq!(wrong.status, 422);
    assert_eq!(
        read(&server, &request_id, &format!("subject={KEY}")).json(),
        json!({"verdict": "pending"})
    );
    let right = answer(
        &server,
        &request_id,
        &json!({"decision": "approve", "shown_effect": effect(&op())}),
    );
    assert_eq!(right.status, 200);
    assert_eq!(
        answer(&server, "apr_none", &json!({"decision": "approve"})).status,
        404
    );
}

#[test]
fn p_17_5_a_lease_that_ends_abandons_the_request_and_a_renewal_revives_it() {
    let server = start_admin(&directory());
    let op = op();
    let request_id = waiting_request(&server, &op);
    let effect = effect(&op);
    let q = format!("subject={KEY}");
    // 3 times 60 seconds and a grace time of 120 seconds.
    admin_post(&server, "/__fake/clock", &json!({"advance": 301}));
    let void = read(&server, &request_id, &q);
    assert_eq!(void.json(), json!({"verdict": "void"}));
    // The question gets approval_required without usage, and approval_expired with usage.
    assert_eq!(
        ask(&server, &ask_effect(KEY, Some(&effect), false))["context"]["reason"],
        "approval_required"
    );
    assert_eq!(
        ask(&server, &ask_effect(KEY, Some(&effect), true))["context"]["reason"],
        "approval_expired"
    );
    // A read with no renew=true revives nothing. A keepalive does.
    assert_eq!(read(&server, &request_id, &q).json()["verdict"], "void");
    let path = format!("{REQUESTS}/{request_id}/keepalive");
    let revived = Client::connect(server.local_addr()).post_json(&path, &json!({"subject": KEY}));
    assert_eq!(
        (revived.status, revived.json()),
        (200, json!({"verdict": "pending"}))
    );
    // The owner can now answer.
    assert_eq!(
        answer(&server, &request_id, &json!({"decision": "approve"})).status,
        200
    );
    assert_eq!(read(&server, &request_id, &q).json()["verdict"], "approved");
}

#[test]
fn p_17_5_a_request_with_until_expires_at_that_time_and_a_past_time_is_refused() {
    let server = start_admin(&directory());
    let op = op();
    let id = evaluation_id(&server, KEY, &op);
    // The clock is 2026-10-21T08:00:48Z.
    let past = submit(
        &server,
        &submission(&id, &op, json!({"until": "2026-10-21T08:00:48Z"})),
    );
    assert_eq!(
        (past.status, past.json()),
        (422, json!({"error": "invalid_lease"}))
    );
    let created = submit(
        &server,
        &submission(&id, &op, json!({"until": "2026-10-21T08:05:00+00:00"})),
    );
    assert_eq!(created.status, 201, "{}", created.text());
    let request_id = created.json()["request_id"].as_str().unwrap().to_owned();
    let q = format!("subject={KEY}&renew=true");
    assert_eq!(read(&server, &request_id, &q).json()["verdict"], "pending");
    admin_post(&server, "/__fake/clock", &json!({"advance": 252}));
    assert_eq!(read(&server, &request_id, &q).json()["verdict"], "void");
}

#[test]
fn p_17_4_a_read_waits_for_a_verdict_other_than_pending() {
    let server = Arc::new(start_admin(&directory()));
    let request_id = waiting_request(&server, &op());
    let addr = server.local_addr();
    let result = Arc::new(Mutex::new(None));
    let waiter = {
        let (result, request_id) = (Arc::clone(&result), request_id.clone());
        thread::spawn(move || {
            let started = Instant::now();
            let reply = Client::connect(addr)
                .get(&format!("{REQUESTS}/{request_id}?subject={KEY}&wait=10"));
            *result.lock().unwrap() = Some((reply.json(), started.elapsed()));
        })
    };
    thread::sleep(Duration::from_millis(300));
    assert!(result.lock().unwrap().is_none(), "the read did not wait");
    assert_eq!(
        answer(&server, &request_id, &json!({"decision": "approve"})).status,
        200
    );
    waiter.join().unwrap();
    let (verdict, elapsed) = result.lock().unwrap().take().unwrap();
    assert_eq!(verdict, json!({"verdict": "approved"}));
    assert!(elapsed < Duration::from_secs(5), "{elapsed:?}");
}

#[test]
fn p_17_4_a_read_with_wait_returns_pending_when_the_time_ends() {
    let server = start_admin(&directory());
    let request_id = waiting_request(&server, &op());
    let started = Instant::now();
    let reply = read(&server, &request_id, &format!("subject={KEY}&wait=1"));
    assert_eq!(reply.json(), json!({"verdict": "pending"}));
    assert!(started.elapsed() >= Duration::from_millis(900));
    // A value above the bound waits at most that bound. It is not an error.
    assert_eq!(
        read(&server, &request_id, &format!("subject={KEY}&wait=0")).status,
        200
    );
}

#[test]
fn p_17_4_a_request_of_another_subject_or_of_no_one_gets_the_same_answer() {
    let server = start_admin(&directory());
    let request_id = waiting_request(&server, &op());
    let not_found = json!({"error": "not_found"});
    for (path, subject) in [
        (request_id.as_str(), "key:conf0002"),
        ("apr_unknown", KEY),
        ("apr_d78", "key:conf0002"),
    ] {
        let reply = read(&server, path, &format!("subject={subject}&renew=true"));
        assert_eq!(
            (reply.status, reply.json()),
            (404, not_found.clone()),
            "{path}"
        );
    }
    let path = format!("{REQUESTS}/{request_id}/keepalive");
    let reply =
        Client::connect(server.local_addr()).post_json(&path, &json!({"subject": "key:conf0002"}));
    assert_eq!((reply.status, reply.json()), (404, not_found));
}

#[test]
fn p_17_4_the_parameter_subject_is_mandatory_and_the_values_are_checked() {
    let server = start_admin(&directory());
    let request_id = waiting_request(&server, &op());
    for query in [
        "",
        "subject=",
        &format!("subject={KEY}&renew=yes"),
        &format!("subject={KEY}&wait=-1"),
        &format!("subject={KEY}&wait=abc"),
        "subject=%zz",
    ] {
        let reply = read(&server, &request_id, query);
        assert_eq!(
            (reply.status, reply.json()),
            (422, json!({"error": "invalid_argument"})),
            "{query}"
        );
    }
    // A subject with a colon works as text and as percent-encoded text.
    assert_eq!(
        read(&server, &request_id, "subject=key%3Aconf0001").status,
        200
    );
    let path = format!("{REQUESTS}/{request_id}/keepalive");
    let reply =
        Client::connect(server.local_addr()).post_json(&path, &json!({"subject": KEY, "x": 1}));
    assert_eq!(reply.status, 422);
}

#[test]
fn p_17_9_a_submission_is_checked_before_the_request_is_kept() {
    let server = start_admin(&directory());
    let op = op();
    let id = evaluation_id(&server, KEY, &op);
    let code = |body: &Value| {
        let reply = submit(&server, body);
        (
            reply.status,
            reply.json()["error"].as_str().unwrap_or("").to_owned(),
        )
    };
    let good = submission(&id, &op, json!({"lease_s": 60}));

    let mut b = good.clone();
    b["evaluation_id"] = json!("ev_unknown");
    assert_eq!(code(&b), (422, "invalid_evaluation".to_owned()));

    let mut b = good.clone();
    b["effect"] = json!(effect(&json!({"other": 1})));
    assert_eq!(code(&b), (422, "invalid_evaluation".to_owned()));

    // The effect that the question had, with another op: the effect is not the hash of the op.
    let mut b = good.clone();
    b["op"] = json!({"tool": "run_write_query", "database": "analytics", "sql": "DROP TABLE x"});
    assert_eq!(code(&b), (422, "effect_mismatch".to_owned()));

    for bad in [
        json!({"x": 1.5}),
        json!({"x": 9_007_199_254_740_992_u64}),
        json!([1]),
    ] {
        let mut b = good.clone();
        b["op"] = bad;
        assert_eq!(code(&b), (422, "invalid_op".to_owned()));
    }
    let mut b = good.clone();
    b["view"] = json!({"body": "/missing"});
    assert_eq!(code(&b), (422, "invalid_view".to_owned()));

    let mut b = good.clone();
    b["lease_s"] = json!(5);
    assert_eq!(code(&b), (422, "invalid_lease".to_owned()));
    b["lease_s"] = json!(1_000_000_000_u64);
    assert_eq!(code(&b), (422, "invalid_lease".to_owned()));
    let mut b = good.clone();
    b.as_object_mut().unwrap().remove("lease_s");
    assert_eq!(code(&b), (422, "lease_required".to_owned()));
    let mut b = good.clone();
    b["until"] = json!("2030-01-01T00:00:00Z");
    assert_eq!(code(&b), (422, "invalid_lease".to_owned()));

    let mut b = good.clone();
    b["approval_ref"] = json!("ref_none");
    b.as_object_mut().unwrap().remove("lease_s");
    assert_eq!(code(&b), (422, "invalid_argument".to_owned()));
    let mut b = good.clone();
    b["explanation"] = json!("the agent says so");
    assert_eq!(code(&b), (422, "invalid_argument".to_owned()));

    // A duplicate member name in op is invalid_op.
    let text = format!(
        r#"{{"evaluation_id":"{id}","effect":"{}","op":{{"a":1,"a":2}},"view":{{}},"lease_s":60}}"#,
        effect(&op)
    );
    let reply = Client::connect(server.local_addr()).send(
        "POST",
        REQUESTS,
        &[("Content-Type", "application/json")],
        Some(text.as_bytes()),
    );
    assert_eq!(
        (reply.status, reply.json()),
        (422, json!({"error": "invalid_op"}))
    );

    // A big command.
    let big = json!({"sql": "x".repeat(70_000)});
    let id_big = evaluation_id(&server, KEY, &big);
    let reply = submit(&server, &submission(&id_big, &big, json!({"lease_s": 60})));
    assert_eq!(
        (reply.status, reply.json()),
        (413, json!({"error": "command_too_large"}))
    );

    // No request exists after all these errors.
    let list = Client::connect(server.local_addr())
        .get("/__fake/approvals")
        .json();
    let mine = list["approvals"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|a| a["created"] != 0)
        .count();
    assert_eq!(mine, 0);
    assert_eq!(submit(&server, &good).status, 201);
}

#[test]
fn p_17_4_a_request_can_supersede_another_one_of_the_same_subject() {
    let server = start_admin(&directory());
    let first = waiting_request(&server, &op());
    let other = json!({"tool": "run_write_query", "database": "analytics", "sql": "DELETE 2"});
    let id = evaluation_id(&server, KEY, &other);
    let reply = submit(
        &server,
        &submission(&id, &other, json!({"lease_s": 60, "supersedes": first})),
    );
    assert_eq!(reply.status, 201);
    assert_eq!(
        read(&server, &first, &format!("subject={KEY}")).json(),
        json!({"verdict": "void"})
    );
    let id = evaluation_id(&server, KEY, &json!({"n": 1}));
    let reply = submit(
        &server,
        &submission(
            &id,
            &json!({"n": 1}),
            json!({"lease_s": 60, "supersedes": "apr_unknown"}),
        ),
    );
    assert_eq!(reply.status, 422);
}

#[test]
fn p_17_4_the_methods_and_the_paths_of_the_api_are_closed() {
    let server = start_admin(&directory());
    let request_id = waiting_request(&server, &op());
    let mut client = Client::connect(server.local_addr());
    let reply = client.get(REQUESTS);
    assert_eq!((reply.status, reply.header("allow")), (405, Some("POST")));
    let reply = client.post_json(&format!("{REQUESTS}/{request_id}"), &json!({}));
    assert_eq!((reply.status, reply.header("allow")), (405, Some("GET")));
    let reply = client.get(&format!("{REQUESTS}/{request_id}/keepalive"));
    assert_eq!((reply.status, reply.header("allow")), (405, Some("POST")));
    assert_eq!(
        client.get(&format!("{REQUESTS}/{request_id}/other")).status,
        404
    );
    assert_eq!(client.get("/approval/v1/other").status, 404);
    assert_eq!(client.get("/approval/v1/requestsx").status, 404);
    let reply = client.send("POST", REQUESTS, &[], Some(b"{}"));
    assert_eq!(reply.status, 415);
}

#[test]
fn p_17_4_a_service_with_no_approval_action_gets_403_and_each_service_sees_its_own_requests() {
    let mut data = directory();
    let digest = |text: &str| hex_of(&Sha256::digest(text.as_bytes()));
    data["services"][0]["credential_sha256"] = json!(digest("token-datastore"));
    data["services"].as_array_mut().unwrap().push(json!({
        "id": "other",
        "credential_sha256": digest("token-other"),
        "document": {"server": "other", "resource_types": [], "actions": []}
    }));
    let server = start_admin(&data);
    let addr = server.local_addr();
    let ds = [("Authorization", "Bearer token-datastore")];
    let other = [("Authorization", "Bearer token-other")];
    // The admin routes use the credential of the PDP too.
    let body = ask_effect(KEY, Some(&effect(&op())), false);
    let asked = Client::connect(addr).post_json_with(EVALUATION, &ds, &body);
    assert_eq!(asked.json()["context"]["reason"], "approval_required");
    let id = asked.json()["context"]["evaluation_id"]
        .as_str()
        .unwrap()
        .to_owned();
    let sub = submission(&id, &op(), json!({"lease_s": 60}));
    assert_eq!(Client::connect(addr).post_json(REQUESTS, &sub).status, 401);
    let reply = Client::connect(addr).post_json_with(REQUESTS, &other, &sub);
    assert_eq!(reply.status, 403);
    let created = Client::connect(addr).post_json_with(REQUESTS, &ds, &sub);
    assert_eq!(created.status, 201, "{}", created.text());
    let request_id = created.json()["request_id"].as_str().unwrap().to_owned();
    let path = format!("{REQUESTS}/{request_id}?subject={KEY}");
    let reply = Client::connect(addr).send("GET", &path, &ds, None);
    assert_eq!(reply.status, 200);
    assert_eq!(
        Client::connect(addr)
            .send("GET", &path, &other, None)
            .status,
        403
    );
}

fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn p_17_1_an_evaluation_id_is_for_one_subject_and_stays_valid_for_a_time() {
    let server = start_admin(&directory());
    let op = op();
    let id = evaluation_id(&server, KEY, &op);
    // Another subject cannot use it: the evaluation binds the subject. The submission names none,
    // so the request is for the subject of the evaluation, and another subject cannot read it.
    let created = submit(&server, &submission(&id, &op, json!({"lease_s": 60})));
    assert_eq!(created.status, 201);
    let request_id = created.json()["request_id"].as_str().unwrap().to_owned();
    assert_eq!(
        read(&server, &request_id, "subject=key:conf0002").status,
        404
    );
    // After the time that the PDP publishes, the id is late.
    let id = evaluation_id(&server, KEY, &json!({"n": 7}));
    admin_post(&server, "/__fake/clock", &json!({"advance": 301}));
    let late = submit(
        &server,
        &submission(&id, &json!({"n": 7}), json!({"lease_s": 60})),
    );
    assert_eq!(
        (late.status, late.json()),
        (422, json!({"error": "invalid_evaluation"}))
    );
}

#[test]
fn p_17_1_a_question_for_a_key_of_a_person_with_confirm_on_the_owner_side_needs_an_approval() {
    let server = start_admin(&directory());
    let effect = effect(&op());
    let answer = ask(&server, &ask_effect("key:ownconf01", Some(&effect), false));
    assert_eq!(answer["context"]["reason"], "approval_required");
    // A person with no confirm has no approval step.
    let answer = ask(&server, &ask_effect("alice", Some(&effect), true));
    assert_eq!(answer["decision"], true);
    // A question for access never needs one.
    let access = ask(&server, &question("carol", "access", "", false));
    assert_eq!(access["decision"], true);
}

#[test]
fn p_17_1_a_bad_effect_gets_http_400_and_a_batch_item_gets_invalid_request() {
    let server = start_admin(&directory());
    let mut body = ask_effect(KEY, Some("sha256:00"), false);
    let reply = once_json(server.local_addr(), EVALUATION, &body);
    assert_eq!(reply.status, 400);
    body["context"]["approval"] = json!({"effect": effect(&op()), "op": {}});
    assert_eq!(
        once_json(server.local_addr(), EVALUATION, &body).status,
        400
    );
    let batch = json!({"evaluations": [ask_effect(KEY, Some("sha256:00"), false)]});
    let reply = once_json(server.local_addr(), EVALUATIONS, &batch);
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json()["evaluations"][0]["context"]["reason"],
        "invalid_request"
    );
}

#[test]
fn p_17_4_a_reset_puts_the_requests_of_the_data_file_back() {
    let server = start_admin(&directory());
    let effect = "sha256:a41c5a8d6cec2f1afb10d7938db7c71b3d57062601ed21250be429bb62babb62";
    assert_eq!(
        ask(&server, &ask_effect(KEY, Some(effect), true))["decision"],
        true
    );
    assert_eq!(
        ask(&server, &ask_effect(KEY, Some(effect), true))["context"]["reason"],
        "approval_required"
    );
    admin_post(&server, "/__fake/reset", &json!({}));
    assert_eq!(
        ask(&server, &ask_effect(KEY, Some(effect), true))["decision"],
        true
    );
    // A load of new data replaces the requests too.
    let reply = Client::connect(server.local_addr()).send(
        "PUT",
        "/__fake/load",
        &[("Content-Type", "application/json")],
        Some(directory().to_string().as_bytes()),
    );
    assert_eq!(reply.status, 200, "{}", reply.text());
    assert_eq!(
        ask(&server, &ask_effect(KEY, Some(effect), true))["decision"],
        true
    );
}

#[test]
fn p_17_6_a_cancel_and_a_reply_of_the_test_control_change_the_status() {
    let server = start_admin(&directory());
    let op = op();
    let request_id = waiting_request(&server, &op);
    let reply = admin_post(
        &server,
        &format!("/__fake/approvals/{request_id}/reply"),
        &json!({}),
    );
    assert_eq!(reply.status, 200);
    // `replied` is still pending for the PEP and for the question.
    let q = format!("subject={KEY}");
    assert_eq!(read(&server, &request_id, &q).json()["verdict"], "pending");
    let pending = ask(&server, &ask_effect(KEY, Some(&effect(&op)), false));
    assert_eq!(pending["context"]["reason"], "approval_pending");
    let reply = admin_post(
        &server,
        &format!("/__fake/approvals/{request_id}/cancel"),
        &json!({}),
    );
    assert_eq!(reply.status, 200);
    assert_eq!(read(&server, &request_id, &q).json()["verdict"], "void");
    let reply = admin_post(
        &server,
        &format!("/__fake/approvals/{request_id}/cancel"),
        &json!({}),
    );
    assert_eq!(reply.status, 409);
    let reply =
        Client::connect(server.local_addr()).get(&format!("/__fake/approvals/{request_id}/cancel"));
    assert_eq!(reply.status, 405);
    assert_eq!(
        Client::connect(server.local_addr())
            .get("/__fake/approvals/x")
            .status,
        404
    );
}

#[test]
fn p_17_4_the_test_controls_are_off_without_the_admin_option() {
    let server = start(&directory());
    for path in ["/__fake/approvals", "/__fake/approval-refs"] {
        assert_eq!(Client::connect(server.local_addr()).get(path).status, 404);
    }
    // The API for the PEP does not need the option.
    let reply =
        Client::connect(server.local_addr()).get(&format!("{REQUESTS}/apr_d88a?subject={KEY}"));
    assert_eq!(reply.json(), json!({"verdict": "pending"}));
}

#[test]
fn p_17_4_a_subject_that_has_too_many_requests_that_wait_gets_429() {
    let server = start_admin(&directory());
    // The key conf0002 has no request in the data file.
    let key = "key:conf0002";
    for n in 0..20 {
        let op = json!({"n": n});
        let id = evaluation_id(&server, key, &op);
        let reply = submit(
            &server,
            &submission(&id, &op, json!({"lease_s": 60, "view": {}})),
        );
        assert_eq!(reply.status, 201, "{n}");
    }
    let op = json!({"n": "last"});
    let id = evaluation_id(&server, key, &op);
    let reply = submit(
        &server,
        &submission(&id, &op, json!({"lease_s": 60, "view": {}})),
    );
    assert_eq!(
        (reply.status, reply.json()),
        (429, json!({"error": "rate_limited", "retry_after": 60}))
    );
}
