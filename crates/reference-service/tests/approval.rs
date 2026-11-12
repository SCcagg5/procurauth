//! The approval of an effect through the MCP endpoint (binding 3.5a, 5.7, 5.7a, 5.7b and
//! protocol section 17). The PDP is `fake-pdp` in the same process, and the test answers as the
//! owner with the test control of the PDP.
#![cfg(feature = "mcp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use fake_pdp::Options;
use serde_json::{Value, json};

/// The data of the PDP, with a grant of `data.append` that has `confirm` on the key of Alice. The `confirm` of the
/// grant of Alice herself has no effect on her own questions (protocol 17.8), so the tests use her key.
fn gated_data() -> Value {
    let mut data = pdp_data();
    for subject in data["subjects"].as_array_mut().unwrap() {
        if subject["id"] == KEY_ALICE {
            subject["grants"].as_array_mut().unwrap().push(json!({
                "action": "data.append",
                "resource": "service:datastore/host:prod/database:test2",
                "confirm": true
            }));
        }
    }
    data
}

fn admin_stack() -> Stack {
    stack_with(
        &gated_data(),
        Options {
            admin: true,
            clock_start: Some(1_700_000_010),
            ..Options::default()
        },
        |_| {},
    )
}

fn call(id: u64, name: &str, arguments: &Value) -> Value {
    rpc(
        id,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

fn args(rows: &Value, controls: &Value) -> Value {
    let mut a = json!({"host": "prod", "database": "test2", "table": "customers", "rows": rows});
    for (name, value) in controls.as_object().unwrap() {
        a[name] = value.clone();
    }
    a
}

/// Answer as the owner, with the test control of the PDP.
fn owner(s: &Stack, request_id: &str, decision: &str) {
    let body = json!({"decision": decision}).to_string();
    let reply = send(
        s.pdp.local_addr(),
        "POST",
        &format!("/__fake/approvals/{request_id}/answer"),
        &[
            ("Authorization", &format!("Bearer {CREDENTIAL}")),
            ("Content-Type", "application/json"),
        ],
        Some(body.as_bytes()),
    );
    assert_eq!(reply.status, 200, "{}", reply.text());
}

/// True when the answer of the PDP to this question is `true`.
fn is_true(entry: &fake_pdp::log::LogEntry) -> bool {
    entry
        .answer
        .as_ref()
        .is_some_and(|a| a["decision"] == json!(true))
}

fn result(reply: &Reply) -> Value {
    assert_eq!(reply.status, 200, "{}", reply.text());
    reply.json()["result"].clone()
}

fn status(s: &Stack, token: &str, id: &str) -> Value {
    result(&s.mcp(
        Some(token),
        &call(9, "get_action_status", &json!({"request_id": id})),
    ))
}

#[test]
fn mcp_5_7_the_call_waits_the_owner_approves_and_the_second_call_runs_one_time() {
    let s = admin_stack();
    let token = s.edge.key_token(KEY_ALICE, "alice");
    let a = args(&json!([{"id": 51}]), &json!({"lease_s": 900}));
    // The first call: it runs nothing, and the result tells that the action waits.
    let first = result(&s.mcp(Some(&token), &call(7, "append_rows", &a)));
    assert!(first.get("isError").is_none(), "{first}");
    let action = &first["structuredContent"]["action"];
    assert_eq!(action["status"], "awaiting_approval");
    assert_eq!(action["executed"], false);
    let id = action["id"].as_str().unwrap().to_owned();
    assert_eq!(action["code"].as_str().unwrap().len(), 4);
    assert!(
        first["content"][1]["text"]
            .as_str()
            .unwrap()
            .starts_with("NOT EXECUTED")
    );
    assert_eq!(s.used("alice", "second"), 0);
    // get_action_status gives the verdict, and it is not a use.
    let log_before = s.pdp.log().len();
    let pending = status(&s, &token, &id);
    assert_eq!(pending["structuredContent"], json!({"status": "pending"}));
    assert_eq!(s.pdp.log().len(), log_before, "no question for the tool");
    // The owner approves. The second call runs the effect one time.
    owner(&s, &id, "approve");
    assert_eq!(
        status(&s, &token, &id)["structuredContent"],
        json!({"status": "approved"})
    );
    let run = result(&s.mcp(Some(&token), &call(8, "append_rows", &a)));
    assert_eq!(
        run["structuredContent"],
        json!({"appended": 1, "total": 51}),
        "{run}"
    );
    assert_eq!(s.used("alice", "second"), 1);
    // The approval is consumed: the same call is a new request.
    let again = result(&s.mcp(Some(&token), &call(10, "append_rows", &a)));
    assert_eq!(
        again["structuredContent"]["action"]["status"],
        "awaiting_approval"
    );
    assert_ne!(again["structuredContent"]["action"]["id"], id.as_str());
    // The questions: one with no effect, one with the effect and no usage, then one with usage
    // and the effect after the approval. Only the last one has a `true` answer with usage.
    let log = s.pdp.log();
    let append: Vec<_> = log.iter().filter(|e| e.action == "data.append").collect();
    assert!(append.iter().filter(|e| e.usage && is_true(e)).count() == 1);
}

#[test]
fn mcp_5_7a_a_declined_request_gives_approval_denied_with_no_text_of_the_owner() {
    let s = admin_stack();
    let token = s.edge.key_token(KEY_ALICE, "alice");
    let a = args(&json!([{"id": 52}]), &json!({"lease_s": 900}));
    let first = result(&s.mcp(Some(&token), &call(7, "append_rows", &a)));
    let id = first["structuredContent"]["action"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    owner(&s, &id, "decline");
    assert_eq!(
        status(&s, &token, &id)["structuredContent"],
        json!({"status": "denied"})
    );
    let reply = s.mcp(Some(&token), &call(8, "append_rows", &a));
    let refused = result(&reply);
    assert_eq!(refused["isError"], true);
    assert_eq!(
        refused["structuredContent"]["error"]["code"],
        "approval_denied"
    );
    assert_eq!(refused["structuredContent"]["error"]["retryable"], false);
    let usage_questions = s
        .pdp
        .log()
        .iter()
        .filter(|e| e.action == "data.append" && e.usage && is_true(e))
        .count();
    assert_eq!(usage_questions, 0, "a refused approval asks no use");
    assert_eq!(s.used("alice", "second"), 0);
}

#[test]
fn mcp_5_7_a_call_with_two_controls_or_a_bad_control_gets_invalid_argument_and_asks_nothing() {
    let s = admin_stack();
    let token = s.edge.key_token(KEY_ALICE, "alice");
    let rows = json!([{"id": 1}]);
    for controls in [
        json!({"lease_s": 900, "until": "2030-01-01T00:00:00Z"}),
        json!({"lease_s": 0}),
        json!({"lease_s": "900"}),
        json!({"approval_ref": ""}),
        json!({"lease_s": 900, "wait_s": -1}),
    ] {
        let reply = s.mcp(
            Some(&token),
            &call(7, "append_rows", &args(&rows, &controls)),
        );
        let r = result(&reply);
        assert_eq!(r["isError"], true, "{controls}");
        assert_eq!(
            r["structuredContent"]["error"]["code"], "invalid_argument",
            "{controls}"
        );
    }
    assert!(s.pdp.log().iter().all(|e| e.action != "data.append"));
    assert_eq!(s.app.pep().approval_stats().submissions, 0);
}

#[test]
fn mcp_5_7_a_call_with_no_control_cannot_give_a_lease_when_the_pdp_asks_for_an_approval() {
    let s = admin_stack();
    let token = s.edge.key_token(KEY_ALICE, "alice");
    // The grant of the key of alice has `confirm` on `data.append`: the PDP asks for an approval.
    // The `confirm` of the grant of alice herself has no effect on her own questions (17.8).
    let reply = s.mcp(
        Some(&token),
        &call(7, "append_rows", &args(&json!([{"id": 1}]), &json!({}))),
    );
    let r = result(&reply);
    assert_eq!(r["isError"], true);
    assert_eq!(r["structuredContent"]["error"]["code"], "invalid_argument");
    // The PEP submitted nothing, and no question with usage and the effect ran the action.
    assert_eq!(s.app.pep().approval_stats().submissions, 0);
    assert_eq!(s.used("alice", "second"), 0);
    // A call that needs no approval runs with no control argument.
    let read = result(&s.mcp(
        Some(&token),
        &call(
            8,
            "list_tables",
            &json!({"host": "prod", "database": "test2"}),
        ),
    ));
    assert!(read.get("isError").is_none(), "{read}");
    assert!(read["structuredContent"]["tables"].is_array());
}

#[test]
fn mcp_5_7b_a_request_of_another_subject_and_an_unknown_request_get_the_same_error() {
    let s = admin_stack();
    let alice = s.edge.key_token(KEY_ALICE, "alice");
    let first = result(&s.mcp(
        Some(&alice),
        &call(
            7,
            "append_rows",
            &args(&json!([{"id": 1}]), &json!({"lease_s": 900})),
        ),
    ));
    let id = first["structuredContent"]["action"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let carol = s.edge.token("carol");
    let other = status(&s, &carol, &id);
    let unknown = status(&s, &alice, "apr_none");
    assert_eq!(other["isError"], true);
    assert_eq!(
        other["structuredContent"]["error"]["code"],
        "invalid_argument"
    );
    assert_eq!(other, unknown);
    // A bad request_id is the same error.
    let bad = result(&s.mcp(
        Some(&alice),
        &call(9, "get_action_status", &json!({"request_id": 5})),
    ));
    assert_eq!(
        bad["structuredContent"]["error"]["code"],
        "invalid_argument"
    );
}

#[test]
fn mcp_5_7b_the_status_tool_is_read_only_and_the_list_names_it_when_it_names_a_tool() {
    let s = admin_stack();
    let reply = s.mcp(
        Some(&s.edge.key_token(KEY_ALICE, "alice")),
        &rpc(7, "tools/list", json!({})),
    );
    let tools = result(&reply)["tools"].clone();
    let status = tools
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == "get_action_status")
        .unwrap();
    assert_eq!(status["annotations"]["readOnlyHint"], true);
    // The status tool is listed with each list that names a tool: each tool can give a result that waits.
    let key = s.edge.key_token(KEY_ALICE, "alice");
    let names: Vec<String> = result(&s.mcp(Some(&key), &rpc(7, "tools/list", json!({}))))["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    assert!(names.contains(&"append_rows".to_owned()));
    assert!(names.contains(&"get_action_status".to_owned()));
}

#[test]
fn p_17_12_the_pep_learns_only_the_verdict_the_id_and_the_code() {
    let s = admin_stack();
    let token = s.edge.key_token(KEY_ALICE, "alice");
    let a = args(
        &json!([{"id": 53}]),
        &json!({"approval_ref": "ref_for_the_test"}),
    );
    // The test control registers the reference of the agent, with the intent.
    let body = json!({"ref": "ref_for_the_test", "subject": KEY_ALICE, "lease_s": 900,
        "allow_custom": true})
    .to_string();
    let registered = send(
        s.pdp.local_addr(),
        "POST",
        "/__fake/approval-refs",
        &[
            ("Authorization", &format!("Bearer {CREDENTIAL}")),
            ("Content-Type", "application/json"),
        ],
        Some(body.as_bytes()),
    );
    assert!(registered.status < 300, "{}", registered.text());
    let first = s.mcp(Some(&token), &call(7, "append_rows", &a));
    let id = result(&first)["structuredContent"]["action"]["id"]
        .as_str()
        .unwrap()
        .to_owned();
    owner(&s, &id, "approve");
    let _ = status(&s, &token, &id);
    let stats = s.app.pep().approval_stats();
    assert_eq!(stats.submissions, 1);
    assert_eq!(stats.approval_refs_sent, 1);
    assert_eq!(stats.evaluation_ids_sent, 1);
    assert_eq!(stats.status_reads, 1);
    // The answers of the approval API have the members that the PEP reads and no more.
    assert_eq!(stats.members_ignored, 0, "{stats:?}");
    assert_eq!(stats.members_read, 3 + 1);
    assert_eq!((stats.pending, stats.approved), (1, 1));
    assert_eq!(stats.unknown_verdicts, 0);
}
