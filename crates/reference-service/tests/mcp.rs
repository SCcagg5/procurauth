//! The MCP endpoint of the service with a test PDP. The tests cover the methods and the
//! tools. They also cover the flows of an approval and of a call for input, and the refusals.
#![cfg(feature = "mcp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use fake_pdp::Options;
use fake_pdp::faults::read_faults_str;
use serde_json::{Value, json};

fn call(id: u64, name: &str, arguments: &Value) -> Value {
    rpc(
        id,
        "tools/call",
        json!({"name": name, "arguments": arguments}),
    )
}

fn orders_args() -> Value {
    json!({"host": "prod", "database": "test2", "table": "orders"})
}

fn error_code(reply: &Reply) -> i64 {
    reply.json()["error"]["code"].as_i64().unwrap()
}

#[test]
fn mcp_3_6a_a_method_with_no_tool_asks_mcp_session_and_gets_a_result() {
    let s = stack();
    let token = s.edge.token("alice");
    for method in ["initialize", "ping", "server/discover"] {
        let reply = s.mcp(Some(&token), &rpc(7, method, json!({})));
        assert_eq!(reply.status, 200, "{method}");
        let body = reply.json();
        assert_eq!(body["id"], 7);
        assert_eq!(body["result"]["resultType"], "complete");
    }
    let log = s.pdp.log();
    assert_eq!(log.len(), 3);
    assert!(
        log.iter()
            .all(|e| e.action == "mcp.session" && e.resource == "service:datastore" && !e.usage)
    );
    // A notification has no id: the service answers 202 with no body.
    let note = json!({"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}});
    let reply = s.mcp(Some(&token), &note);
    assert_eq!(reply.status, 202);
    assert!(reply.body.is_empty());
}

#[test]
fn mcp_3_6a_a_method_with_no_tool_is_one_use_when_the_action_lists_a_budget() {
    let s = stack_with(&pdp_data(), Options::default(), |config| {
        config["mcp_session_budget"] = json!(true);
    });
    let token = s.edge.token("alice");
    let reply = s.mcp(Some(&token), &rpc(7, "ping", json!({})));
    assert_eq!(reply.status, 200);
    let log = s.pdp.log();
    assert_eq!(log.len(), 1);
    assert_eq!(log[0].action, "mcp.session");
    assert!(
        log[0].usage,
        "the ping is one use: the question has context.usage"
    );
    // The document lists the budget on the action.
    let document = send(
        s.service.local_addr(),
        "GET",
        "/.well-known/procurauth/actions",
        &[],
        None,
    )
    .json();
    let session = document["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["name"] == "mcp.session")
        .unwrap();
    assert_eq!(session["limits"], json!(["requests"]));
}

#[test]
fn mcp_5_1b_a_false_answer_for_a_method_with_no_tool_gives_403_and_32001() {
    let s = stack();
    // The PDP does not know this subject.
    let reply = s.mcp(
        Some(&s.edge.token("nobody")),
        &rpc(7, "server/discover", json!({})),
    );
    assert_eq!(reply.status, 403);
    assert_eq!(
        reply.json(),
        json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -32001, "message": "forbidden"}})
    );
}

#[test]
fn mcp_5_5_a_pdp_that_gives_an_error_gives_503_and_32603() {
    let s = stack_with(
        &pdp_data(),
        Options {
            extra_faults: read_faults_str(r#"{"failures":[{"kind":"error_503"}]}"#).unwrap(),
            ..Options::default()
        },
        |_| {},
    );
    let token = s.edge.token("alice");
    for request in [
        rpc(7, "ping", json!({})),
        call(
            7,
            "list_tables",
            &json!({"host": "prod", "database": "test1"}),
        ),
    ] {
        let reply = s.mcp(Some(&token), &request);
        assert_eq!(reply.status, 503);
        assert_eq!(error_code(&reply), -32603);
        assert_eq!(reply.json()["id"], 7);
    }
}

#[test]
fn mcp_3_3_a_request_with_no_valid_token_gets_401_with_an_empty_body_before_the_message_is_read() {
    let s = stack();
    let addr = s.service.local_addr();
    let headers = [
        ("Content-Type", "application/json"),
        ("MCP-Protocol-Version", "2026-07-28"),
    ];
    for body in [
        &b"{not json"[..],
        br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#,
    ] {
        let reply = send(addr, "POST", "/mcp", &headers, Some(body));
        assert_eq!(reply.status, 401);
        assert!(reply.body.is_empty());
    }
    let mut with_bad = headers.to_vec();
    with_bad.push(("X-Identity-Token", "abc.def.ghi"));
    let reply = send(addr, "POST", "/mcp", &with_bad, Some(b"{not json"));
    assert_eq!((reply.status, reply.body.len()), (401, 0));
    // A standalone key in `Authorization` is not an identity token.
    let mut standalone = headers.to_vec();
    standalone.push((
        "Authorization",
        "Bearer mcp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ));
    let reply = send(
        addr,
        "POST",
        "/mcp",
        &standalone,
        Some(br#"{"jsonrpc":"2.0","id":7,"method":"ping"}"#),
    );
    assert_eq!((reply.status, reply.body.len()), (401, 0));
    assert!(s.pdp.log().is_empty());
}

#[test]
fn mcp_1_3_a_header_and_a_meta_version_that_differ_give_400_and_32020() {
    let s = stack();
    let request = json!({"jsonrpc": "2.0", "id": 7, "method": "ping",
        "params": {"_meta": {"io.modelcontextprotocol/protocolVersion": "2025-11-25"}}});
    let reply = s.mcp(Some(&s.edge.token("alice")), &request);
    assert_eq!(reply.status, 400);
    assert_eq!(error_code(&reply), -32020);
    assert!(s.pdp.log().is_empty());
}

#[test]
fn a_body_that_is_not_json_gets_400_after_the_token_check() {
    let s = stack();
    let token = s.edge.token("alice");
    let reply = send(
        s.service.local_addr(),
        "POST",
        "/mcp",
        &[
            ("X-Identity-Token", &token),
            ("Content-Type", "application/json"),
        ],
        Some(b"{not json"),
    );
    assert_eq!(reply.status, 400);
    assert_eq!(error_code(&reply), -32700);
    assert_eq!(s.get("/mcp", Some(&token)).status, 405);
}

// ---- The list of the tools (4.1) ----------------------------------------------------------------------------

#[test]
fn mcp_4_1_the_list_names_the_tools_that_the_pdp_lets_the_subject_do() {
    let s = stack();
    let names = |token: &str| -> Vec<String> {
        let reply = s.mcp(Some(token), &rpc(7, "tools/list", json!({})));
        assert_eq!(reply.status, 200);
        reply.json()["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        names(&s.edge.token("alice")),
        [
            "read_rows",
            "write_rows",
            "copy_table",
            "list_tables",
            "query_table"
        ]
    );
    // The key has `data.read` and `data.inspect` on `test2` and no `data.write`.
    assert_eq!(
        names(&s.edge.key_token(KEY_ALICE, "alice")),
        ["read_rows", "list_tables", "query_table"]
    );
    // The list asks one item for each action, with `context.match` equal to `subtree`, and no usage.
    let log = s.pdp.log();
    assert!(log.iter().all(|e| !e.usage));
    assert_eq!(
        log.iter().filter(|e| e.endpoint == "evaluations").count(),
        6,
        "3 actions for each of the two lists"
    );
    assert_eq!(s.used("alice", "second"), 0);
}

#[test]
fn mcp_4_2_a_refused_tool_and_an_unknown_tool_get_the_same_refusal() {
    let s = stack();
    let token = s.edge.key_token(KEY_ALICE, "alice");
    let refused = s.mcp(
        Some(&token),
        &call(
            7,
            "write_rows",
            &json!({"host": "prod", "database": "test2", "table": "orders", "rows": []}),
        ),
    );
    let unknown = s.mcp(Some(&token), &call(7, "no_such_tool", &json!({})));
    assert_eq!((refused.status, unknown.status), (200, 200));
    assert_eq!(refused.json(), unknown.json());
    assert_eq!(error_code(&refused), -32602);
    // An error never copies a value of the request.
    let marker = s.mcp(
        Some(&token),
        &call(
            7,
            "INJECTED-MARKER-7f3a",
            &json!({"x": "INJECTED-MARKER-7f3a"}),
        ),
    );
    assert!(!marker.text().contains("INJECTED-MARKER"));
}

// ---- The calls ---------------------------------------------------------------------------------------------------------

#[test]
fn mcp_3_4_read_rows_is_one_use_with_the_ceiling_of_the_table() {
    let s = stack();
    let reply = s.mcp(
        Some(&s.edge.token("alice")),
        &call(7, "read_rows", &orders_args()),
    );
    assert_eq!(reply.status, 200);
    let result = reply.json()["result"].clone();
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["limit"], 100);
    assert_eq!(result["structuredContent"]["count"], 100);
    let text: Value = serde_json::from_str(result["content"][0]["text"].as_str().unwrap()).unwrap();
    assert_eq!(text, result["structuredContent"]);
    let log = s.pdp.log();
    assert_eq!(log.len(), 1);
    assert!(log[0].usage);
    assert_eq!(s.used("alice", "second"), 1);
}

#[test]
fn mcp_5_3_a_spent_budget_gives_the_tool_error_with_retry_after() {
    let s = stack();
    let token = s.edge.token("alice");
    for i in 0..10 {
        let reply = s.mcp(
            Some(&token),
            &call(
                i,
                "read_rows",
                &json!({"host": "prod", "database": "test2", "table": "orders", "limit": 1}),
            ),
        );
        assert_eq!(reply.json()["result"]["isError"], false);
    }
    let reply = s.mcp(Some(&token), &call(7, "read_rows", &orders_args()));
    assert_eq!(reply.status, 200);
    let body = reply.json();
    let result = &body["result"];
    assert_eq!(result["isError"], true);
    assert_eq!(result["resultType"], "complete");
    assert_eq!(
        result["structuredContent"]["error"]["code"],
        "budget_exceeded"
    );
    assert_eq!(result["structuredContent"]["error"]["retryable"], true);
    assert!(
        (1..=60).contains(
            &result["structuredContent"]["error"]["retry_after"]
                .as_u64()
                .unwrap()
        )
    );
    assert!(body.get("error").is_none());
}

#[test]
fn mcp_3_5_a_call_for_input_asks_without_usage_and_the_next_call_is_the_use() {
    let s = stack();
    let token = s.edge.token("alice");
    let first = s.mcp(
        Some(&token),
        &call(
            7,
            "query_table",
            &json!({"host": "prod", "database": "test2"}),
        ),
    );
    assert_eq!(first.status, 200);
    let result = first.json()["result"].clone();
    assert_eq!(result["resultType"], "input_required");
    assert!(result["inputRequests"]["table"].is_object());
    // No unit, and one question without usage.
    assert_eq!(s.used("alice", "second"), 0);
    assert!(s.pdp.log().iter().all(|e| !e.usage));
    // The next call has the answer of the client. It is the use.
    let params = json!({"name": "query_table", "arguments": {"host": "prod", "database": "test2"},
        "inputResponses": {"table": {"action": "accept", "content": {"table": "orders"}}}});
    let second = s.mcp(Some(&token), &rpc(8, "tools/call", params));
    assert_eq!(second.json()["result"]["isError"], false);
    assert_eq!(second.json()["result"]["structuredContent"]["limit"], 100);
    assert_eq!(s.used("alice", "second"), 1);
}

#[test]
fn mcp_3_5a_an_approval_asks_without_usage_at_the_call_and_with_usage_after_it() {
    let s = stack();
    let token = s.edge.token("alice");
    let args =
        json!({"host": "prod", "database": "test2", "table": "customers", "rows": [{"id": 51}]});
    let first = s.mcp(Some(&token), &call(7, "write_rows", &args));
    assert_eq!(first.json()["result"]["resultType"], "input_required");
    assert_eq!(s.used("alice", "second"), 0);
    let log = s.pdp.log();
    assert_eq!(
        (log.len(), log[0].usage, log[0].action.as_str()),
        (1, false, "data.write")
    );
    // The approval, and the run.
    let params = json!({"name": "write_rows", "arguments": args, "inputResponses": {"approval": {"action": "accept"}}});
    let run = s.mcp(Some(&token), &rpc(8, "tools/call", params));
    assert_eq!(
        run.json()["result"]["structuredContent"],
        json!({"appended": 1, "total": 51})
    );
    let log = s.pdp.log();
    assert_eq!(log.len(), 2);
    assert!(log[1].usage);
    assert_eq!(s.used("alice", "second"), 1);
    // A refused approval takes no unit and asks nothing.
    let params = json!({"name": "write_rows", "arguments": args, "inputResponses": {"approval": {"action": "decline"}}});
    let refused = s.mcp(Some(&token), &rpc(9, "tools/call", params));
    let body = refused.json();
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(
        body["result"]["structuredContent"]["error"]["code"],
        "approval_refused"
    );
    assert_eq!(s.pdp.log().len(), 2);
    assert_eq!(s.used("alice", "second"), 1);
}

#[test]
fn mcp_3_7_copy_table_asks_the_read_without_usage_and_the_write_with_usage() {
    let s = stack();
    let args = json!({"from": {"host": "prod", "database": "test1", "table": "orders"}, "to": {"host": "prod", "database": "test2"}});
    let reply = s.mcp(Some(&s.edge.token("alice")), &call(7, "copy_table", &args));
    assert_eq!(
        reply.json()["result"]["structuredContent"],
        json!({"copied": 30, "truncated": false})
    );
    let log = s.pdp.log();
    assert_eq!((log[0].action.as_str(), log[0].usage), ("data.read", false));
    assert_eq!((log[1].action.as_str(), log[1].usage), ("data.write", true));
    // The key has no grant of `data.write`: the PDP refuses, and no question has usage.
    let s = stack();
    let reply = s.mcp(
        Some(&s.edge.key_token(KEY_ALICE, "alice")),
        &call(7, "copy_table", &args),
    );
    assert_eq!(error_code(&reply), -32602);
    assert!(s.pdp.log().iter().all(|e| !e.usage));
}

#[test]
fn mcp_3_2_arguments_that_do_not_name_a_node_give_32602_with_a_fixed_message() {
    let s = stack();
    let token = s.edge.token("alice");
    for arguments in [
        json!({}),
        json!({"host": "prod"}),
        json!({"host": 5, "database": "test2", "table": "orders"}),
        json!({"host": "", "database": "x", "table": "y"}),
    ] {
        let reply = s.mcp(Some(&token), &call(7, "read_rows", &arguments));
        assert_eq!(reply.status, 200);
        assert_eq!(
            reply.json()["error"],
            json!({"code": -32602, "message": "Invalid params"})
        );
    }
    assert!(s.pdp.log().is_empty());
}

#[test]
fn mcp_3_5_list_tables_is_a_use_of_an_action_without_a_budget() {
    let s = stack();
    let reply = s.mcp(
        Some(&s.edge.token("alice")),
        &call(
            7,
            "list_tables",
            &json!({"host": "prod", "database": "test2"}),
        ),
    );
    assert_eq!(
        reply.json()["result"]["structuredContent"],
        json!({"tables": ["customers", "orders"]})
    );
    let log = s.pdp.log();
    assert_eq!(
        (log.len(), log[0].usage, log[0].action.as_str()),
        (1, false, "data.inspect")
    );
}
