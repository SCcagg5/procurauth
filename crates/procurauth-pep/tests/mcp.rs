//! The MCP binding with the PEP and the test PDP. The tests cover the list of the
//! tools, the action `mcp.session`, the flow with an approval, and the map of the refusals.
#![cfg(feature = "mcp")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::sync::Arc;

use common::*;
use fake_pdp::{Options, Server};
use procurauth_core::path::NodePath;
use procurauth_pep::clock::ManualClock;
use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
use procurauth_pep::mcp::{
    McpGate, RpcRequest, Stage, ToolMap, ToolSpec, input_required_reply, input_responses,
    refusal_reply,
};
use procurauth_pep::operation::{Operation, node};
use procurauth_pep::{Identity, Pep};
use serde_json::{Value, json};

fn data() -> Value {
    let mut data = datastore_data();
    data["services"][0]["document"]["actions"].as_array_mut().unwrap().push(json!({
        "name": "mcp.session", "resource_types": ["service"], "description": "Use the MCP endpoint."
    }));
    // Alice and her key may use the session. The key has the grant, and Alice has it too (3.5).
    for subject in data["subjects"].as_array_mut().unwrap() {
        let id = subject["id"].as_str().unwrap().to_owned();
        if id == "alice" || id == KEY_ALICE {
            subject["grants"]
                .as_array_mut()
                .unwrap()
                .push(json!({"action": "mcp.session", "resource": "service:datastore"}));
        }
    }
    data
}

fn tool(name: &str, action: &str) -> ToolSpec {
    ToolSpec {
        name: name.into(),
        action: action.into(),
        description: format!("The tool {name}."),
        input_schema: json!({"type": "object"}),
    }
}

fn tools() -> ToolMap {
    ToolMap::new(vec![
        tool("read_rows", "data.read"),
        tool("write_rows", "data.write"),
        tool("copy_table", "data.write"),
    ])
    .unwrap()
}

struct Rig {
    server: fake_pdp::RunningServer,
    pep: Pep,
    edge: Edge,
}

fn rig(options: Options) -> Rig {
    let data = data();
    let server = Server::from_value(&data, options)
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap();
    let edge = Edge::new();
    let cfg = config(&server.url(), &edge);
    let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&cfg.pdp)));
    let pep = Pep::with_clock(
        cfg,
        document_of(&data),
        transport,
        Arc::new(ManualClock::at_seconds(NOW)),
    )
    .unwrap();
    Rig { server, pep, edge }
}

impl Rig {
    fn person(&self, sub: &str) -> Identity {
        self.pep
            .authenticate([(HEADER, self.edge.token(sub).as_str())])
            .unwrap()
    }

    fn key(&self) -> Identity {
        self.pep
            .authenticate([(HEADER, self.edge.token_for_key(KEY_ALICE, "alice").as_str())])
            .unwrap()
    }

    fn used(&self, subject: &str) -> u64 {
        self.server
            .counters()
            .iter()
            .filter(|c| c.subject == subject && c.window.as_str() == "second")
            .map(|c| c.used)
            .sum()
    }
}

fn node_of(database: &str) -> NodePath {
    node(SERVICE, &[("host", "prod"), ("database", database)]).unwrap()
}

fn request(method: &str, params: Value) -> RpcRequest {
    let mut params = params;
    params["_meta"] = json!({"io.modelcontextprotocol/protocolVersion": "2026-07-28"});
    RpcRequest {
        id: Some(json!(7)),
        method: method.into(),
        params,
    }
}

#[test]
fn mcp_4_1_the_list_names_only_the_tools_whose_action_the_pdp_lets_the_subject_do() {
    let r = rig(Options::default());
    let map = tools();
    let gate = McpGate::new(&r.pep, &map);
    // The key has `data.read` on `test2` and no `data.write`: only `read_rows`.
    let names: Vec<_> = gate
        .list_tools(&r.key())
        .unwrap()
        .iter()
        .map(|t| t.name.clone())
        .collect();
    assert_eq!(names, ["read_rows"]);
    // Alice has both, and the order is the order of the map.
    let names: Vec<_> = gate
        .list_tools(&r.person("alice"))
        .unwrap()
        .iter()
        .map(|t| t.name.clone())
        .collect();
    assert_eq!(names, ["read_rows", "write_rows", "copy_table"]);
}

#[test]
fn mcp_4_1_the_list_asks_one_item_for_each_action_with_match_subtree_and_no_usage() {
    let t = Scripted::answering(|_| json!({"decision": true}));
    let edge = Edge::new();
    let (pep, _) = pep(t.clone(), &edge, "http://pdp.test", |_| {});
    let who = pep
        .authenticate([(HEADER, edge.token("alice").as_str())])
        .unwrap();
    let map = tools();
    let tools = McpGate::new(&pep, &map).list_tools(&who).unwrap();
    assert_eq!(tools.len(), 3);
    let posts = t.posts();
    assert_eq!(posts.len(), 1, "one request");
    let body = posts[0].body.clone().unwrap();
    assert_eq!(posts[0].path(), "/access/v1/evaluations");
    assert_eq!(body["context"], json!({"match": "subtree"}));
    let items = body["evaluations"].as_array().unwrap();
    assert_eq!(items.len(), 2, "two actions for three tools");
    for item in items {
        assert_eq!(
            item["resource"],
            json!({"type": "service", "id": "datastore"})
        );
    }
    assert!(!posts[0].has_usage());
}

#[test]
fn mcp_4_2_a_refused_tool_and_an_unknown_tool_get_the_same_refusal() {
    let r = rig(Options::default());
    let map = tools();
    let gate = McpGate::new(&r.pep, &map);
    let key = r.key();
    let write = Operation::new("data.write", node_of("test2"));
    let refused = gate
        .call(&key, "write_rows", &write, Stage::Run)
        .unwrap_err();
    let unknown = gate
        .call(&key, "no_such_tool", &write, Stage::Run)
        .unwrap_err();
    let call = request("tools/call", json!({"name": "write_rows", "arguments": {}}));
    assert_eq!(
        refusal_reply(&refused, &call, true),
        refusal_reply(&unknown, &call, true)
    );
    assert_eq!(refusal_reply(&refused, &call, true).status, 200);
    assert_eq!(
        refusal_reply(&refused, &call, true).body.unwrap()["error"]["code"],
        -32602
    );
}

#[test]
fn mcp_3_5a_an_approval_asks_without_usage_at_the_call_and_with_usage_at_the_run() {
    let r = rig(Options::default());
    let map = tools();
    let gate = McpGate::new(&r.pep, &map);
    let alice = r.person("alice");
    let write = Operation::new("data.write", node_of("test2"));
    // The call: one question without usage. No unit.
    let allowed = gate.call(&alice, "write_rows", &write, Stage::Ask).unwrap();
    assert_eq!(allowed.units(), 0);
    assert_eq!(r.server.log().len(), 1);
    assert!(!r.server.log()[0].usage);
    assert_eq!(r.used("alice"), 0);
    // The run, after the approval: one question with usage. One unit.
    let allowed = gate.call(&alice, "write_rows", &write, Stage::Run).unwrap();
    assert_eq!(allowed.units(), 1);
    assert!(r.server.log()[1].usage);
    assert_eq!(r.used("alice"), 1);
    // A refused approval sends no question: the service does not call `Stage::Run`.
    let call = request("tools/call", json!({"name": "write_rows"}));
    let reply = input_required_reply(
        &call,
        json!({"approval": {"method": "elicitation/create"}}),
        None,
    );
    assert_eq!(
        reply.body.unwrap()["result"]["resultType"],
        "input_required"
    );
    let follow = request(
        "tools/call",
        json!({"name": "write_rows", "inputResponses": {"approval": {"action": "decline"}}}),
    );
    assert_eq!(
        input_responses(&follow).unwrap()["approval"]["action"],
        "decline"
    );
    assert_eq!(r.server.log().len(), 2);
}

#[test]
fn mcp_3_5_a_kept_true_answer_of_the_call_never_starts_the_use() {
    let r = rig(Options::default());
    let map = tools();
    let gate = McpGate::new(&r.pep, &map);
    let alice = r.person("alice");
    let op = Operation::new("data.read", node_of("test1"));
    gate.call(&alice, "read_rows", &op, Stage::Ask).unwrap();
    gate.call(&alice, "read_rows", &op, Stage::Ask).unwrap();
    assert_eq!(r.used("alice"), 0);
    gate.call(&alice, "read_rows", &op, Stage::Run).unwrap();
    assert_eq!(r.used("alice"), 1);
}

#[test]
fn mcp_3_7_a_tool_with_two_permissions_asks_the_other_first_and_refuses_for_the_key() {
    let r = rig(Options::default());
    let map = tools();
    let gate = McpGate::new(&r.pep, &map);
    let copy = Operation::new("data.write", node_of("test2")).also(
        "data.read",
        node(
            SERVICE,
            &[("host", "prod"), ("database", "test1"), ("table", "orders")],
        )
        .unwrap(),
    );
    // Alice can read `test1` and write `test2`.
    let allowed = gate
        .call(&r.person("alice"), "copy_table", &copy, Stage::Run)
        .unwrap();
    assert_eq!(allowed.units(), 1);
    let before = r.server.log().len();
    assert_eq!(before, 2);
    // The key has no grant on `test1`, and no `data.write`: the call is refused, and no question has usage.
    let refused = gate
        .call(&r.key(), "copy_table", &copy, Stage::Run)
        .unwrap_err();
    assert_eq!(refused.status(), 403);
    let log = r.server.log();
    assert!(log[before..].iter().all(|e| !e.usage));
    assert_eq!(r.used(KEY_ALICE), 0);
}

#[test]
fn mcp_3_6a_a_method_with_no_tool_asks_the_action_mcp_session_on_the_service() {
    let r = rig(Options::default());
    let map = tools();
    let gate = McpGate::new(&r.pep, &map);
    let allowed = gate.session(&r.person("alice")).unwrap();
    assert_eq!(allowed.units(), 0, "the action has no budget");
    let entry = &r.server.log()[0];
    assert_eq!(entry.action, "mcp.session");
    assert_eq!(entry.resource, "service:datastore");
    // Bob has no grant of this action.
    let refused = gate.session(&r.person("bob")).unwrap_err();
    let ping = request("ping", json!({}));
    let reply = refusal_reply(&refused, &ping, false);
    assert_eq!(reply.status, 403);
    assert_eq!(
        reply.body.unwrap()["error"],
        json!({"code": -32001, "message": "forbidden"})
    );
}

#[test]
fn mcp_5_3_a_spent_budget_on_a_tool_call_is_a_tool_error_with_retry_after() {
    let data = budgets_data();
    let server = Server::from_value(&data, Options::default())
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap();
    let edge = Edge::new();
    let cfg = config(&server.url(), &edge);
    let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&cfg.pdp)));
    let mut doc = document_of(&data);
    doc.actions.push(procurauth_core::action_document::Action {
        name: "mcp.session".into(),
        resource_types: vec!["service".into()],
        description: "Use the MCP endpoint.".into(),
        limits: vec![],
        approval: false,
    });
    let pep = Pep::with_clock(cfg, doc, transport, Arc::new(ManualClock::at_seconds(NOW))).unwrap();
    let who = pep
        .authenticate([(HEADER, edge.token("once").as_str())])
        .unwrap();
    let map = tools();
    let gate = McpGate::new(&pep, &map);
    let op = Operation::new("data.read", node_of("test1"));
    assert!(gate.call(&who, "read_rows", &op, Stage::Run).is_ok());
    let refused = gate.call(&who, "read_rows", &op, Stage::Run).unwrap_err();
    let call = request("tools/call", json!({"name": "read_rows"}));
    let reply = refusal_reply(&refused, &call, true);
    assert_eq!(reply.status, 200);
    let body = reply.body.unwrap();
    assert_eq!(body["result"]["isError"], true);
    assert_eq!(
        body["result"]["structuredContent"]["error"]["retry_after"],
        12
    );
    // On a method other than `tools/call`, the same refusal is a 429.
    let ping = request("ping", json!({}));
    let reply = refusal_reply(&refused, &ping, false);
    assert_eq!(reply.status, 429);
    assert_eq!(reply.to_http().header("Retry-After"), Some("12"));
}

#[test]
fn mcp_5_5_a_pdp_that_closes_the_connection_gives_503_and_32603() {
    let r = rig(Options::default());
    let alice = r.person("alice");
    let map = tools();
    let gate = McpGate::new(&r.pep, &map);
    r.server.set_faults(
        fake_pdp::faults::read_faults_str(r#"{"failures":[{"kind":"close"}]}"#).unwrap(),
    );
    let op = Operation::new("data.read", node_of("test1"));
    let refused = gate.call(&alice, "read_rows", &op, Stage::Run).unwrap_err();
    let call = request("tools/call", json!({"name": "read_rows"}));
    let reply = refusal_reply(&refused, &call, true);
    assert_eq!(reply.status, 503);
    assert_eq!(reply.body.unwrap()["error"]["code"], -32603);
}

#[test]
fn mcp_3_2_the_map_is_checked_against_the_document() {
    let doc = document_of(&data());
    assert!(tools().check_against(&doc).is_ok());
    let missing = ToolMap::new(vec![tool("x", "data.nowhere")]).unwrap();
    assert!(missing.check_against(&doc).is_err());
    // The document of section 13 has no `mcp.session`.
    assert!(tools().check_against(&datastore_document()).is_err());
}

#[test]
fn mcp_5_7_the_control_arguments_are_split_from_the_arguments_and_exactly_one_gives_the_wait() {
    use procurauth_pep::approval::Control;
    use procurauth_pep::mcp::split_approval_arguments;
    let good = split_approval_arguments(
        &json!({"table": "orders", "lease_s": 900, "wait_s": 100, "supersedes": "apr_0"}),
    )
    .unwrap();
    assert_eq!(good.control, Control::LeaseSeconds(900));
    assert_eq!(good.supersedes.as_deref(), Some("apr_0"));
    // The wait is bounded.
    assert_eq!(good.wait_seconds, Some(25));
    // The control arguments never enter the arguments that build `op`.
    assert_eq!(good.rest, json!({"table": "orders"}));
    let reference = split_approval_arguments(&json!({"approval_ref": "r"})).unwrap();
    assert_eq!(reference.control, Control::Reference("r".into()));
    let until = split_approval_arguments(&json!({"until": "2030-01-01T00:00:00Z"})).unwrap();
    assert_eq!(until.control, Control::Until("2030-01-01T00:00:00Z".into()));
    for bad in [
        json!({}),
        json!({"lease_s": 900, "until": "x"}),
        json!({"lease_s": 900, "approval_ref": "x"}),
        json!({"lease_s": 0}),
        json!({"lease_s": 1.5}),
        json!({"lease_s": "900"}),
        json!({"approval_ref": ""}),
        json!({"approval_ref": 5}),
        json!({"lease_s": 900, "wait_s": -1}),
        json!({"lease_s": 900, "supersedes": 3}),
        json!([1]),
    ] {
        assert!(split_approval_arguments(&bad).is_err(), "{bad}");
    }
}

#[test]
fn mcp_5_7_the_replies_of_an_approval_have_the_forms_of_the_binding() {
    use procurauth_pep::approval::{ApprovalRefusal, PendingApproval, Verdict};
    use procurauth_pep::mcp::{approval_tool_error, awaiting_reply, status_reply};
    let call = request("tools/call", json!({"name": "append_rows"}));
    let waiting = awaiting_reply(
        &call,
        &PendingApproval {
            request_id: "apr_9f3a".into(),
            code: "K7QF".into(),
        },
    )
    .body
    .unwrap();
    let result = &waiting["result"];
    assert_eq!(result["resultType"], "complete");
    assert!(result.get("isError").is_none());
    assert_eq!(
        result["structuredContent"],
        json!({"action": {"id": "apr_9f3a", "status": "awaiting_approval", "code": "K7QF", "executed": false}})
    );
    assert!(
        result["content"][1]["text"]
            .as_str()
            .unwrap()
            .starts_with("NOT EXECUTED")
    );
    for (cause, code, retryable) in [
        (ApprovalRefusal::Denied, "approval_denied", false),
        (ApprovalRefusal::Expired, "approval_expired", false),
        (ApprovalRefusal::InvalidArgument, "invalid_argument", false),
        (ApprovalRefusal::NoDevice, "approval_unavailable", true),
        (
            ApprovalRefusal::RateLimited { retry_after: 60 },
            "approval_rate_limited",
            true,
        ),
    ] {
        let body = approval_tool_error(&call, &cause).body.unwrap();
        let error = &body["result"]["structuredContent"]["error"];
        assert_eq!(body["result"]["isError"], true);
        assert_eq!(error["code"], code);
        assert_eq!(error["retryable"], retryable);
        assert_eq!(
            error.get("retry_after").is_some(),
            code == "approval_rate_limited"
        );
        // The text of the content is the compact JSON of the structured content ([CONTRACT, 6.1]).
        let text = body["result"]["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            body["result"]["structuredContent"]
        );
    }
    let status = status_reply(&call, Verdict::Void).body.unwrap();
    assert_eq!(
        status["result"]["structuredContent"],
        json!({"status": "void"})
    );
    assert!(status["result"].get("isError").is_none());
    // The refusal of the approval is the same reply through `refusal_reply`.
    let refusal = procurauth_pep::Refusal::Approval(ApprovalRefusal::Denied);
    assert_eq!(
        refusal_reply(&refusal, &call, true).body.unwrap()["result"]["structuredContent"]["error"]
            ["code"],
        "approval_denied"
    );
    assert_eq!(refusal_reply(&refusal, &call, false).status, 403);
}

#[test]
fn mcp_5_7b_the_status_tool_is_read_only_and_a_request_id_is_a_short_text() {
    use procurauth_pep::mcp::{status_request_id, status_tool_entry};
    let entry = status_tool_entry();
    assert_eq!(entry["name"], "get_action_status");
    assert_eq!(entry["annotations"]["readOnlyHint"], true);
    assert_eq!(
        status_request_id(&json!({"request_id": "apr_1"})),
        Some("apr_1")
    );
    for bad in [
        json!({}),
        json!({"request_id": 1}),
        json!({"request_id": ""}),
        json!({"request_id": "a b"}),
    ] {
        assert_eq!(status_request_id(&bad), None, "{bad}");
    }
}
