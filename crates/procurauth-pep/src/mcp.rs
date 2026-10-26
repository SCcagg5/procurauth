//! The MCP binding (`bindings/mcp/procurauth-mcp-binding.md`).
//!
//! This module is a thin layer over [`Pep`]. It holds the rules that only MCP
//! needs:
//!
//! - the map of the tools (3.2);
//! - the list of the tools, with the display questions (4.1);
//! - the action `mcp.session` for the methods that have no tool (3.6a);
//! - the flow of two questions for an approval or for a call for input (3.5, 3.5a);
//! - the map of the refusals to HTTP statuses and JSON-RPC errors (section 5).
//!
//! The module never reads a message before the identity token is good. The
//! caller checks the token with [`Pep::authenticate`] first, and it sends an
//! HTTP 401 with an empty body when the check fails (3.3, 3.3a, 5.6a).
//!
//! # The flow of one request
//!
//! 1. Check the token. A failure gives a 401 with no body.
//! 2. Read the message with [`RpcRequest::parse`], and check the version with [`check_version`].
//! 3. For `tools/list`, call [`McpGate::list_tools`]. For `tools/call`, call [`McpGate::call`].
//!    For another method, call [`McpGate::session`].
//! 4. Map a refusal with [`refusal_reply`].

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::document::ActionDocument;
use crate::identity::Identity;
use crate::operation::{Operation, Permission, node};
use crate::pep::{Allowed, Pep};
use crate::refusal::Refusal;
use crate::reply::HttpReply;

/// The action for the MCP methods that have no tool (3.6a).
pub const SESSION_ACTION: &str = "mcp.session";
/// The name of the member of `_meta` with the version of the protocol (1.3).
pub const VERSION_META_KEY: &str = "io.modelcontextprotocol/protocolVersion";
/// The revision that this binding is for (1.3).
pub const REVISION: &str = "2026-07-28";

/// The JSON-RPC code for a denial (5.1b).
pub const CODE_FORBIDDEN: i64 = -32001;
/// The JSON-RPC code for a refused budget on a method other than `tools/call` (5.4).
pub const CODE_RATE_LIMITED: i64 = -31429;
/// The JSON-RPC code for an error of the service (5.5).
pub const CODE_INTERNAL: i64 = -32603;
/// The JSON-RPC code for a tool that is unknown or refused (5.1).
pub const CODE_INVALID_PARAMS: i64 = -32602;
/// The JSON-RPC code for a header and a `_meta` version that differ (U25).
pub const CODE_VERSION_MISMATCH: i64 = -32020;
/// The JSON-RPC code for a body that is not JSON.
pub const CODE_PARSE_ERROR: i64 = -32700;
/// The JSON-RPC code for a request that is not a JSON-RPC request.
pub const CODE_INVALID_REQUEST: i64 = -32600;
/// The JSON-RPC code for a method that the service does not have.
pub const CODE_METHOD_NOT_FOUND: i64 = -32601;

/// A tool and the action that the PDP decides for it (3.2).
#[derive(Clone, Debug, PartialEq)]
pub struct ToolSpec {
    /// The name of the tool.
    pub name: String,
    /// The action of the tool, from the action document.
    pub action: String,
    /// The description for the client.
    pub description: String,
    /// The JSON Schema of the arguments.
    pub input_schema: Value,
}

/// Why a map of the tools is not valid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolMapError(pub String);

impl std::fmt::Display for ToolMapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ToolMapError {}

/// The map of the tools: the order of the list is the order here (4.3).
#[derive(Clone, Debug)]
pub struct ToolMap {
    tools: Vec<ToolSpec>,
}

impl ToolMap {
    /// A map from tools. Each name occurs one time.
    ///
    /// # Errors
    /// Returns an error when a name occurs more than one time.
    pub fn new(tools: Vec<ToolSpec>) -> Result<Self, ToolMapError> {
        let mut seen = BTreeSet::new();
        for tool in &tools {
            if !seen.insert(tool.name.as_str()) {
                return Err(ToolMapError(format!(
                    "The tool `{}` occurs more than one time.",
                    tool.name
                )));
            }
        }
        Ok(Self { tools })
    }

    /// Check the map against the action document: each action is declared, and the
    /// document declares `mcp.session` (3.6a).
    ///
    /// # Errors
    /// Returns an error for the first action that the document does not declare.
    pub fn check_against(&self, document: &ActionDocument) -> Result<(), ToolMapError> {
        for action in self
            .tools
            .iter()
            .map(|t| t.action.as_str())
            .chain([SESSION_ACTION])
        {
            if document.action(action).is_none() {
                return Err(ToolMapError(format!(
                    "The action `{action}` is not in the action document."
                )));
            }
        }
        Ok(())
    }

    /// The tools, in the order of the list.
    pub fn tools(&self) -> &[ToolSpec] {
        &self.tools
    }

    /// The tool with this name.
    pub fn get(&self, name: &str) -> Option<&ToolSpec> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// The actions of the tools, each one time, in the order of the first tool that has it (4.1).
    pub fn actions(&self) -> Vec<&str> {
        let mut seen = BTreeSet::new();
        self.tools
            .iter()
            .map(|t| t.action.as_str())
            .filter(|a| seen.insert(*a))
            .collect()
    }
}

/// The revision of an MCP request. The result has `resultType` for the revision 2026-07-28 (5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revision {
    /// The revision 2026-07-28. The request has the version in `params._meta`.
    V2026,
    /// An earlier revision.
    Legacy,
}

/// One JSON-RPC request.
#[derive(Clone, Debug, PartialEq)]
pub struct RpcRequest {
    /// The `id`. A notification has none.
    pub id: Option<Value>,
    /// The method.
    pub method: String,
    /// The parameters: an object, or `null` when the request has none.
    pub params: Value,
}

/// Why a body is not a JSON-RPC request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ParseError {
    /// The body is not JSON. The reply is HTTP 400 with `-32700`.
    NotJson,
    /// The body is JSON, and it is not a JSON-RPC 2.0 request. The reply is HTTP 400 with `-32600`.
    NotRequest,
}

impl RpcRequest {
    /// Read the body of a request. The reader is strict: a duplicate member is not valid.
    ///
    /// # Errors
    /// Returns [`ParseError`] when the body is not a JSON-RPC 2.0 request.
    pub fn parse(body: &[u8]) -> Result<Self, ParseError> {
        let value = procurauth_core::json::parse_slice(body).map_err(|_| ParseError::NotJson)?;
        let Value::Object(map) = value else {
            return Err(ParseError::NotRequest);
        };
        if map.get("jsonrpc") != Some(&json!("2.0")) {
            return Err(ParseError::NotRequest);
        }
        let Some(Value::String(method)) = map.get("method") else {
            return Err(ParseError::NotRequest);
        };
        let id = match map.get("id") {
            None => None,
            Some(id @ (Value::String(_) | Value::Number(_))) => Some(id.clone()),
            Some(_) => return Err(ParseError::NotRequest),
        };
        let params = match map.get("params") {
            None | Some(Value::Null) => Value::Null,
            Some(params @ Value::Object(_)) => params.clone(),
            Some(_) => return Err(ParseError::NotRequest),
        };
        Ok(Self {
            id,
            method: method.clone(),
            params,
        })
    }

    /// The version in `params._meta`, when the request has it.
    pub fn meta_version(&self) -> Option<&str> {
        self.params.get("_meta")?.get(VERSION_META_KEY)?.as_str()
    }

    /// The revision of the request (1.3).
    pub fn revision(&self) -> Revision {
        if self.meta_version() == Some(REVISION) {
            Revision::V2026
        } else {
            Revision::Legacy
        }
    }

    /// The arguments of a `tools/call`, and the name of the tool.
    pub fn tool_call(&self) -> Option<(&str, &Value)> {
        let name = self.params.get("name")?.as_str()?;
        static EMPTY: Value = Value::Null;
        Some((name, self.params.get("arguments").unwrap_or(&EMPTY)))
    }

    /// True when the request is a notification: it has no `id`.
    pub fn is_notification(&self) -> bool {
        self.id.is_none()
    }
}

/// What the service does for a method (3.4, 3.6, 3.6a).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// `tools/list`: not a use. Call [`McpGate::list_tools`].
    ToolsList,
    /// `tools/call`: one operation. Call [`McpGate::call`].
    ToolsCall,
    /// A method with no tool, for example `initialize`, `ping`, `server/discover`
    /// or a notification. Call [`McpGate::session`].
    Session,
}

/// The kind of a method.
pub fn classify(method: &str) -> Kind {
    match method {
        "tools/list" => Kind::ToolsList,
        "tools/call" => Kind::ToolsCall,
        _ => Kind::Session,
    }
}

/// A reply of the MCP endpoint: an HTTP status, headers and an optional JSON-RPC body.
#[derive(Clone, Debug, PartialEq)]
pub struct McpReply {
    /// The HTTP status.
    pub status: u16,
    /// The headers other than `Content-Type`.
    pub headers: Vec<(String, String)>,
    /// The JSON body. It is `None` for an empty body.
    pub body: Option<Value>,
}

impl McpReply {
    /// The reply as an HTTP reply.
    pub fn to_http(&self) -> HttpReply {
        let mut reply = match &self.body {
            Some(body) => HttpReply::json(self.status, body),
            None => HttpReply::empty(self.status),
        };
        for (name, value) in &self.headers {
            reply = reply.with_header(name, value.clone());
        }
        reply
    }

    fn error(
        status: u16,
        id: Option<&Value>,
        code: i64,
        message: &str,
        data: Option<Value>,
    ) -> Self {
        let Some(id) = id else {
            // 5.6a: without the `id`, the body is empty.
            return Self {
                status,
                headers: Vec::new(),
                body: None,
            };
        };
        let mut error = Map::new();
        error.insert("code".into(), json!(code));
        error.insert("message".into(), json!(message));
        if let Some(data) = data {
            error.insert("data".into(), data);
        }
        Self {
            status,
            headers: Vec::new(),
            body: Some(json!({"jsonrpc": "2.0", "id": id, "error": Value::Object(error)})),
        }
    }
}

/// The reply for a body that is not a JSON-RPC request. The `id` is not known: the body is JSON-RPC with `id` null.
pub fn parse_error_reply(error: ParseError) -> McpReply {
    let (code, message) = match error {
        ParseError::NotJson => (CODE_PARSE_ERROR, "Parse error"),
        ParseError::NotRequest => (CODE_INVALID_REQUEST, "Invalid request"),
    };
    McpReply {
        status: 400,
        headers: Vec::new(),
        body: Some(
            json!({"jsonrpc": "2.0", "id": null, "error": {"code": code, "message": message}}),
        ),
    }
}

/// Check the header `MCP-Protocol-Version` against the version in `_meta` (1.3).
///
/// # Errors
/// Returns HTTP 400 with the code `-32020` when both are present and differ.
pub fn check_version(header: Option<&str>, request: &RpcRequest) -> Result<(), McpReply> {
    match (header, request.meta_version()) {
        (Some(header), Some(meta)) if header != meta => Err(McpReply::error(
            400,
            request.id.as_ref(),
            CODE_VERSION_MISMATCH,
            "Version mismatch",
            None,
        )),
        _ => Ok(()),
    }
}

/// The JSON-RPC result of a request. A result of the revision 2026-07-28 has `resultType` `complete`.
pub fn result_reply(request: &RpcRequest, mut result: Value) -> McpReply {
    if request.revision() == Revision::V2026
        && let Some(map) = result.as_object_mut()
    {
        map.entry("resultType").or_insert_with(|| json!("complete"));
    }
    match &request.id {
        Some(id) => McpReply {
            status: 200,
            headers: Vec::new(),
            body: Some(json!({"jsonrpc": "2.0", "id": id, "result": result})),
        },
        // A notification gets no JSON-RPC answer.
        None => McpReply {
            status: 202,
            headers: Vec::new(),
            body: None,
        },
    }
}

/// The JSON-RPC error `-32602` with a fixed message. A tool that the service
/// does not have and a tool that the PDP refuses get this same reply (5.1, 4.2).
pub fn unknown_tool_reply(request: &RpcRequest) -> McpReply {
    McpReply::error(
        200,
        request.id.as_ref(),
        CODE_INVALID_PARAMS,
        "Unknown tool",
        None,
    )
}

/// The JSON-RPC error `-32602` for arguments that do not name a node of the
/// service. The message is fixed. It differs from the message of an unknown tool.
/// The reply does not depend on the rights of the subject.
pub fn invalid_params_reply(request: &RpcRequest) -> McpReply {
    McpReply::error(
        200,
        request.id.as_ref(),
        CODE_INVALID_PARAMS,
        "Invalid params",
        None,
    )
}

/// The JSON-RPC error `-32601` for a method that the service does not have.
pub fn method_not_found_reply(request: &RpcRequest) -> McpReply {
    McpReply::error(
        200,
        request.id.as_ref(),
        CODE_METHOD_NOT_FOUND,
        "Method not found",
        None,
    )
}

/// The tool error for a refused budget (5.3).
pub fn budget_tool_error(request: &RpcRequest, retry_after: u64) -> McpReply {
    let error = json!({
        "code": "budget_exceeded",
        "message": "The budget of this action is spent.",
        "retryable": true,
        "retry_after": retry_after,
    });
    let structured = json!({"error": error});
    result_reply(
        request,
        json!({
            "content": [{"type": "text", "text": structured.to_string()}],
            "structuredContent": structured,
            "isError": true,
        }),
    )
}

/// A tool error with a fixed code and message, for a failure of the service itself.
pub fn tool_error(request: &RpcRequest, code: &str, message: &str) -> McpReply {
    let structured = json!({"error": {"code": code, "message": message, "retryable": false}});
    result_reply(
        request,
        json!({
            "content": [{"type": "text", "text": structured.to_string()}],
            "structuredContent": structured,
            "isError": true,
        }),
    )
}

/// Map a refusal of the PEP to the reply of the binding (section 5).
///
/// For `tools/call` (`for_tool_call` is true):
///
/// - `false`: HTTP 200 and `-32602`, as for an unknown tool.
/// - `budget_exceeded`: HTTP 200 and the tool error of 5.3.
///
/// For another method:
///
/// - `false`: HTTP 403 and `-32001`.
/// - `budget_exceeded`: HTTP 429 with `Retry-After` and `-31429`.
///
/// For each method, no answer of the PDP gives HTTP 503 and `-32603`. A refusal
/// of the token gives HTTP 401 with an empty body. The reply has the
/// JSON-RPC error only when the request has an `id` (5.6a). The messages are fixed.
pub fn refusal_reply(refusal: &Refusal, request: &RpcRequest, for_tool_call: bool) -> McpReply {
    let id = request.id.as_ref();
    match refusal {
        Refusal::Unauthenticated(_) => McpReply {
            status: 401,
            headers: Vec::new(),
            body: None,
        },
        Refusal::Forbidden { .. } if for_tool_call => unknown_tool_reply(request),
        Refusal::Forbidden { .. } => McpReply::error(403, id, CODE_FORBIDDEN, "forbidden", None),
        Refusal::RateLimited { retry_after } if for_tool_call => {
            budget_tool_error(request, *retry_after)
        }
        Refusal::RateLimited { retry_after } => {
            let mut reply = McpReply::error(
                429,
                id,
                CODE_RATE_LIMITED,
                "rate_limited",
                Some(json!({"retry_after": retry_after})),
            );
            reply
                .headers
                .push(("Retry-After".to_owned(), retry_after.to_string()));
            reply
        }
        Refusal::Unavailable(_) => {
            McpReply::error(503, id, CODE_INTERNAL, "Service unavailable", None)
        }
        Refusal::Internal(_) => McpReply::error(500, id, CODE_INTERNAL, "Internal error", None),
    }
}

/// The stage of a `tools/call` (3.4, 3.5, 3.5a).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// The call only asks the client for input or for an approval. It is not a
    /// use. The PEP asks without `context.usage`.
    Ask,
    /// The tool runs. This is the use. The PEP asks with `context.usage` when the action lists a budget.
    Run,
}

/// The PEP for the tools of one MCP endpoint.
#[derive(Debug)]
pub struct McpGate<'a> {
    pep: &'a Pep,
    tools: &'a ToolMap,
}

impl<'a> McpGate<'a> {
    /// A gate for these tools.
    pub fn new(pep: &'a Pep, tools: &'a ToolMap) -> Self {
        Self { pep, tools }
    }

    /// The operation for a tool: the action of the tool on the node that the
    /// service built from the arguments (3.2). Add other permissions with
    /// [`Operation::also`] (3.7).
    pub fn operation(&self, tool: &ToolSpec, node: crate::operation::NodePath) -> Operation {
        Operation::new(&tool.action, node)
    }

    /// Ask for a method that has no tool (3.6a). The PEP asks the action
    /// `mcp.session` on the service. When the action lists a budget, the request is one use.
    pub fn session(&self, who: &Identity) -> Result<Allowed, Refusal> {
        let service =
            node(self.pep.service_id(), &[]).map_err(|e| Refusal::Internal(e.to_string()))?;
        self.pep
            .decide(who, &Operation::new(SESSION_ACTION, service))
            .into_result()
    }

    /// The tools that the subject can see (4.1). For each action of the tools,
    /// the PEP asks the action on the service with `context.match` equal to
    /// `subtree`, without `context.usage`. The list keeps the order of the map (4.3).
    ///
    /// # Errors
    /// Returns [`Refusal::Unavailable`] when the PDP gives no valid answer (5.5).
    pub fn list_tools(&self, who: &Identity) -> Result<Vec<&'a ToolSpec>, Refusal> {
        let service =
            node(self.pep.service_id(), &[]).map_err(|e| Refusal::Internal(e.to_string()))?;
        let actions = self.tools.actions();
        let permissions: Vec<Permission> = actions
            .iter()
            .map(|a| Permission::new(*a, service.clone()))
            .collect();
        let visible = self.pep.display(who, &permissions)?;
        let allowed: BTreeSet<&str> = actions
            .iter()
            .zip(visible)
            .filter_map(|(action, seen)| seen.then_some(*action))
            .collect();
        Ok(self
            .tools
            .tools()
            .iter()
            .filter(|t| allowed.contains(t.action.as_str()))
            .collect())
    }

    /// Ask for one call of a tool, at the stage `stage` (3.4, 3.5, 3.5a, 3.7).
    /// A tool that the map does not have gets the refusal of a `false` answer.
    /// Thus an absent tool and a refused tool look the same (4.2, 5.1).
    ///
    /// # Errors
    /// Returns the refusal. Map it with [`refusal_reply`].
    pub fn call(
        &self,
        who: &Identity,
        tool: &str,
        operation: &Operation,
        stage: Stage,
    ) -> Result<Allowed, Refusal> {
        if self.tools.get(tool).is_none() {
            return Err(Refusal::Forbidden {
                reason: None,
                cause: crate::refusal::DenialCause::Decision,
            });
        }
        match stage {
            Stage::Ask => self.pep.check(who, operation),
            Stage::Run => self.pep.decide(who, operation),
        }
        .into_result()
    }
}

/// The result of a `tools/list`.
pub fn tools_list_reply(request: &RpcRequest, tools: &[&ToolSpec]) -> McpReply {
    let list: Vec<Value> = tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "inputSchema": t.input_schema,
            })
        })
        .collect();
    result_reply(request, json!({"tools": list}))
}

/// The result of a call that asks the client for input, in the form of the revision 2026-07-28.
/// `input_requests` is an object. Each member is a request for the client.
pub fn input_required_reply(
    request: &RpcRequest,
    input_requests: Value,
    request_state: Option<&str>,
) -> McpReply {
    let mut result = Map::new();
    result.insert("resultType".into(), json!("input_required"));
    result.insert("inputRequests".into(), input_requests);
    if let Some(state) = request_state {
        result.insert("requestState".into(), json!(state));
    }
    result_reply(request, Value::Object(result))
}

/// The answers of the client to a request for input: `params.inputResponses`.
/// The client controls them, so the service never trusts them for a decision.
/// The PDP decides, at the stage [`Stage::Run`].
pub fn input_responses(request: &RpcRequest) -> Option<&Map<String, Value>> {
    request.params.get("inputResponses")?.as_object()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(method: &str, params: Value, id: Option<Value>) -> RpcRequest {
        RpcRequest {
            id,
            method: method.to_owned(),
            params,
        }
    }

    fn call() -> RpcRequest {
        request(
            "tools/call",
            json!({"name": "read_rows", "arguments": {"a": 1}, "_meta": {VERSION_META_KEY: REVISION}}),
            Some(json!(7)),
        )
    }

    fn forbidden() -> Refusal {
        Refusal::Forbidden {
            reason: Some(procurauth_core::authzen::Reason::UnknownSubject),
            cause: crate::refusal::DenialCause::Decision,
        }
    }

    #[test]
    fn a_json_rpc_request_is_read() {
        let body = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"t","arguments":{"x":1},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;
        let r = RpcRequest::parse(body).unwrap();
        assert_eq!(r.id, Some(json!(7)));
        assert_eq!(r.method, "tools/call");
        assert_eq!(r.revision(), Revision::V2026);
        let (name, arguments) = r.tool_call().unwrap();
        assert_eq!(name, "t");
        assert_eq!(arguments["x"], 1);
        assert!(!r.is_notification());
    }

    #[test]
    fn a_body_that_is_not_a_request_is_refused() {
        assert_eq!(RpcRequest::parse(b"{not json"), Err(ParseError::NotJson));
        assert_eq!(
            RpcRequest::parse(br#"{"a":1,"a":2}"#),
            Err(ParseError::NotJson)
        );
        for body in [
            &br#"[]"#[..],
            br#"{"jsonrpc":"1.0","method":"x"}"#,
            br#"{"jsonrpc":"2.0"}"#,
            br#"{"jsonrpc":"2.0","method":5}"#,
            br#"{"jsonrpc":"2.0","method":"x","id":{"a":1}}"#,
            br#"{"jsonrpc":"2.0","method":"x","params":[1]}"#,
        ] {
            assert_eq!(
                RpcRequest::parse(body),
                Err(ParseError::NotRequest),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
        let r = RpcRequest::parse(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
            .unwrap();
        assert!(r.is_notification());
        assert_eq!(r.params, Value::Null);
    }

    #[test]
    fn a_parse_error_has_the_status_400() {
        let reply = parse_error_reply(ParseError::NotJson);
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body.unwrap()["error"]["code"], CODE_PARSE_ERROR);
    }

    #[test]
    fn mcp_1_3_a_header_and_a_meta_version_that_differ_give_400_and_32020() {
        let r = request(
            "ping",
            json!({"_meta": {VERSION_META_KEY: "2025-11-25"}}),
            Some(json!(7)),
        );
        let reply = check_version(Some("2026-07-28"), &r).unwrap_err();
        assert_eq!(reply.status, 400);
        assert_eq!(reply.body.unwrap()["error"]["code"], -32020);
        assert!(check_version(Some("2025-11-25"), &r).is_ok());
        assert!(check_version(None, &r).is_ok());
        assert!(
            check_version(
                Some("2026-07-28"),
                &request("ping", Value::Null, Some(json!(1)))
            )
            .is_ok()
        );
    }

    #[test]
    fn mcp_5_1_a_false_answer_on_tools_call_is_32602_with_status_200() {
        let reply = refusal_reply(&forbidden(), &call(), true);
        assert_eq!(reply.status, 200);
        let body = reply.body.unwrap();
        assert_eq!(body["error"]["code"], -32602);
        assert_eq!(body["id"], 7);
        assert!(body.get("result").is_none());
        // The reason never shows.
        assert!(!body.to_string().contains("unknown_subject"));
    }

    #[test]
    fn the_replies_for_bad_arguments_and_for_a_method_that_does_not_exist_have_fixed_messages() {
        let r = request("tools/call", json!({"name": "INJECTED"}), Some(json!(7)));
        let bad = invalid_params_reply(&r);
        assert_eq!(bad.status, 200);
        assert_eq!(
            bad.body.unwrap()["error"],
            json!({"code": -32602, "message": "Invalid params"})
        );
        let none = method_not_found_reply(&r);
        assert_eq!(none.body.unwrap()["error"]["code"], -32601);
        assert!(
            invalid_params_reply(&request("x", Value::Null, None))
                .body
                .is_none()
        );
    }

    #[test]
    fn mcp_4_2_a_missing_tool_and_a_refused_tool_get_the_same_reply() {
        let refused = refusal_reply(&forbidden(), &call(), true);
        assert_eq!(refused, unknown_tool_reply(&call()));
    }

    #[test]
    fn mcp_5_1b_a_false_answer_on_another_method_is_403_and_32001() {
        let ping = request(
            "ping",
            json!({"_meta": {VERSION_META_KEY: REVISION}}),
            Some(json!(7)),
        );
        let reply = refusal_reply(&forbidden(), &ping, false);
        assert_eq!(reply.status, 403);
        assert_eq!(
            reply.body.unwrap(),
            json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -32001, "message": "forbidden"}})
        );
    }

    #[test]
    fn mcp_5_3_a_refused_budget_on_tools_call_is_a_tool_error() {
        let reply = refusal_reply(&Refusal::RateLimited { retry_after: 12 }, &call(), true);
        assert_eq!(reply.status, 200);
        let body = reply.body.unwrap();
        let result = &body["result"];
        assert_eq!(result["resultType"], "complete");
        assert_eq!(result["isError"], true);
        assert_eq!(
            result["structuredContent"]["error"]["code"],
            "budget_exceeded"
        );
        assert_eq!(result["structuredContent"]["error"]["retryable"], true);
        assert_eq!(result["structuredContent"]["error"]["retry_after"], 12);
        // The text is the compact JSON of the structured content.
        let text = result["content"][0]["text"].as_str().unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(text).unwrap(),
            result["structuredContent"]
        );
        assert!(body.get("error").is_none());
    }

    #[test]
    fn mcp_5_3_a_legacy_revision_has_no_result_type() {
        let legacy = request("tools/call", json!({"name": "t"}), Some(json!(7)));
        let body = refusal_reply(&Refusal::RateLimited { retry_after: 3 }, &legacy, true)
            .body
            .unwrap();
        assert!(body["result"].get("resultType").is_none());
    }

    #[test]
    fn mcp_5_4_a_refused_budget_on_another_method_is_429_with_retry_after_and_31429() {
        let ping = request("ping", Value::Null, Some(json!(7)));
        let reply = refusal_reply(&Refusal::RateLimited { retry_after: 12 }, &ping, false);
        assert_eq!(reply.status, 429);
        assert_eq!(reply.to_http().header("Retry-After"), Some("12"));
        assert_eq!(
            reply.body.unwrap(),
            json!({"jsonrpc": "2.0", "id": 7, "error": {"code": -31429, "message": "rate_limited", "data": {"retry_after": 12}}})
        );
    }

    #[test]
    fn mcp_5_5_no_answer_of_the_pdp_is_503_and_32603_for_each_method() {
        let refusal = Refusal::Unavailable(crate::refusal::UnavailableCause::Status(500));
        for for_tool in [true, false] {
            let reply = refusal_reply(&refusal, &call(), for_tool);
            assert_eq!(reply.status, 503);
            assert_eq!(reply.body.unwrap()["error"]["code"], -32603);
        }
    }

    #[test]
    fn mcp_5_6a_without_an_id_the_body_is_empty() {
        let notification = request("notifications/initialized", Value::Null, None);
        for refusal in [
            forbidden(),
            Refusal::RateLimited { retry_after: 2 },
            Refusal::Unavailable(crate::refusal::UnavailableCause::Status(500)),
        ] {
            let reply = refusal_reply(&refusal, &notification, false);
            assert!(reply.body.is_none(), "{reply:?}");
            assert!(reply.to_http().body.is_empty());
        }
    }

    #[test]
    fn mcp_3_3a_a_refused_token_is_401_with_an_empty_body() {
        let refusal = Refusal::Unauthenticated(crate::refusal::AuthFailure::NoToken);
        let reply = refusal_reply(&refusal, &call(), true);
        assert_eq!(reply.status, 401);
        assert!(reply.to_http().body.is_empty());
    }

    #[test]
    fn mcp_5_6_an_error_copies_no_value_of_the_request() {
        let r = request(
            "tools/call",
            json!({"name": "INJECTED-MARKER", "arguments": {"x": "INJECTED-MARKER"}}),
            Some(json!(7)),
        );
        for reply in [
            unknown_tool_reply(&r),
            refusal_reply(&Refusal::RateLimited { retry_after: 3 }, &r, true),
            refusal_reply(&forbidden(), &r, false),
        ] {
            assert!(!reply.to_http().body.is_empty() || reply.body.is_none());
            assert!(!String::from_utf8_lossy(&reply.to_http().body).contains("INJECTED-MARKER"));
        }
    }

    #[test]
    fn mcp_4_3_the_map_keeps_the_order_and_shares_one_item_for_one_action() {
        let tool = |name: &str, action: &str| ToolSpec {
            name: name.into(),
            action: action.into(),
            description: String::new(),
            input_schema: json!({"type": "object"}),
        };
        let map = ToolMap::new(vec![
            tool("read_rows", "data.read"),
            tool("write_rows", "data.write"),
            tool("copy_table", "data.write"),
        ])
        .unwrap();
        assert_eq!(map.actions(), ["data.read", "data.write"]);
        assert_eq!(map.tools()[2].name, "copy_table");
        assert!(ToolMap::new(vec![tool("a", "x.y"), tool("a", "x.z")]).is_err());
    }

    #[test]
    fn mcp_5_3_a_tools_list_reply_names_the_tools() {
        let spec = ToolSpec {
            name: "read_rows".into(),
            action: "data.read".into(),
            description: "Read rows.".into(),
            input_schema: json!({"type": "object"}),
        };
        let reply = tools_list_reply(&call(), &[&spec]);
        let body = reply.body.unwrap();
        assert_eq!(body["result"]["tools"][0]["name"], "read_rows");
        assert_eq!(body["result"]["resultType"], "complete");
    }

    #[test]
    fn the_kind_of_a_method_decides_the_work() {
        assert_eq!(classify("tools/list"), Kind::ToolsList);
        assert_eq!(classify("tools/call"), Kind::ToolsCall);
        for method in [
            "initialize",
            "ping",
            "server/discover",
            "notifications/initialized",
        ] {
            assert_eq!(classify(method), Kind::Session);
        }
    }

    #[test]
    fn an_input_request_has_the_result_type_input_required() {
        let reply = input_required_reply(
            &call(),
            json!({"approval": {"method": "elicitation/create"}}),
            Some("s1"),
        );
        let result = reply.body.unwrap()["result"].clone();
        assert_eq!(result["resultType"], "input_required");
        assert_eq!(result["requestState"], "s1");
        let follow = request(
            "tools/call",
            json!({"name": "t", "inputResponses": {"approval": {"action": "accept"}}}),
            Some(json!(8)),
        );
        assert_eq!(
            input_responses(&follow).unwrap()["approval"]["action"],
            "accept"
        );
        assert!(input_responses(&call()).is_none());
    }
}
