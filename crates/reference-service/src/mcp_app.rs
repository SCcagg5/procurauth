//! The MCP endpoint of the service, with the helpers of `procurauth-pep::mcp`.
//!
//! The endpoint has five tools, and the tool `get_action_status`. The tools show each
//! flow that the binding describes. Each tool follows protocol section 17 (5.2b). When the PDP
//! asks for an approval, the tool follows 17.7 and gives the result of 5.7.
//! Each tool builds `op` and `view` of its call (17.3a).
//!
//! | Tool | Action | Flow |
//! | --- | --- | --- |
//! | `read_rows` | `data.read` | One use of an action that lists a budget (3.4). |
//! | `list_tables` | `data.inspect` | A use of an action that lists no budget. |
//! | `append_rows` | `data.append` | A use of an action that lists a budget. The `view` has a body. |
//! | `copy_table` | `data.write` | Two permissions: a read and a write (3.7, 10.1a). |
//! | `query_table` | `data.read` | A call that asks the client for the table (3.5). |
//! | `get_action_status` | none | The verdict of a request that waits (5.7b). |
//!
//! The form of the request for input follows the draft of the MCP revision
//! 2026-07-28. The result has `resultType` `input_required` and `inputRequests`.
//! The next call has `params.inputResponses`. The binding does not define this form.

use procurauth_core::names::validate_id;
use procurauth_pep::approval::ApprovalRefusal;
use procurauth_pep::mcp::{
    ApprovalArguments, Kind, McpGate, McpReply, REVISION, RpcRequest, STATUS_TOOL, Stage, ToolMap,
    ToolMapError, ToolSpec, awaiting_reply, check_version, classify, input_required_reply,
    input_responses, invalid_argument_reply, invalid_params_reply, method_not_found_reply,
    parse_error_reply, refusal_reply, result_reply, split_approval_arguments, status_reply,
    status_request_id, tool_error, tools_list_reply_with_status, unknown_tool_reply,
};
use procurauth_pep::operation::{NodePath, Operation, node};
use procurauth_pep::{Allowed, Identity, Outcome};
use serde_json::{Value, json};

use crate::app::{App, DEFAULT_LIMIT, MAX_WRITE_ROWS, Routed};

/// The most bytes of the body of a `view` ([CONTRACT, 9.5]).
const MAX_BODY_BYTES: usize = 16 * 1024;
use crate::document::{APPEND, INSPECT, READ, WRITE};

fn tool(name: &str, action: &str, description: &str, schema: Value) -> ToolSpec {
    ToolSpec {
        name: name.to_owned(),
        action: action.to_owned(),
        description: description.to_owned(),
        input_schema: schema,
    }
}

/// The sentence that each tool description has (binding 5.7).
const APPROVAL_NOTE: &str = " The call can need the approval of the owner, and the decision point decides. \
    If it does, the tool gives an action in the status awaiting_approval with executed false, and the tool did not run. \
    After the approval, call the tool again with the same arguments. Read the verdict with get_action_status. \
    A call gives at most one of approval_ref, lease_s and until. A call that needs an approval and has none gets invalid_argument. \
    The arguments wait_s and supersedes are optional.";

/// Add the control arguments of binding 5.7 to the schema of a tool.
fn with_controls(mut schema: Value) -> Value {
    if let Some(map) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        map.insert("approval_ref".into(), json!({"type": "string"}));
        map.insert("lease_s".into(), json!({"type": "integer", "minimum": 1}));
        map.insert("until".into(), json!({"type": "string"}));
        map.insert("wait_s".into(), json!({"type": "integer", "minimum": 0}));
        map.insert("supersedes".into(), json!({"type": "string"}));
    }
    schema
}

fn table_schema(extra: &Value) -> Value {
    let mut properties = json!({
        "host": {"type": "string"},
        "database": {"type": "string"},
        "table": {"type": "string"},
    });
    if let (Some(map), Some(more)) = (properties.as_object_mut(), extra.as_object()) {
        map.extend(more.clone());
    }
    json!({"type": "object", "properties": properties, "required": ["host", "database", "table"]})
}

/// The map of the tools (3.2). The order is the order of the list (4.3).
///
/// # Errors
/// Returns an error when two tools have the same name. The names are fixed, so a test checks this.
pub fn tool_map() -> Result<ToolMap, ToolMapError> {
    let note = |text: &str| format!("{text}{APPROVAL_NOTE}");
    let tools = vec![
        tool(
            "read_rows",
            READ,
            &note("Read the rows of a table."),
            with_controls(table_schema(
                &json!({"limit": {"type": "integer", "minimum": 1}}),
            )),
        ),
        tool(
            "append_rows",
            APPEND,
            &note("Add rows to a table."),
            with_controls(table_schema(&json!({
                "rows": {"type": "array", "items": {"type": "object"}},
            }))),
        ),
        tool(
            "copy_table",
            WRITE,
            &note("Copy a table into another database."),
            with_controls(json!({"type": "object", "properties": {
                "from": {"type": "object"}, "to": {"type": "object"}}, "required": ["from", "to"]})),
        ),
        tool(
            "list_tables",
            INSPECT,
            &note(
                "List the tables of a database. The argument like keeps the tables whose name starts with it.",
            ),
            with_controls(json!({"type": "object", "properties": {
                "host": {"type": "string"}, "database": {"type": "string"},
                "like": {"type": "string"}},
                "required": ["host", "database"]})),
        ),
        tool(
            "query_table",
            READ,
            &note("Read the rows of a table. The tool asks for the table when the call has none."),
            with_controls(json!({"type": "object", "properties": {
                "host": {"type": "string"}, "database": {"type": "string"},
                "table": {"type": "string"}}, "required": ["host", "database"]})),
        ),
    ];
    ToolMap::new(tools)
}

fn id<'v>(value: &'v Value, name: &str) -> Option<&'v str> {
    let text = value.get(name)?.as_str()?;
    validate_id(text).ok()?;
    Some(text)
}

fn table_node(service: &str, args: &Value) -> Option<NodePath> {
    node(
        service,
        &[
            ("host", id(args, "host")?),
            ("database", id(args, "database")?),
            ("table", id(args, "table")?),
        ],
    )
    .ok()
}

fn database_node(service: &str, args: &Value) -> Option<NodePath> {
    node(
        service,
        &[
            ("host", id(args, "host")?),
            ("database", id(args, "database")?),
        ],
    )
    .ok()
}

fn done(reply: &McpReply) -> Routed {
    Routed::plain(reply.to_http())
}

fn refused(refusal: &procurauth_pep::Refusal, rpc: &RpcRequest, for_tool: bool) -> Routed {
    Routed {
        reply: refusal_reply(refusal, rpc, for_tool).to_http(),
        note: Some(refusal.to_string()),
    }
}

fn tool_result(rpc: &RpcRequest, structured: &Value) -> Routed {
    done(&result_reply(
        rpc,
        json!({
            "content": [{"type": "text", "text": structured.to_string()}],
            "structuredContent": structured,
        }),
    ))
}

/// The answer of the client to a request for input, from `params.inputResponses`.
fn response<'r>(rpc: &'r RpcRequest, key: &str) -> Option<&'r Value> {
    input_responses(rpc)?.get(key)
}

impl App {
    /// Handle one request to the MCP endpoint. The caller checked the identity
    /// token before it called this method (binding 3.3, 3.3a).
    pub(crate) fn mcp(&self, request: &crate::http::Request, who: &Identity) -> Routed {
        let rpc = match RpcRequest::parse(&request.body) {
            Ok(rpc) => rpc,
            Err(error) => return done(&parse_error_reply(error)),
        };
        if let Err(reply) = check_version(request.header("MCP-Protocol-Version"), &rpc) {
            return done(&reply);
        }
        let gate = McpGate::new(&self.pep, &self.tools);
        match classify(&rpc.method) {
            Kind::ToolsList => match gate.list_tools(who) {
                Ok(list) => done(&tools_list_reply_with_status(
                    &rpc,
                    &list,
                    gate.lists_status_tool(&list),
                )),
                Err(refusal) => refused(&refusal, &rpc, false),
            },
            Kind::ToolsCall => self.mcp_call(&rpc, who, &gate),
            Kind::Session => match gate.session(who) {
                Ok(_) => done(&session_reply(&rpc)),
                Err(refusal) => refused(&refusal, &rpc, false),
            },
        }
    }

    /// Ask for the use that a tool call makes, and follow protocol 17.7 when the PDP asks for an approval
    /// (binding 3.5a). `build` gives `op` and `view` of the call (17.3a). It runs only when the PDP asks
    /// for an approval. A call that waits gives the result of 5.7 as an `Err`.
    fn gated(
        gate: &McpGate<'_>,
        who: &Identity,
        rpc: &RpcRequest,
        tool: &str,
        operation: &Operation,
        controls: &ApprovalArguments,
        build: impl FnOnce() -> Result<(Value, Value), ApprovalRefusal>,
    ) -> Result<Allowed, Routed> {
        match gate.approve(who, tool, operation, || {
            build().map(|(op, view)| controls.into_call(op, view))
        }) {
            Outcome::Allowed(allowed) => Ok(allowed),
            Outcome::ApprovalRequired(pending) => Err(done(&awaiting_reply(rpc, &pending))),
            Outcome::Refused(refusal) => Err(refused(&refusal, rpc, true)),
        }
    }

    /// Ask for a call that asks the client for input. It is not a use (binding 3.5).
    fn ask_input(
        gate: &McpGate<'_>,
        who: &Identity,
        rpc: &RpcRequest,
        tool: &str,
        operation: &Operation,
    ) -> Result<Allowed, Routed> {
        gate.call(who, tool, operation, Stage::Ask)
            .map_err(|refusal| refused(&refusal, rpc, true))
    }

    fn mcp_call(&self, rpc: &RpcRequest, who: &Identity, gate: &McpGate<'_>) -> Routed {
        let Some((name, args)) = rpc.tool_call() else {
            return done(&invalid_params_reply(rpc));
        };
        if name == STATUS_TOOL && gate.has_status_tool() {
            return Self::mcp_status(rpc, who, gate, args);
        }
        if self.tools.get(name).is_none() {
            return done(&unknown_tool_reply(rpc));
        }
        let service = self.pep.service_id();
        let bad = || done(&invalid_params_reply(rpc));
        // Step 2 of [CONTRACT, 9.4]: the control arguments. A bad call asks the PDP nothing.
        let Ok(controls) = split_approval_arguments(args) else {
            return done(&invalid_argument_reply(rpc));
        };
        match name {
            "read_rows" => {
                let Some(path) = table_node(service, args) else {
                    return bad();
                };
                let Some(limit) = requested_limit(args) else {
                    return bad();
                };
                let operation = Operation::new(READ, path);
                let build = || {
                    Ok(read_command(
                        "read_rows",
                        "Read the rows of a table",
                        args,
                        limit,
                    ))
                };
                match Self::gated(gate, who, rpc, name, &operation, &controls, build) {
                    Ok(allowed) => self.rows_result(rpc, args, &allowed),
                    Err(routed) => routed,
                }
            }
            "list_tables" => {
                let Some(path) = database_node(service, args) else {
                    return bad();
                };
                let like = match args.get("like") {
                    None => "",
                    Some(Value::String(text)) => text.as_str(),
                    Some(_) => return bad(),
                };
                let operation = Operation::new(INSPECT, path);
                let build = || {
                    Ok((
                        json!({"tool": "list_tables", "host": text_of(args, "host"),
                               "database": text_of(args, "database"), "like": like}),
                        json!({"title": "List the tables of a database",
                               "fields": [["Host", "/host"], ["Database", "/database"],
                                          ["Name starts with", "/like"]]}),
                    ))
                };
                match Self::gated(gate, who, rpc, name, &operation, &controls, build) {
                    Err(routed) => routed,
                    Ok(_) => match self.store.tables(
                        id(args, "host").unwrap_or(""),
                        id(args, "database").unwrap_or(""),
                    ) {
                        Some(tables) => {
                            let kept: Vec<&String> = tables
                                .iter()
                                .filter(|name| name.starts_with(like))
                                .collect();
                            tool_result(rpc, &json!({"tables": kept}))
                        }
                        None => done(&tool_error(
                            rpc,
                            "not_found",
                            "The database does not exist.",
                        )),
                    },
                }
            }
            "append_rows" => self.mcp_append_rows(rpc, who, gate, args, &controls),
            "copy_table" => self.mcp_copy_table(rpc, who, gate, args, &controls),
            "query_table" => self.mcp_query_table(rpc, who, gate, args, &controls),
            _ => done(&unknown_tool_reply(rpc)),
        }
    }

    fn rows_result(&self, rpc: &RpcRequest, args: &Value, allowed: &Allowed) -> Routed {
        let Some(requested) = requested_limit(args) else {
            return done(&invalid_params_reply(rpc));
        };
        // Step 6: the ceiling `max_rows` lowers the request (7.5).
        let limit = allowed.ceilings().cap("max_rows", requested).value;
        let wanted = usize::try_from(limit).unwrap_or(usize::MAX);
        let (host, database, table) = (
            id(args, "host").unwrap_or(""),
            id(args, "database").unwrap_or(""),
            id(args, "table").unwrap_or(""),
        );
        match self.store.read(host, database, table, wanted) {
            None => done(&tool_error(rpc, "not_found", "The table does not exist.")),
            Some((rows, total)) => tool_result(
                rpc,
                &json!({"rows": rows, "count": rows.len(), "limit": limit, "truncated": total > rows.len()}),
            ),
        }
    }

    /// A tool that adds rows. Its `op` has the rows as the compact JSON text of the array, so that the
    /// `view` can show them as a body (17.9). The tool refuses rows that do not fit in the body of a
    /// `view`, and it never hides a part of them ([CONTRACT, 9.5]).
    fn mcp_append_rows(
        &self,
        rpc: &RpcRequest,
        who: &Identity,
        gate: &McpGate<'_>,
        args: &Value,
        controls: &ApprovalArguments,
    ) -> Routed {
        let service = self.pep.service_id();
        let Some(path) = table_node(service, args) else {
            return done(&invalid_params_reply(rpc));
        };
        let Some(rows) = args.get("rows").and_then(Value::as_array) else {
            return done(&invalid_params_reply(rpc));
        };
        if rows.len() > MAX_WRITE_ROWS || !rows.iter().all(Value::is_object) {
            return done(&invalid_params_reply(rpc));
        }
        let (host, database, table) = (
            id(args, "host").unwrap_or(""),
            id(args, "database").unwrap_or(""),
            id(args, "table").unwrap_or(""),
        );
        let operation = Operation::new(APPEND, path);
        let build = || {
            let text = Value::Array(rows.clone()).to_string();
            if text.len() > MAX_BODY_BYTES {
                return Err(ApprovalRefusal::InvalidArgument);
            }
            Ok((
                json!({"tool": "append_rows", "host": host, "database": database,
                       "table": table, "rows": text}),
                json!({
                    "title": "Add rows to a table",
                    "fields": [["Host", "/host"], ["Database", "/database"], ["Table", "/table"]],
                    "body": "/rows",
                    "body_label": "Rows, as JSON",
                }),
            ))
        };
        match Self::gated(gate, who, rpc, "append_rows", &operation, controls, build) {
            Err(routed) => routed,
            Ok(_) => match self
                .store
                .append(host, database, table, rows.clone(), false)
            {
                Some(total) => tool_result(rpc, &json!({"appended": rows.len(), "total": total})),
                None => done(&tool_error(rpc, "not_found", "The table does not exist.")),
            },
        }
    }

    /// The tool `get_action_status` (5.7b). It asks the PDP no question. It reads the verdict on
    /// the approval API with the subject of the token. The read renews the lease.
    fn mcp_status(rpc: &RpcRequest, who: &Identity, gate: &McpGate<'_>, args: &Value) -> Routed {
        let Some(request_id) = status_request_id(args) else {
            return done(&invalid_argument_reply(rpc));
        };
        match gate.status(who, request_id) {
            Ok(verdict) => done(&status_reply(rpc, verdict)),
            Err(refusal) => refused(&refusal, rpc, true),
        }
    }

    /// A tool that needs two permissions (3.7, 10.1a). The write is the use. The read of the
    /// source is asked first, with no effect (protocol 17.1).
    fn mcp_copy_table(
        &self,
        rpc: &RpcRequest,
        who: &Identity,
        gate: &McpGate<'_>,
        args: &Value,
        controls: &ApprovalArguments,
    ) -> Routed {
        let service = self.pep.service_id();
        let (Some(from), Some(to)) = (args.get("from"), args.get("to")) else {
            return done(&invalid_params_reply(rpc));
        };
        let (Some(source), Some(target)) = (table_node(service, from), database_node(service, to))
        else {
            return done(&invalid_params_reply(rpc));
        };
        let operation = Operation::new(WRITE, target).also(READ, source.clone());
        let build = || {
            Ok((
                json!({"tool": "copy_table",
                       "from": {"host": text_of(from, "host"), "database": text_of(from, "database"),
                                "table": text_of(from, "table")},
                       "to": {"host": text_of(to, "host"), "database": text_of(to, "database")}}),
                json!({"title": "Copy a table into another database",
                       "fields": [["From host", "/from/host"], ["From database", "/from/database"],
                                  ["From table", "/from/table"], ["To host", "/to/host"],
                                  ["To database", "/to/database"]]}),
            ))
        };
        let allowed = match Self::gated(gate, who, rpc, "copy_table", &operation, controls, build) {
            Ok(allowed) => allowed,
            Err(routed) => return routed,
        };
        let limit = allowed
            .ceilings_for(READ, &source)
            .map_or(u64::MAX, |c| c.cap("max_rows", u64::MAX).value);
        let wanted = usize::try_from(limit).unwrap_or(usize::MAX);
        let (host, database, table) = (
            id(from, "host").unwrap_or(""),
            id(from, "database").unwrap_or(""),
            id(from, "table").unwrap_or(""),
        );
        let Some((rows, total)) = self.store.read(host, database, table, wanted) else {
            return done(&tool_error(rpc, "not_found", "The table does not exist."));
        };
        let copied = rows.len();
        match self.store.append(
            id(to, "host").unwrap_or(""),
            id(to, "database").unwrap_or(""),
            table,
            rows,
            true,
        ) {
            Some(_) => tool_result(rpc, &json!({"copied": copied, "truncated": total > copied})),
            None => done(&tool_error(
                rpc,
                "not_found",
                "The database does not exist.",
            )),
        }
    }

    /// A tool that asks the client for the table (3.5). The call with no table
    /// is not a use. The call with the table is the use.
    fn mcp_query_table(
        &self,
        rpc: &RpcRequest,
        who: &Identity,
        gate: &McpGate<'_>,
        args: &Value,
        controls: &ApprovalArguments,
    ) -> Routed {
        let service = self.pep.service_id();
        let answered = response(rpc, "table")
            .and_then(|r| r.get("content"))
            .and_then(|c| c.get("table"))
            .and_then(Value::as_str);
        let table = id(args, "table").or_else(|| answered.filter(|t| validate_id(t).is_ok()));
        let Some(table) = table else {
            // No table: the PEP asks the action on the database, without usage. The call asks the client.
            let Some(database) = database_node(service, args) else {
                return done(&invalid_params_reply(rpc));
            };
            let operation = Operation::new(READ, database);
            return match Self::ask_input(gate, who, rpc, "query_table", &operation) {
                Err(routed) => routed,
                Ok(_) => done(&input_required_reply(
                    rpc,
                    json!({"table": {"method": "elicitation/create", "params": {
                        "message": "Which table?",
                        "requestedSchema": {"type": "object",
                            "properties": {"table": {"type": "string"}}, "required": ["table"]}}}}),
                    None,
                )),
            };
        };
        let mut full = args.clone();
        if let Some(map) = full.as_object_mut() {
            map.insert("table".into(), json!(table));
        }
        let Some(path) = table_node(service, &full) else {
            return done(&invalid_params_reply(rpc));
        };
        let Some(limit) = requested_limit(&full) else {
            return done(&invalid_params_reply(rpc));
        };
        let operation = Operation::new(READ, path);
        let build = || {
            Ok(read_command(
                "query_table",
                "Read the rows of a table",
                &full,
                limit,
            ))
        };
        match Self::gated(gate, who, rpc, "query_table", &operation, controls, build) {
            Ok(allowed) => self.rows_result(rpc, &full, &allowed),
            Err(routed) => routed,
        }
    }
}

/// The text of a member of the arguments. A member that is not a text gives the empty text.
fn text_of<'v>(value: &'v Value, name: &str) -> &'v str {
    value.get(name).and_then(Value::as_str).unwrap_or("")
}

/// The number of rows that a read asks for: the argument `limit`, or the default. `None` when `limit`
/// is not a whole number from 1. The default is explicit in `op` (17.3a).
fn requested_limit(args: &Value) -> Option<u64> {
    match args.get("limit") {
        None => Some(DEFAULT_LIMIT),
        Some(value) => value.as_u64().filter(|n| *n >= 1),
    }
}

/// `op` and `view` of a read of the rows of a table (17.3a). The tool name is in `op`, so an approval
/// of one tool never covers another tool with the same action (17.3a).
fn read_command(tool: &str, title: &str, args: &Value, limit: u64) -> (Value, Value) {
    (
        json!({"tool": tool, "host": text_of(args, "host"), "database": text_of(args, "database"),
               "table": text_of(args, "table"), "limit": limit}),
        json!({"title": title,
               "fields": [["Host", "/host"], ["Database", "/database"], ["Table", "/table"],
                          ["Most rows", "/limit"]]}),
    )
}

/// The result of a method that has no tool (binding 3.6a). The binding gives no
/// result for these methods, so the service gives the smallest good one.
fn session_reply(rpc: &RpcRequest) -> McpReply {
    let info = json!({"name": "reference-service", "version": env!("CARGO_PKG_VERSION")});
    match rpc.method.as_str() {
        "initialize" => result_reply(
            rpc,
            json!({"protocolVersion": REVISION, "capabilities": {"tools": {}}, "serverInfo": info}),
        ),
        "server/discover" => result_reply(
            rpc,
            json!({"supportedVersions": [REVISION], "capabilities": {"tools": {}}, "serverInfo": info}),
        ),
        "ping" => result_reply(rpc, json!({})),
        method if method.starts_with("notifications/") => result_reply(rpc, json!({})),
        _ => method_not_found_reply(rpc),
    }
}
