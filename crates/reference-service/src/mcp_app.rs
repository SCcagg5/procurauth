//! The MCP endpoint of the service, with the helpers of `procurauth-pep::mcp`.
//!
//! The endpoint has five tools. The tools show each flow that the binding
//! describes.
//!
//! | Tool | Action | Flow |
//! | --- | --- | --- |
//! | `read_rows` | `data.read` | One use of an action that lists a budget (3.4). |
//! | `list_tables` | `data.inspect` | A use of an action that lists no budget. |
//! | `write_rows` | `data.write` | An approval: a question without usage, then one with usage (3.5a). |
//! | `copy_table` | `data.write` | Two permissions: a read and a write (3.7, 10.1a). |
//! | `query_table` | `data.read` | A call that asks the client for the table (3.5). |
//!
//! The form of the request for input follows the draft of the MCP revision
//! 2026-07-28. The result has `resultType` `input_required` and `inputRequests`.
//! The next call has `params.inputResponses`. The binding does not define this form.

use procurauth_core::names::validate_id;
use procurauth_pep::mcp::{
    Kind, McpGate, McpReply, REVISION, RpcRequest, Stage, ToolMap, ToolMapError, ToolSpec,
    check_version, classify, input_required_reply, input_responses, invalid_params_reply,
    method_not_found_reply, parse_error_reply, refusal_reply, result_reply, tool_error,
    tools_list_reply, unknown_tool_reply,
};
use procurauth_pep::operation::{NodePath, Operation, node};
use procurauth_pep::{Allowed, Identity};
use serde_json::{Value, json};

use crate::app::{App, DEFAULT_LIMIT, MAX_WRITE_ROWS, Routed};
use crate::document::{INSPECT, READ, WRITE};

fn tool(name: &str, action: &str, description: &str, schema: Value) -> ToolSpec {
    ToolSpec {
        name: name.to_owned(),
        action: action.to_owned(),
        description: description.to_owned(),
        input_schema: schema,
    }
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
    let tools = vec![
        tool(
            "read_rows",
            READ,
            "Read the rows of a table.",
            table_schema(&json!({"limit": {"type": "integer", "minimum": 1}})),
        ),
        tool(
            "write_rows",
            WRITE,
            "Add rows to a table. The client must approve the write.",
            table_schema(&json!({"rows": {"type": "array", "items": {"type": "object"}}})),
        ),
        tool(
            "copy_table",
            WRITE,
            "Copy a table into another database.",
            json!({"type": "object", "properties": {
                "from": {"type": "object"}, "to": {"type": "object"}}, "required": ["from", "to"]}),
        ),
        tool(
            "list_tables",
            INSPECT,
            "List the tables of a database.",
            json!({"type": "object", "properties": {
                "host": {"type": "string"}, "database": {"type": "string"}},
                "required": ["host", "database"]}),
        ),
        tool(
            "query_table",
            READ,
            "Read the rows of a table. The tool asks for the table when the call has none.",
            json!({"type": "object", "properties": {
                "host": {"type": "string"}, "database": {"type": "string"},
                "table": {"type": "string"}}, "required": ["host", "database"]}),
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
            "isError": false,
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
                Ok(list) => done(&tools_list_reply(&rpc, &list)),
                Err(refusal) => refused(&refusal, &rpc, false),
            },
            Kind::ToolsCall => self.mcp_call(&rpc, who, &gate),
            Kind::Session => match gate.session(who) {
                Ok(_) => done(&session_reply(&rpc)),
                Err(refusal) => refused(&refusal, &rpc, false),
            },
        }
    }

    fn ask(
        gate: &McpGate<'_>,
        who: &Identity,
        rpc: &RpcRequest,
        tool: &str,
        operation: &Operation,
        stage: Stage,
    ) -> Result<Allowed, Routed> {
        gate.call(who, tool, operation, stage)
            .map_err(|refusal| refused(&refusal, rpc, true))
    }

    fn mcp_call(&self, rpc: &RpcRequest, who: &Identity, gate: &McpGate<'_>) -> Routed {
        let Some((name, args)) = rpc.tool_call() else {
            return done(&invalid_params_reply(rpc));
        };
        if self.tools.get(name).is_none() {
            return done(&unknown_tool_reply(rpc));
        }
        let service = self.pep.service_id();
        let bad = || done(&invalid_params_reply(rpc));
        match name {
            "read_rows" => {
                let Some(path) = table_node(service, args) else {
                    return bad();
                };
                let operation = Operation::new(READ, path);
                match Self::ask(gate, who, rpc, name, &operation, Stage::Run) {
                    Ok(allowed) => self.rows_result(rpc, args, &allowed),
                    Err(routed) => routed,
                }
            }
            "list_tables" => {
                let Some(path) = database_node(service, args) else {
                    return bad();
                };
                let operation = Operation::new(INSPECT, path);
                match Self::ask(gate, who, rpc, name, &operation, Stage::Run) {
                    Err(routed) => routed,
                    Ok(_) => match self.store.tables(
                        id(args, "host").unwrap_or(""),
                        id(args, "database").unwrap_or(""),
                    ) {
                        Some(tables) => tool_result(rpc, &json!({"tables": tables})),
                        None => done(&tool_error(
                            rpc,
                            "not_found",
                            "The database does not exist.",
                        )),
                    },
                }
            }
            "write_rows" => self.mcp_write_rows(rpc, who, gate, args),
            "copy_table" => self.mcp_copy_table(rpc, who, gate, args),
            "query_table" => self.mcp_query_table(rpc, who, gate, args),
            _ => done(&unknown_tool_reply(rpc)),
        }
    }

    fn rows_result(&self, rpc: &RpcRequest, args: &Value, allowed: &Allowed) -> Routed {
        let requested = match args.get("limit") {
            None => DEFAULT_LIMIT,
            Some(value) => match value.as_u64() {
                Some(n) if n >= 1 => n,
                _ => return done(&invalid_params_reply(rpc)),
            },
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

    /// A tool with an effect: it waits for an approval (3.5a).
    fn mcp_write_rows(
        &self,
        rpc: &RpcRequest,
        who: &Identity,
        gate: &McpGate<'_>,
        args: &Value,
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
        let operation = Operation::new(WRITE, path);
        let approval = response(rpc, "approval")
            .and_then(|r| r.get("action"))
            .and_then(Value::as_str);
        match approval {
            // The call: the PEP asks the action without `context.usage`. This is not a use (3.5a).
            None => match Self::ask(gate, who, rpc, "write_rows", &operation, Stage::Ask) {
                Err(routed) => routed,
                Ok(_) => done(&input_required_reply(
                    rpc,
                    json!({"approval": {"method": "elicitation/create", "params": {
                        "message": "Approve the write of these rows?",
                        "requestedSchema": {"type": "object", "properties": {}}}}}),
                    None,
                )),
            },
            // A refused approval takes no unit, and the service asks nothing.
            Some("decline") => done(&tool_error(
                rpc,
                "approval_refused",
                "The approval is refused.",
            )),
            // The run, after the approval: the use, with `context.usage` (3.5a).
            Some("accept") => match Self::ask(gate, who, rpc, "write_rows", &operation, Stage::Run)
            {
                Err(routed) => routed,
                Ok(_) => {
                    let (host, database, table) = (
                        id(args, "host").unwrap_or(""),
                        id(args, "database").unwrap_or(""),
                        id(args, "table").unwrap_or(""),
                    );
                    match self
                        .store
                        .append(host, database, table, rows.clone(), false)
                    {
                        Some(total) => {
                            tool_result(rpc, &json!({"appended": rows.len(), "total": total}))
                        }
                        None => done(&tool_error(rpc, "not_found", "The table does not exist.")),
                    }
                }
            },
            Some(_) => done(&invalid_params_reply(rpc)),
        }
    }

    /// A tool that needs two permissions (3.7, 10.1a).
    fn mcp_copy_table(
        &self,
        rpc: &RpcRequest,
        who: &Identity,
        gate: &McpGate<'_>,
        args: &Value,
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
        let allowed = match Self::ask(gate, who, rpc, "copy_table", &operation, Stage::Run) {
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
            return match Self::ask(gate, who, rpc, "query_table", &operation, Stage::Ask) {
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
        let operation = Operation::new(READ, path);
        match Self::ask(gate, who, rpc, "query_table", &operation, Stage::Run) {
            Ok(allowed) => self.rows_result(rpc, &full, &allowed),
            Err(routed) => routed,
        }
    }
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
