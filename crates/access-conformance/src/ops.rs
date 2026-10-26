//! The operations of the data model, as requests to the service under test.
//!
//! The profile gives each operation a method, a path template, headers and a
//! body template. The runner replaces the variables. Some operations have
//! defaults. These are the read of the action document, the read of the
//! options route, and the calls of the MCP binding.

use serde_json::{Value, json};

use crate::http::Headers;
use crate::model::Operation;
use crate::profile::OpDef;
use crate::vars::Vars;

/// The revision of MCP that the requests use.
pub(crate) const MCP_REVISION: &str = "2026-07-28";
/// The JSON-RPC id of an MCP request.
const MCP_ID: u64 = 7;

/// The parts of a request, before the runner adds the step headers and the token.
#[derive(Clone, Debug)]
pub(crate) struct Parts {
    /// The method.
    pub(crate) method: String,
    /// The path with the query.
    pub(crate) target: String,
    /// The headers.
    pub(crate) headers: Headers,
    /// The body.
    pub(crate) body: Option<Vec<u8>>,
}

/// The variables that an operation gives.
pub(crate) fn op_vars(operation: Operation, def: &OpDef, service: &str) -> Vars {
    let mut vars = Vars::new();
    let text = |vars: &mut Vars, name: &str, value: &Option<String>| {
        if let Some(value) = value {
            vars.set(name, Value::String(value.clone()));
        }
    };
    text(&mut vars, "action", &def.action);
    text(&mut vars, "resource_type", &def.resource_type);
    text(&mut vars, "resource_id", &def.resource_id);
    text(&mut vars, "tool", &def.tool);
    text(&mut vars, "ceiling", &def.ceiling);
    if let Some(ancestors) = &def.ancestors {
        vars.set("ancestors", ancestors.clone());
    }
    if let Some(value) = def.ceiling_value {
        vars.set("ceiling_value", json!(value));
    }
    if operation == Operation::UseService {
        vars.set_default("resource_type", json!("service"));
        vars.set_default("resource_id", json!(service));
        vars.set_default("ancestors", json!([]));
    }
    vars
}

/// Set a header. A header with the same name, in any case, is replaced.
pub(crate) fn put_header(headers: &mut Headers, name: &str, value: &str) {
    headers.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
    headers.push((name.to_owned(), value.to_owned()));
}

/// True when the list has a header with this name.
pub(crate) fn has_header(headers: &Headers, name: &str) -> bool {
    headers.iter().any(|(n, _)| n.eq_ignore_ascii_case(name))
}

/// Build the request of an operation.
///
/// # Errors
/// Returns a message when a variable has no value.
pub(crate) fn build(operation: Operation, def: &OpDef, vars: &Vars) -> Result<Parts, String> {
    let unknown = |name: String| format!("the variable `{name}` has no value");
    let default_method = match operation {
        Operation::ReadActions | Operation::ListOptions => "GET",
        op if op.is_mcp() => "POST",
        _ => "GET",
    };
    let method = def
        .method
        .clone()
        .unwrap_or_else(|| default_method.to_owned());
    let template = def.path.clone().unwrap_or_else(|| match operation {
        Operation::ReadActions => "/.well-known/procurauth/actions".to_owned(),
        Operation::ListOptions => {
            "/.well-known/procurauth/resources?type={{options_type}}".to_owned()
        }
        _ => "{{mcp_path}}".to_owned(),
    });
    let target = vars.text(&template, false).map_err(unknown)?;
    if !target.starts_with('/') {
        return Err(format!(
            "the path of the operation must start with a slash, found \"{target}\""
        ));
    }
    let mut headers: Headers = Vec::new();
    if operation.is_mcp() {
        put_header(&mut headers, "Content-Type", "application/json");
        put_header(
            &mut headers,
            "Accept",
            "application/json, text/event-stream",
        );
        put_header(&mut headers, "MCP-Protocol-Version", MCP_REVISION);
    }
    for (name, value) in &def.headers {
        let name = vars.text(name, false).map_err(unknown)?;
        let value = vars.text(value, false).map_err(unknown)?;
        put_header(&mut headers, &name, &value);
    }
    let body = if let Some(body) = &def.body {
        Some(vars.value(body).map_err(unknown)?)
    } else if def.body_text.is_some() {
        None
    } else if matches!(
        operation,
        Operation::McpCallPlain
            | Operation::McpCallBudget
            | Operation::McpCallInput
            | Operation::McpCallMulti
            | Operation::McpCallApproval
    ) {
        let arguments = match &def.arguments {
            Some(arguments) => vars.value(arguments).map_err(unknown)?,
            None => json!({}),
        };
        Some(json!({
            "jsonrpc": "2.0",
            "id": MCP_ID,
            "method": "tools/call",
            "params": {
                "name": vars.string("{{tool}}").map_err(unknown)?,
                "arguments": arguments,
                "_meta": {"io.modelcontextprotocol/protocolVersion": MCP_REVISION},
            }
        }))
    } else {
        None
    };
    let bytes = match (&body, &def.body_text) {
        (Some(value), _) => {
            if !has_header(&headers, "content-type") {
                put_header(&mut headers, "Content-Type", "application/json");
            }
            Some(value.to_string().into_bytes())
        }
        (None, Some(text)) => Some(vars.text(text, false).map_err(unknown)?.into_bytes()),
        (None, None) => None,
    };
    Ok(Parts {
        method,
        target,
        headers,
        body: bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars() -> Vars {
        let mut vars = Vars::new();
        vars.set("mcp_path", json!("/mcp"));
        vars.set("options_type", json!("database"));
        vars.set("tool", json!("read_rows"));
        vars.set("resource_id", json!("orders"));
        vars
    }

    #[test]
    fn the_read_of_the_action_document_has_a_default() {
        let parts = build(Operation::ReadActions, &OpDef::default(), &vars()).unwrap();
        assert_eq!(parts.method, "GET");
        assert_eq!(parts.target, "/.well-known/procurauth/actions");
        assert!(parts.body.is_none());
    }

    #[test]
    fn the_read_of_the_options_route_uses_the_type() {
        let parts = build(Operation::ListOptions, &OpDef::default(), &vars()).unwrap();
        assert_eq!(
            parts.target,
            "/.well-known/procurauth/resources?type=database"
        );
    }

    #[test]
    fn a_use_has_the_method_the_path_and_the_body_of_the_profile() {
        let def = OpDef {
            method: Some("POST".into()),
            path: Some("/t/{{resource_id}}".into()),
            body: Some(json!({"id": "{{resource_id}}"})),
            ..OpDef::default()
        };
        let parts = build(Operation::UsePlain, &def, &vars()).unwrap();
        assert_eq!(parts.method, "POST");
        assert_eq!(parts.target, "/t/orders");
        assert_eq!(parts.body.unwrap(), br#"{"id":"orders"}"#);
        assert!(has_header(&parts.headers, "content-type"));
    }

    #[test]
    fn an_mcp_call_has_the_default_headers_and_body() {
        let def = OpDef {
            arguments: Some(json!({"table": "{{resource_id}}"})),
            ..OpDef::default()
        };
        let parts = build(Operation::McpCallPlain, &def, &vars()).unwrap();
        assert_eq!(parts.method, "POST");
        assert_eq!(parts.target, "/mcp");
        let body: Value = serde_json::from_slice(&parts.body.unwrap()).unwrap();
        assert_eq!(body["method"], "tools/call");
        assert_eq!(body["id"], 7);
        assert_eq!(body["params"]["name"], "read_rows");
        assert_eq!(body["params"]["arguments"]["table"], "orders");
        assert_eq!(
            body["params"]["_meta"]["io.modelcontextprotocol/protocolVersion"],
            "2026-07-28"
        );
        let get = |n: &str| {
            parts
                .headers
                .iter()
                .find(|(h, _)| h.eq_ignore_ascii_case(n))
                .map(|(_, v)| v.clone())
        };
        assert_eq!(get("MCP-Protocol-Version").as_deref(), Some("2026-07-28"));
        assert_eq!(
            get("Accept").as_deref(),
            Some("application/json, text/event-stream")
        );
    }

    #[test]
    fn the_profile_replaces_a_default_header_and_a_default_body() {
        let def = OpDef {
            headers: [("accept".to_owned(), "application/json".to_owned())].into(),
            body: Some(json!({"custom": true})),
            ..OpDef::default()
        };
        let parts = build(Operation::McpApprove, &def, &vars()).unwrap();
        let accepts: Vec<_> = parts
            .headers
            .iter()
            .filter(|(h, _)| h.eq_ignore_ascii_case("accept"))
            .collect();
        assert_eq!(accepts.len(), 1);
        assert_eq!(accepts[0].1, "application/json");
        assert_eq!(parts.body.unwrap(), br#"{"custom":true}"#);
    }

    #[test]
    fn the_variables_of_a_use_of_the_service_have_defaults() {
        let def = OpDef {
            action: Some("data.read".into()),
            ..OpDef::default()
        };
        let vars = op_vars(Operation::UseService, &def, "datastore");
        assert_eq!(vars.get("resource_type"), Some(&json!("service")));
        assert_eq!(vars.get("resource_id"), Some(&json!("datastore")));
        assert_eq!(vars.get("ancestors"), Some(&json!([])));
        assert_eq!(vars.get("action"), Some(&json!("data.read")));
    }

    #[test]
    fn an_unknown_variable_in_a_path_is_an_error() {
        let def = OpDef {
            path: Some("/x/{{nothing}}".into()),
            ..OpDef::default()
        };
        assert!(build(Operation::UsePlain, &def, &vars()).is_err());
    }
}
