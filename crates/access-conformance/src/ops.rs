//! The operations of the data model, as requests to the service under test.
//!
//! The profile gives each operation a method, a path template, headers and a
//! body template. The runner replaces the variables. Some operations have
//! defaults. These are the read of the action document, the read of the
//! options route, and the calls of the MCP binding.

use serde_json::{Value, json};

use procurauth_core::effect::{effect_hash, resource_text};
use procurauth_core::path::{NodePath, NodeRef};

use crate::http::Headers;
use crate::model::{Operation, Variant};
use crate::profile::OpDef;
use crate::vars::Vars;

/// The revision of MCP that the requests use.
pub(crate) const MCP_REVISION: &str = "2026-07-28";
/// The JSON-RPC id of an MCP request.
const MCP_ID: u64 = 7;
/// The value of the control argument `lease_s` in the base call of `mcp_call_approval`.
pub(crate) const BASE_LEASE_SECONDS: u64 = 900;
/// The value of the variable `approval_ref`, and of the control argument of the variant `approval_ref`.
pub(crate) const APPROVAL_REF: &str = "ref_conformance_0001";
/// The value of the control argument `wait_s` in the variant `wait`.
pub(crate) const WAIT_SECONDS: u64 = 1;

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

/// The effects of the three calls of `mcp_call_approval`: the base call, `effect_2` and `effect_3` (protocol 17.3).
///
/// # Errors
/// Returns a message when the operation has no `approval` member, or when the node or an `op`
/// is not valid.
pub(crate) fn effects(def: &OpDef, service: &str) -> Result<[String; 3], String> {
    let approval = def
        .approval
        .as_ref()
        .ok_or_else(|| "the operation has no member `approval`".to_owned())?;
    let action = def
        .action
        .as_deref()
        .ok_or_else(|| "the operation has no member `action`".to_owned())?;
    let (Some(kind), Some(id), Some(Value::Array(ancestors))) = (
        def.resource_type.as_deref(),
        def.resource_id.as_deref(),
        def.ancestors.as_ref(),
    ) else {
        return Err(
            "the operation has no `resource_type`, `resource_id` or `ancestors`".to_owned(),
        );
    };
    let mut nodes: Vec<NodeRef> = Vec::new();
    for item in ancestors {
        let (Some(t), Some(i)) = (
            item.get("type").and_then(Value::as_str),
            item.get("id").and_then(Value::as_str),
        ) else {
            return Err("an ancestor has no `type` or `id`".to_owned());
        };
        nodes.push(NodeRef::new(t, i));
    }
    nodes.push(NodeRef::new(kind, id));
    let node = NodePath::from_nodes(nodes).map_err(|e| format!("the node is not valid: {e}"))?;
    if node.service_id() != service {
        return Err(format!(
            "the chain starts with the service `{}`, and the profile has the service `{service}`",
            node.service_id()
        ));
    }
    let resource = resource_text(&node);
    let one = |op: &Value| {
        effect_hash(service, action, &resource, op).map_err(|e| format!("`op` is not valid: {e}"))
    };
    Ok([
        one(&approval.op)?,
        one(&approval.effect_2.op)?,
        one(&approval.effect_3.op)?,
    ])
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
    if operation == Operation::McpCallApproval {
        // The action of the other permission of the call, or a text that no action has (protocol 5.2).
        vars.set(
            "other_action",
            Value::String(def.other_action.clone().unwrap_or_else(|| "-".to_owned())),
        );
    }
    if operation == Operation::McpCallApproval
        && let Ok([base, second, third]) = effects(def, service)
    {
        vars.set("effect", json!(base));
        vars.set("effect_2", json!(second));
        vars.set("effect_3", json!(third));
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

/// Add the headers `Mcp-Method` and `Mcp-Name` of a JSON-RPC request ([CONTRACT, 2.5]).
///
/// `Mcp-Method` has the method of the body. For `tools/call`, `Mcp-Name` has the tool name.
/// A header that the step already sets stays as it is.
fn add_mcp_headers(headers: &mut Headers, body: &Value) {
    let Some(method) = body.get("method").and_then(Value::as_str) else {
        return;
    };
    if !has_header(headers, "mcp-method") {
        put_header(headers, "Mcp-Method", method);
    }
    if method == "tools/call"
        && !has_header(headers, "mcp-name")
        && let Some(name) = body.pointer("/params/name").and_then(Value::as_str)
    {
        put_header(headers, "Mcp-Name", name);
    }
}

/// The arguments of a call of `mcp_call_approval`: the arguments of the base call or of the variant
/// `effect_2` or `effect_3`, and the control arguments. The base call has `lease_s`. The variant
/// `approval_ref` gives `approval_ref` in place of it. The variant `no_control` has no control argument.
/// The variant `wait` adds `wait_s`.
fn approval_arguments(def: &OpDef, vars: &Vars, variant: Option<Variant>) -> Result<Value, String> {
    let unknown = |name: String| format!("the variable `{name}` has no value");
    let template = match (variant, &def.approval) {
        (Some(Variant::Effect2), Some(a)) => Some(&a.effect_2.arguments),
        (Some(Variant::Effect3), Some(a)) => Some(&a.effect_3.arguments),
        _ => def.arguments.as_ref(),
    };
    let mut arguments = match template {
        Some(t) => vars.value(t).map_err(unknown)?,
        None => json!({}),
    };
    let Some(map) = arguments.as_object_mut() else {
        return Err("the arguments of the call are not a JSON object".to_owned());
    };
    match variant {
        Some(Variant::ApprovalRef) => {
            map.insert("approval_ref".to_owned(), json!(APPROVAL_REF));
        }
        Some(Variant::NoControl) => {}
        _ => {
            map.insert("lease_s".to_owned(), json!(BASE_LEASE_SECONDS));
        }
    }
    if variant == Some(Variant::Wait) {
        map.insert("wait_s".to_owned(), json!(WAIT_SECONDS));
    }
    Ok(arguments)
}

/// Build the request of an operation. The `variant` changes the base call of `mcp_call_approval`.
///
/// # Errors
/// Returns a message when a variable has no value.
pub(crate) fn build(
    operation: Operation,
    def: &OpDef,
    vars: &Vars,
    variant: Option<Variant>,
) -> Result<Parts, String> {
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
        let arguments = if operation == Operation::McpCallApproval {
            approval_arguments(def, vars, variant)?
        } else {
            match &def.arguments {
                Some(arguments) => vars.value(arguments).map_err(unknown)?,
                None => json!({}),
            }
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
    if let Some(value) = &body
        && operation.is_mcp()
    {
        add_mcp_headers(&mut headers, value);
    }
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
        let parts = build(Operation::ReadActions, &OpDef::default(), &vars(), None).unwrap();
        assert_eq!(parts.method, "GET");
        assert_eq!(parts.target, "/.well-known/procurauth/actions");
        assert!(parts.body.is_none());
    }

    #[test]
    fn the_read_of_the_options_route_uses_the_type() {
        let parts = build(Operation::ListOptions, &OpDef::default(), &vars(), None).unwrap();
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
        let parts = build(Operation::UsePlain, &def, &vars(), None).unwrap();
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
        let parts = build(Operation::McpCallPlain, &def, &vars(), None).unwrap();
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
        assert_eq!(get("Mcp-Method").as_deref(), Some("tools/call"));
        assert_eq!(get("Mcp-Name").as_deref(), Some("read_rows"));
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
        let parts = build(Operation::McpApprove, &def, &vars(), None).unwrap();
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
    fn a_header_of_the_step_replaces_the_default_mcp_headers() {
        let def = OpDef {
            headers: [("mcp-method".to_owned(), "ping".to_owned())].into(),
            ..OpDef::default()
        };
        let parts = build(Operation::McpCallPlain, &def, &vars(), None).unwrap();
        let methods: Vec<_> = parts
            .headers
            .iter()
            .filter(|(h, _)| h.eq_ignore_ascii_case("mcp-method"))
            .collect();
        assert_eq!(methods.len(), 1);
        assert_eq!(methods[0].1, "ping");
    }

    #[test]
    fn a_body_without_a_method_gets_no_mcp_method_header() {
        let def = OpDef {
            body: Some(json!({"custom": true})),
            ..OpDef::default()
        };
        let parts = build(Operation::McpApprove, &def, &vars(), None).unwrap();
        assert!(!has_header(&parts.headers, "mcp-method"));
        assert!(!has_header(&parts.headers, "mcp-name"));
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
        assert!(build(Operation::UsePlain, &def, &vars(), None).is_err());
    }

    fn approval_def() -> OpDef {
        let op = |n: u64| json!({"tool": "append_rows", "table": "orders", "rows": format!("[{{\"id\":{n}}}]")});
        let args = |n: u64| json!({"table": "orders", "rows": [{"id": n}]});
        OpDef {
            tool: Some("append_rows".into()),
            action: Some("data.append".into()),
            resource_type: Some("table".into()),
            resource_id: Some("orders".into()),
            ancestors: Some(json!([
                {"type": "service", "id": "datastore"},
                {"type": "host", "id": "prod"},
                {"type": "database", "id": "test2"}
            ])),
            arguments: Some(args(1)),
            approval: Some(crate::profile::ApprovalDef {
                op: op(1),
                effect_2: crate::profile::ApprovalVariant {
                    arguments: args(2),
                    op: op(2),
                },
                effect_3: crate::profile::ApprovalVariant {
                    arguments: args(3),
                    op: op(3),
                },
            }),
            ..OpDef::default()
        }
    }

    #[test]
    fn the_effects_of_the_three_calls_follow_protocol_17_3_and_differ() {
        let def = approval_def();
        let [base, second, third] = effects(&def, "datastore").unwrap();
        let direct = effect_hash(
            "datastore",
            "data.append",
            "host:prod/database:test2/table:orders",
            &def.approval.as_ref().unwrap().op,
        )
        .unwrap();
        assert_eq!(base, direct);
        assert!(base != second && second != third && base != third);
        assert!(effects(&def, "other").is_err());
        let vars = op_vars(Operation::McpCallApproval, &def, "datastore");
        assert_eq!(vars.get("effect"), Some(&json!(base)));
        assert_eq!(vars.get("effect_2"), Some(&json!(second)));
        assert_eq!(vars.get("effect_3"), Some(&json!(third)));
        // The other operations give no effect.
        assert!(
            op_vars(Operation::McpCallPlain, &def, "datastore")
                .get("effect")
                .is_none()
        );
    }

    #[test]
    fn the_variants_of_the_approval_call_change_the_control_arguments() {
        let def = approval_def();
        let mut v = vars();
        v.set("tool", json!("append_rows"));
        let arguments = |variant: Option<Variant>| -> Value {
            let parts = build(Operation::McpCallApproval, &def, &v, variant).unwrap();
            let body: Value = serde_json::from_slice(&parts.body.unwrap()).unwrap();
            body["params"]["arguments"].clone()
        };
        let base = arguments(None);
        assert_eq!(base["lease_s"], 900);
        assert_eq!(base["rows"], json!([{"id": 1}]));
        assert!(base.get("approval_ref").is_none() && base.get("wait_s").is_none());
        assert_eq!(
            arguments(Some(Variant::Effect2))["rows"],
            json!([{"id": 2}])
        );
        assert_eq!(
            arguments(Some(Variant::Effect3))["rows"],
            json!([{"id": 3}])
        );
        let by_ref = arguments(Some(Variant::ApprovalRef));
        assert_eq!(by_ref["approval_ref"], APPROVAL_REF);
        assert!(by_ref.get("lease_s").is_none());
        let wait = arguments(Some(Variant::Wait));
        assert_eq!(
            (wait["lease_s"].clone(), wait["wait_s"].clone()),
            (json!(900), json!(1))
        );
        assert_eq!(wait["rows"], base["rows"]);
    }
}
