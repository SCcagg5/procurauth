//! The AuthZEN 1.0 messages that the tools need, with the members that the
//! protocol adds (`context.usage`, `context.limits`, `context.match`,
//! `context.reason`, `context.retry_after`).
//!
//! The envelope follows AuthZEN 1.0: a receiver ignores a member that it
//! does not know. The members of this protocol are strict: a bad value is a
//! finding with the number of the paragraph that gives the rule.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::action_document::{ActionDocument, NodeError};
use crate::finding::{Finding, JsonPath, Report, show, type_word};
use crate::names::{IdError, SERVICE, is_type_or_limit_name, validate_id};
use crate::path::{NodePath, NodeRef, PathError};
use crate::read::{Obj, Unknown};

/// The subject type of a person and of a key (3.3).
pub const SUBJECT_TYPE: &str = "user";

/// The subject of a question (3.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Subject {
    /// The type. A PEP sends `user` (3.3).
    pub subject_type: String,
    /// The id. A PEP sends the `sub` of the identity token, as opaque text (3.3).
    pub id: String,
    /// Other properties. This protocol sends none (9.6).
    pub properties: Option<Map<String, Value>>,
}

impl Subject {
    /// The subject that a PEP sends for the `sub` of an identity token (3.3).
    pub fn user(sub: impl Into<String>) -> Self {
        Self {
            subject_type: SUBJECT_TYPE.to_owned(),
            id: sub.into(),
            properties: None,
        }
    }
}

/// The action of a question.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRef {
    /// The name of the action.
    pub name: String,
    /// Other properties.
    pub properties: Option<Map<String, Value>>,
}

/// The resource of a question (4.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Resource {
    /// The type of the node.
    pub resource_type: String,
    /// The id of the node. Nobody encodes it (4.1).
    pub id: String,
    /// The properties. The member `ancestors` holds the chain (4.1).
    pub properties: Option<Map<String, Value>>,
}

/// Why a chain is not valid (4.1, 11.1).
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ChainError {
    /// `ancestors` is not an array.
    #[error("`resource.properties.ancestors` is not an array")]
    AncestorsNotArray,
    /// An item of `ancestors` is not an object with a string `type` and a string `id`.
    #[error(
        "item {index} of `resource.properties.ancestors` is not an object with `type` and `id`"
    )]
    AncestorNotObject {
        /// The position of the item, from 0.
        index: usize,
    },
    /// A resource below the service has no chain.
    #[error("a resource below the service has no chain in `resource.properties.ancestors`")]
    ChainMissing,
    /// The first object of the chain is not the service.
    #[error("the first object of the chain does not have the type `service`")]
    FirstNotService,
    /// The resource is the service, and it has a chain.
    #[error("the service has no chain, and the request gives one")]
    ServiceHasAncestors,
    /// An id breaks the rules of 4.1.
    #[error("the id of node {index}: {source}")]
    BadId {
        /// The position of the node, from 0 for the service.
        index: usize,
        /// The cause.
        source: IdError,
    },
    /// The depth is more than 4.
    #[error("the depth is {0}, and the maximum is 4")]
    TooDeep(usize),
    /// The nodes do not follow the tree of types of the document.
    #[error("{0}")]
    Tree(#[from] NodeError),
}

impl ChainError {
    /// The reason that a PDP gives for this error (11.1). A bad id has no
    /// reason in 11.1, so the answer has none.
    pub fn reason(&self) -> Option<Reason> {
        match self {
            Self::AncestorsNotArray | Self::AncestorNotObject { .. } => {
                Some(Reason::InvalidRequest)
            }
            Self::BadId { .. } => None,
            _ => Some(Reason::InvalidResource),
        }
    }
}

impl Resource {
    /// The resource for a node. The chain holds the nodes above it (4.1).
    /// The service has no `properties` (4.1).
    pub fn from_path(path: &NodePath) -> Self {
        let nodes = path.nodes();
        let (node, above) = nodes.split_last().map_or_else(
            || (NodeRef::service(""), &nodes[..0]),
            |(last, above)| (last.clone(), above),
        );
        let properties = (!above.is_empty()).then(|| {
            let mut properties = Map::new();
            properties.insert(
                "ancestors".to_owned(),
                json!(
                    above
                        .iter()
                        .map(|n| json!({"type": n.node_type, "id": n.id}))
                        .collect::<Vec<_>>()
                ),
            );
            properties
        });
        Self {
            resource_type: node.node_type,
            id: node.id,
            properties,
        }
    }

    /// The chain of `resource.properties.ancestors`. An absent member is an empty chain.
    ///
    /// # Errors
    /// Returns an error when the member is not an array of objects with `type` and `id`.
    pub fn ancestors(&self) -> Result<Vec<NodeRef>, ChainError> {
        let Some(value) = self.properties.as_ref().and_then(|p| p.get("ancestors")) else {
            return Ok(Vec::new());
        };
        let Some(items) = value.as_array() else {
            return Err(ChainError::AncestorsNotArray);
        };
        items
            .iter()
            .enumerate()
            .map(|(index, item)| {
                let node_type = item.get("type").and_then(Value::as_str);
                let id = item.get("id").and_then(Value::as_str);
                match (node_type, id) {
                    (Some(t), Some(i)) => Ok(NodeRef::new(t, i)),
                    _ => Err(ChainError::AncestorNotObject { index }),
                }
            })
            .collect()
    }

    /// The path of the node: the chain, then the resource.
    ///
    /// # Errors
    /// Returns an error when the chain does not start at the service, when an
    /// id breaks 4.1, or when the depth is more than 4. The function does not
    /// check the types against a document: use [`check_resource`] for that.
    pub fn node_path(&self) -> Result<NodePath, ChainError> {
        let mut nodes = self.ancestors()?;
        if self.resource_type == SERVICE {
            if !nodes.is_empty() {
                return Err(ChainError::ServiceHasAncestors);
            }
        } else if nodes.is_empty() {
            return Err(ChainError::ChainMissing);
        }
        nodes.push(NodeRef::new(&self.resource_type, &self.id));
        if nodes[0].node_type != SERVICE {
            return Err(ChainError::FirstNotService);
        }
        for (index, node) in nodes.iter().enumerate() {
            validate_id(&node.id).map_err(|source| ChainError::BadId { index, source })?;
        }
        NodePath::from_nodes(nodes).map_err(|error| match error {
            PathError::TooDeep(depth) => ChainError::TooDeep(depth),
            _ => ChainError::FirstNotService,
        })
    }
}

/// Check the chain and the type of a resource against the last good action
/// document of the service (4.1, 11.1). Return the path of the node.
///
/// # Errors
/// Returns the first rule that the resource breaks. [`ChainError::reason`]
/// gives the reason of the answer.
pub fn check_resource(
    document: &ActionDocument,
    resource: &Resource,
) -> Result<NodePath, ChainError> {
    let path = resource.node_path()?;
    document.check_path(&path)?;
    Ok(path)
}

/// One question: an Access Evaluation request (AuthZEN 1.0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationRequest {
    /// The subject.
    pub subject: Subject,
    /// The action.
    pub action: ActionRef,
    /// The resource.
    pub resource: Resource,
    /// The context. It can hold `usage` and `match`.
    pub context: Option<Map<String, Value>>,
}

impl EvaluationRequest {
    /// A question for the `sub` of a token, an action and a node, with no context.
    pub fn new(sub: &str, action: &str, node: &NodePath) -> Self {
        Self {
            subject: Subject::user(sub),
            action: ActionRef {
                name: action.to_owned(),
                properties: None,
            },
            resource: Resource::from_path(node),
            context: None,
        }
    }

    /// Add `context.usage` with one unit (6.4).
    #[must_use]
    pub fn with_usage(mut self) -> Self {
        self.context
            .get_or_insert_with(Map::new)
            .insert("usage".to_owned(), json!({"units": 1}));
        self
    }

    /// Add `context.match` (4.4).
    #[must_use]
    pub fn with_match(mut self, mode: MatchMode) -> Self {
        self.context
            .get_or_insert_with(Map::new)
            .insert("match".to_owned(), json!(mode.as_str()));
        self
    }

    /// The question as JSON.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "subject".into(),
            part_to_value(
                &self.subject.subject_type,
                &self.subject.id,
                self.subject.properties.as_ref(),
                "type",
                "id",
            ),
        );
        let mut action = Map::new();
        action.insert("name".into(), json!(self.action.name));
        if let Some(p) = &self.action.properties {
            action.insert("properties".into(), Value::Object(p.clone()));
        }
        m.insert("action".into(), Value::Object(action));
        m.insert(
            "resource".into(),
            part_to_value(
                &self.resource.resource_type,
                &self.resource.id,
                self.resource.properties.as_ref(),
                "type",
                "id",
            ),
        );
        if let Some(context) = &self.context {
            m.insert("context".into(), Value::Object(context.clone()));
        }
        Value::Object(m)
    }

    /// Read one question.
    ///
    /// # Errors
    /// Returns a finding for each member that AuthZEN 1.0 requires and that is absent or has a wrong type.
    pub fn from_value(value: &Value) -> Result<Self, Vec<Finding>> {
        let mut report = Report::new();
        let parsed = read_request(value, &JsonPath::root(), &Defaults::default(), &mut report);
        match parsed {
            Some(request) if !report.has_errors() => Ok(request),
            _ => Err(report.into_findings()),
        }
    }

    /// The typed members of the context that this protocol defines.
    ///
    /// # Errors
    /// Returns a finding for each bad member (6.4, 6.11, 4.4).
    pub fn request_context(&self) -> Result<RequestContext, Vec<Finding>> {
        RequestContext::from_context(self.context.as_ref())
    }
}

fn part_to_value(
    first: &str,
    second: &str,
    properties: Option<&Map<String, Value>>,
    k1: &str,
    k2: &str,
) -> Value {
    let mut m = Map::new();
    m.insert(k1.into(), json!(first));
    m.insert(k2.into(), json!(second));
    if let Some(p) = properties {
        m.insert("properties".into(), Value::Object(p.clone()));
    }
    Value::Object(m)
}

/// The values that the top level of an Access Evaluations request gives to each item.
#[derive(Default)]
struct Defaults<'a> {
    subject: Option<&'a Value>,
    action: Option<&'a Value>,
    resource: Option<&'a Value>,
    context: Option<&'a Value>,
}

fn read_request(
    value: &Value,
    path: &JsonPath,
    defaults: &Defaults<'_>,
    report: &mut Report,
) -> Option<EvaluationRequest> {
    let mut obj = Obj::new(value, path, "authzen", Unknown::Ignore, report)?;
    let subject = obj.optional("subject").or(defaults.subject);
    let action = obj.optional("action").or(defaults.action);
    let resource = obj.optional("resource").or(defaults.resource);
    let context = obj.optional("context").or(defaults.context);
    let start = report.error_count();
    let subject = require_part(subject, "subject", path, report)
        .and_then(|v| read_typed(v, &path.key("subject"), report));
    let action = require_part(action, "action", path, report)
        .and_then(|v| read_action(v, &path.key("action"), report));
    let resource = require_part(resource, "resource", path, report)
        .and_then(|v| read_typed(v, &path.key("resource"), report));
    let context = context.and_then(|v| match v {
        Value::Object(map) => Some(map.clone()),
        other => {
            report.error(
                &path.key("context"),
                "authzen",
                "wrong_type",
                format!(
                    "Expected an object, found {}: {}.",
                    type_word(other),
                    show(other)
                ),
            );
            None
        }
    });
    if report.error_count() != start {
        return None;
    }
    let (subject_type, subject_id, subject_properties) = subject?;
    let (resource_type, resource_id, resource_properties) = resource?;
    Some(EvaluationRequest {
        subject: Subject {
            subject_type,
            id: subject_id,
            properties: subject_properties,
        },
        action: action?,
        resource: Resource {
            resource_type,
            id: resource_id,
            properties: resource_properties,
        },
        context,
    })
}

fn require_part<'a>(
    value: Option<&'a Value>,
    key: &str,
    path: &JsonPath,
    report: &mut Report,
) -> Option<&'a Value> {
    if value.is_none() {
        report.error(
            path,
            "authzen",
            "missing_member",
            format!("Member `{key}` is absent, and the request gives no default."),
        );
    }
    value
}

type TypedPart = (String, String, Option<Map<String, Value>>);

fn read_typed(value: &Value, path: &JsonPath, report: &mut Report) -> Option<TypedPart> {
    let mut obj = Obj::new(value, path, "authzen", Unknown::Ignore, report)?;
    let node_type = obj.string("type", report);
    let id = obj.string("id", report);
    let properties = read_properties(&mut obj, path, report);
    Some((node_type?.to_owned(), id?.to_owned(), properties))
}

fn read_action(value: &Value, path: &JsonPath, report: &mut Report) -> Option<ActionRef> {
    let mut obj = Obj::new(value, path, "authzen", Unknown::Ignore, report)?;
    let name = obj.string("name", report);
    let properties = read_properties(&mut obj, path, report);
    Some(ActionRef {
        name: name?.to_owned(),
        properties,
    })
}

fn read_properties(
    obj: &mut Obj<'_>,
    path: &JsonPath,
    report: &mut Report,
) -> Option<Map<String, Value>> {
    match obj.optional("properties")? {
        Value::Object(map) => Some(map.clone()),
        other => {
            report.error(
                &path.key("properties"),
                "authzen",
                "wrong_type",
                format!(
                    "Expected an object, found {}: {}.",
                    type_word(other),
                    show(other)
                ),
            );
            None
        }
    }
}

/// An Access Evaluations request (AuthZEN 1.0): the items, with the default
/// values of the top level applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvaluationsRequest {
    /// The questions. A request without `evaluations`, or with an empty array,
    /// is one question, as AuthZEN 1.0 says.
    pub items: Vec<EvaluationRequest>,
    /// True when the request has at least one item in `evaluations`.
    pub has_items: bool,
    /// The member `options`, when the request has it.
    pub options: Option<Map<String, Value>>,
}

impl EvaluationsRequest {
    /// Read a request of the Access Evaluations API.
    ///
    /// # Errors
    /// Returns a finding for each part that the request or an item lacks.
    pub fn from_value(value: &Value) -> Result<Self, Vec<Finding>> {
        let mut report = Report::new();
        let root = JsonPath::root();
        let Some(mut obj) = Obj::new(value, &root, "authzen", Unknown::Ignore, &mut report) else {
            return Err(report.into_findings());
        };
        let defaults = Defaults {
            subject: obj.optional("subject"),
            action: obj.optional("action"),
            resource: obj.optional("resource"),
            context: obj.optional("context"),
        };
        let evaluations = obj.array_opt("evaluations", &mut report);
        let options = match obj.optional("options") {
            Some(Value::Object(map)) => Some(map.clone()),
            Some(other) => {
                report.error(
                    &root.key("options"),
                    "authzen",
                    "wrong_type",
                    format!(
                        "Expected an object, found {}: {}.",
                        type_word(other),
                        show(other)
                    ),
                );
                None
            }
            None => None,
        };
        let mut items = Vec::new();
        let has_items = evaluations.is_some_and(|e| !e.is_empty());
        match evaluations {
            Some(list) if !list.is_empty() => {
                for (index, item) in list.iter().enumerate() {
                    let path = root.key("evaluations").index(index);
                    items.extend(read_request(item, &path, &defaults, &mut report));
                }
            }
            _ => {
                let empty = Value::Object(Map::new());
                items.extend(read_request(&empty, &root, &defaults, &mut report));
            }
        }
        if report.has_errors() {
            return Err(report.into_findings());
        }
        Ok(Self {
            items,
            has_items,
            options,
        })
    }
}

/// Check where `context.usage` sits in a request body (6.11). Only a request
/// with one evaluation can carry it. In a request with items, a `usage` at the
/// top level or in an item is an error. The PDP then answers HTTP 400.
pub fn check_usage_placement(request: &Value) -> Vec<Finding> {
    let mut report = Report::new();
    let root = JsonPath::root();
    let has_items = request
        .get("evaluations")
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty());
    if !has_items {
        return Vec::new();
    }
    let message = "A request with items must not have `context.usage` (6.11).";
    if request
        .get("context")
        .and_then(|c| c.get("usage"))
        .is_some()
    {
        report.error(
            &root.key("context").key("usage"),
            "6.11",
            "usage_in_items_request",
            message,
        );
    }
    if let Some(items) = request.get("evaluations").and_then(Value::as_array) {
        for (index, item) in items.iter().enumerate() {
            if item.get("context").and_then(|c| c.get("usage")).is_some() {
                report.error(
                    &root
                        .key("evaluations")
                        .index(index)
                        .key("context")
                        .key("usage"),
                    "6.11",
                    "usage_in_items_request",
                    message,
                );
            }
        }
    }
    report.into_findings()
}

/// The value of `context.match` (4.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum MatchMode {
    /// The answer is a decision about the node. This is the default.
    #[default]
    Node,
    /// The answer tells if a grant applies on the node, above it or below it.
    Subtree,
}

impl MatchMode {
    /// The word of the protocol.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Node => "node",
            Self::Subtree => "subtree",
        }
    }
}

/// The members of the context of a question that this protocol defines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RequestContext {
    /// The value of `context.usage.units`, when the question has `usage` (6.4).
    pub usage_units: Option<u64>,
    /// The value of `context.match` (4.4).
    pub match_mode: MatchMode,
}

impl RequestContext {
    /// Read the members of the context. Other members are ignored (AuthZEN 1.0).
    ///
    /// # Errors
    /// Returns a finding for a bad `usage` (6.4), a bad `match` (4.4), or a
    /// `usage` with `match` equal to `subtree` (6.11).
    pub fn from_context(context: Option<&Map<String, Value>>) -> Result<Self, Vec<Finding>> {
        let mut out = Self::default();
        let Some(context) = context else {
            return Ok(out);
        };
        let mut report = Report::new();
        let path = JsonPath::root().key("context");
        if let Some(usage) = context.get("usage") {
            let usage_path = path.key("usage");
            match usage.as_object() {
                None => report.error(
                    &usage_path,
                    "6.4",
                    "bad_usage",
                    format!(
                        "Expected an object with the member `units`, found {}.",
                        show(usage)
                    ),
                ),
                Some(map) => match map.get("units") {
                    Some(units) if units.as_u64() == Some(1) => out.usage_units = Some(1),
                    Some(units) => report.error(
                        &usage_path.key("units"),
                        "6.4",
                        "bad_units",
                        format!("Member `units`: expected 1, found {}.", show(units)),
                    ),
                    None => report.error(
                        &usage_path,
                        "6.4",
                        "missing_member",
                        "Member `units` is absent.",
                    ),
                },
            }
        }
        if let Some(mode) = context.get("match") {
            match mode.as_str() {
                Some("node") => out.match_mode = MatchMode::Node,
                Some("subtree") => out.match_mode = MatchMode::Subtree,
                _ => report.error(
                    &path.key("match"),
                    "4.4",
                    "bad_match",
                    format!(
                        "Member `match`: expected `node` or `subtree`, found {}.",
                        show(mode)
                    ),
                ),
            }
        }
        if context.contains_key("usage") && out.match_mode == MatchMode::Subtree {
            report.error(
                &path,
                "6.11",
                "usage_with_subtree",
                "A request with `context.usage` must not have `context.match` equal to `subtree`.",
            );
        }
        if report.has_errors() {
            Err(report.into_findings())
        } else {
            Ok(out)
        }
    }
}

/// The reason of a `false` answer (11.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Reason {
    /// The PDP does not know the subject.
    UnknownSubject,
    /// The resource or its chain is not valid.
    InvalidResource,
    /// A member of this protocol is bad, in an item of an Access Evaluations answer.
    InvalidRequest,
    /// A counter of the use has too few units left.
    BudgetExceeded,
    /// Another text. A PEP maps it as a `false` answer with no reason (10.3).
    Other(String),
}

impl Reason {
    /// The text of the protocol.
    pub fn as_str(&self) -> &str {
        match self {
            Self::UnknownSubject => "unknown_subject",
            Self::InvalidResource => "invalid_resource",
            Self::InvalidRequest => "invalid_request",
            Self::BudgetExceeded => "budget_exceeded",
            Self::Other(text) => text,
        }
    }

    /// Read the text of a reason.
    pub fn parse(text: &str) -> Self {
        match text {
            "unknown_subject" => Self::UnknownSubject,
            "invalid_resource" => Self::InvalidResource,
            "invalid_request" => Self::InvalidRequest,
            "budget_exceeded" => Self::BudgetExceeded,
            other => Self::Other(other.to_owned()),
        }
    }
}

/// The members of the context of an answer that this protocol defines.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AnswerContext {
    /// The ceilings (7.3).
    pub limits: BTreeMap<String, u64>,
    /// `context.usage.units`: the units that the PDP took, 0 or 1 (6.12).
    pub usage_units: Option<u64>,
    /// The reason of a `false` answer (11.1).
    pub reason: Option<Reason>,
    /// The seconds to wait, with `budget_exceeded` (11.1).
    pub retry_after: Option<u64>,
}

/// One answer: an Access Evaluation response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    /// The decision.
    pub decision: bool,
    /// The members of the context that this protocol defines.
    pub context: AnswerContext,
}

impl Decision {
    /// A `true` answer with ceilings and the units that the PDP took.
    pub fn allow(limits: BTreeMap<String, u64>, usage_units: Option<u64>) -> Self {
        Self {
            decision: true,
            context: AnswerContext {
                limits,
                usage_units,
                ..AnswerContext::default()
            },
        }
    }

    /// A `false` answer with an optional reason.
    pub fn deny(reason: Option<Reason>) -> Self {
        Self {
            decision: false,
            context: AnswerContext {
                reason,
                ..AnswerContext::default()
            },
        }
    }

    /// A `false` answer with `budget_exceeded` and `retry_after` (11.1).
    pub fn budget_exceeded(retry_after: u64) -> Self {
        Self {
            decision: false,
            context: AnswerContext {
                reason: Some(Reason::BudgetExceeded),
                retry_after: Some(retry_after),
                ..AnswerContext::default()
            },
        }
    }

    /// The decision that a PEP applies. A `true` answer to a question with
    /// `context.usage` that has no `context.usage.units` counts as `false` (6.12).
    pub fn allows(&self, asked_usage: bool) -> bool {
        self.decision && (!asked_usage || self.context.usage_units.is_some())
    }

    /// The answer as JSON.
    pub fn to_value(&self) -> Value {
        let mut context = Map::new();
        if !self.context.limits.is_empty() {
            context.insert("limits".into(), json!(self.context.limits));
        }
        if let Some(units) = self.context.usage_units {
            context.insert("usage".into(), json!({"units": units}));
        }
        if let Some(reason) = &self.context.reason {
            context.insert("reason".into(), json!(reason.as_str()));
        }
        if let Some(seconds) = self.context.retry_after {
            context.insert("retry_after".into(), json!(seconds));
        }
        let mut out = Map::new();
        out.insert("decision".into(), json!(self.decision));
        if !context.is_empty() {
            out.insert("context".into(), Value::Object(context));
        }
        Value::Object(out)
    }

    /// Read one answer. A PEP maps an error to HTTP 503 (10.3).
    ///
    /// # Errors
    /// Returns a finding for each member that is not valid.
    pub fn from_value(value: &Value) -> Result<Self, Vec<Finding>> {
        let mut report = Report::new();
        let decision = read_decision(value, &JsonPath::root(), &mut report);
        match decision {
            Some(decision) if !report.has_errors() => Ok(decision),
            _ => Err(report.into_findings()),
        }
    }
}

fn read_decision(value: &Value, path: &JsonPath, report: &mut Report) -> Option<Decision> {
    let mut obj = Obj::new(value, path, "authzen", Unknown::Ignore, report)?;
    let decision = obj.boolean("decision", report);
    let mut context = AnswerContext::default();
    if let Some(ctx_value) = obj.optional("context") {
        let ctx_path = path.key("context");
        if let Some(mut ctx) = Obj::new(ctx_value, &ctx_path, "authzen", Unknown::Ignore, report) {
            if let Some(limits) = ctx.optional("limits") {
                read_limits(limits, &ctx_path.key("limits"), &mut context, report);
            }
            if let Some(mut usage) = ctx.object_opt("usage", "6.12", Unknown::Ignore, report) {
                match usage.optional("units") {
                    Some(units) if matches!(units.as_u64(), Some(0 | 1)) => {
                        context.usage_units = units.as_u64()
                    }
                    Some(units) => report.error(
                        &usage.member_path("units"),
                        "6.12",
                        "bad_units",
                        format!("Member `units`: expected 0 or 1, found {}.", show(units)),
                    ),
                    None => report.error(
                        usage.path(),
                        "6.12",
                        "missing_member",
                        "Member `units` is absent.",
                    ),
                }
            }
            if let Some(reason) = ctx.string_opt("reason", report) {
                context.reason = Some(Reason::parse(reason));
            }
            if let Some(value) = ctx.optional("retry_after") {
                match value.as_u64() {
                    Some(seconds) if seconds >= 1 => context.retry_after = Some(seconds),
                    _ => report.error(
                        &ctx_path.key("retry_after"),
                        "11.1",
                        "bad_retry_after",
                        format!(
                            "Member `retry_after`: expected a whole number from 1, found {}.",
                            show(value)
                        ),
                    ),
                }
            }
            if context.reason == Some(Reason::BudgetExceeded) && context.retry_after.is_none() {
                report.error(
                    &ctx_path,
                    "11.1",
                    "missing_retry_after",
                    "The reason `budget_exceeded` needs the member `retry_after`.",
                );
            }
        }
    }
    Some(Decision {
        decision: decision?,
        context,
    })
}

fn read_limits(value: &Value, path: &JsonPath, context: &mut AnswerContext, report: &mut Report) {
    let Some(map) = value.as_object() else {
        report.error(
            path,
            "7.3",
            "wrong_type",
            format!(
                "Expected an object, found {}: {}.",
                type_word(value),
                show(value)
            ),
        );
        return;
    };
    for (name, item) in map {
        if !is_type_or_limit_name(name) {
            report.error(
                &path.key(name),
                "5.2",
                "bad_limit_name",
                format!("Limit name {}: expected 1 to 32 characters, a to z first, then a to z, 0 to 9 or underscore.", show(&json!(name))),
            );
            continue;
        }
        match item.as_u64() {
            Some(number) => {
                context.limits.insert(name.clone(), number);
            }
            None => report.error(
                &path.key(name),
                "7.3",
                "bad_ceiling",
                format!(
                    "Ceiling `{name}`: expected a whole number of 0 or more, found {}. A budget value never appears in an answer.",
                    show(item)
                ),
            ),
        }
    }
}

/// Read an Access Evaluations answer: the list of the answers, in the order of the request.
///
/// # Errors
/// Returns a finding for each bad answer.
pub fn read_evaluations_answer(value: &Value) -> Result<Vec<Decision>, Vec<Finding>> {
    let mut report = Report::new();
    let root = JsonPath::root();
    let Some(mut obj) = Obj::new(value, &root, "authzen", Unknown::Ignore, &mut report) else {
        return Err(report.into_findings());
    };
    let items = obj.array("evaluations", &mut report);
    let mut out = Vec::new();
    for (index, item) in items.unwrap_or_default().iter().enumerate() {
        out.extend(read_decision(
            item,
            &root.key("evaluations").index(index),
            &mut report,
        ));
    }
    if report.has_errors() {
        Err(report.into_findings())
    } else {
        Ok(out)
    }
}

/// The answers as the JSON of an Access Evaluations response.
pub fn evaluations_answer_to_value(decisions: &[Decision]) -> Value {
    json!({"evaluations": decisions.iter().map(Decision::to_value).collect::<Vec<_>>()})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section_13_document() -> ActionDocument {
        ActionDocument::from_value(&json!({
            "server": "datastore",
            "resource_types": [
                {"name": "host", "parent": "service", "description": "H."},
                {"name": "database", "parent": "host", "description": "D."},
                {"name": "table", "parent": "database", "description": "T."}
            ],
            "actions": [], "limits": []
        }))
        .unwrap()
    }

    fn path(text: &str) -> NodePath {
        NodePath::parse(text).unwrap()
    }

    fn resource(value: Value) -> Resource {
        let request = json!({"subject": {"type": "user", "id": "a"}, "action": {"name": "x"}, "resource": value});
        EvaluationRequest::from_value(&request).unwrap().resource
    }

    #[test]
    fn p_3_3_the_subject_has_the_type_user_and_the_sub_as_id() {
        let subject = Subject::user("key:9b1c04e2aa71f0c3");
        assert_eq!(subject.subject_type, "user");
        assert_eq!(subject.id, "key:9b1c04e2aa71f0c3");
    }

    #[test]
    fn p_13_the_question_of_alice_is_built_as_the_protocol_shows() {
        let node = path("service:datastore/host:prod/database:test2/table:orders");
        let request = EvaluationRequest::new("alice", "data.read", &node).with_usage();
        assert_eq!(
            request.to_value(),
            json!({
                "subject": {"type": "user", "id": "alice"},
                "action": {"name": "data.read"},
                "resource": {"type": "table", "id": "orders",
                    "properties": {"ancestors": [
                        {"type": "service", "id": "datastore"},
                        {"type": "host", "id": "prod"},
                        {"type": "database", "id": "test2"}]}},
                "context": {"usage": {"units": 1}}
            })
        );
        assert_eq!(
            EvaluationRequest::from_value(&request.to_value()).unwrap(),
            request
        );
    }

    #[test]
    fn p_4_1_the_service_has_no_ancestors() {
        let resource = Resource::from_path(&NodePath::service("datastore"));
        assert_eq!(resource.resource_type, "service");
        assert!(resource.properties.is_none());
        assert_eq!(
            resource.node_path().unwrap(),
            NodePath::service("datastore")
        );
    }

    #[test]
    fn p_4_1_the_service_can_have_an_empty_array() {
        let r = resource(
            json!({"type": "service", "id": "datastore", "properties": {"ancestors": []}}),
        );
        assert_eq!(
            check_resource(&section_13_document(), &r).unwrap(),
            NodePath::service("datastore")
        );
    }

    #[test]
    fn p_4_1_the_chain_goes_from_the_service_to_the_parent() {
        let doc = section_13_document();
        let r = resource(
            json!({"type": "table", "id": "orders", "properties": {"ancestors": [
            {"type": "service", "id": "datastore"}, {"type": "host", "id": "prod"}, {"type": "database", "id": "test2"}]}}),
        );
        let node = check_resource(&doc, &r).unwrap();
        assert_eq!(
            node.to_string(),
            "service:datastore/host:prod/database:test2/table:orders"
        );
    }

    #[test]
    fn p_4_1_the_chain_must_not_hold_the_resource() {
        let doc = section_13_document();
        let r = resource(
            json!({"type": "host", "id": "prod", "properties": {"ancestors": [
            {"type": "service", "id": "datastore"}, {"type": "host", "id": "prod"}]}}),
        );
        assert!(matches!(
            check_resource(&doc, &r),
            Err(ChainError::Tree(NodeError::WrongParent { .. }))
        ));
    }

    #[test]
    fn p_11_1_a_resource_below_the_service_with_no_ancestors_is_invalid() {
        let doc = section_13_document();
        let r = resource(json!({"type": "host", "id": "prod"}));
        let error = check_resource(&doc, &r).unwrap_err();
        assert_eq!(error, ChainError::ChainMissing);
        assert_eq!(error.reason(), Some(Reason::InvalidResource));
        let r = resource(json!({"type": "host", "id": "prod", "properties": {"ancestors": []}}));
        assert_eq!(
            check_resource(&doc, &r).unwrap_err(),
            ChainError::ChainMissing
        );
    }

    #[test]
    fn p_11_1_the_first_object_must_be_the_service_of_the_pep() {
        let doc = section_13_document();
        let r = resource(
            json!({"type": "database", "id": "t", "properties": {"ancestors": [
            {"type": "service", "id": "other"}, {"type": "host", "id": "prod"}]}}),
        );
        let error = check_resource(&doc, &r).unwrap_err();
        assert!(matches!(
            error,
            ChainError::Tree(NodeError::WrongService { .. })
        ));
        assert_eq!(error.reason(), Some(Reason::InvalidResource));
        let r = resource(json!({"type": "service", "id": "other"}));
        assert!(matches!(
            check_resource(&doc, &r),
            Err(ChainError::Tree(NodeError::WrongService { .. }))
        ));
        let r = resource(
            json!({"type": "database", "id": "t", "properties": {"ancestors": [
            {"type": "host", "id": "prod"}]}}),
        );
        assert_eq!(
            check_resource(&doc, &r).unwrap_err(),
            ChainError::FirstNotService
        );
    }

    #[test]
    fn p_11_1_the_types_must_follow_the_parents_of_the_document() {
        let doc = section_13_document();
        let r = resource(
            json!({"type": "table", "id": "t", "properties": {"ancestors": [
            {"type": "service", "id": "datastore"}, {"type": "database", "id": "d"}]}}),
        );
        assert!(matches!(
            check_resource(&doc, &r),
            Err(ChainError::Tree(NodeError::WrongParent { .. }))
        ));
        let r = resource(
            json!({"type": "ghost", "id": "t", "properties": {"ancestors": [
            {"type": "service", "id": "datastore"}]}}),
        );
        let error = check_resource(&doc, &r).unwrap_err();
        assert!(matches!(
            error,
            ChainError::Tree(NodeError::UnknownType { index: 1, .. })
        ));
        assert_eq!(error.reason(), Some(Reason::InvalidResource));
    }

    #[test]
    fn p_11_1_a_depth_above_four_is_invalid() {
        let doc = section_13_document();
        let ancestors: Vec<Value> = std::iter::once(json!({"type": "service", "id": "datastore"}))
            .chain((0..4).map(|i| json!({"type": "host", "id": format!("h{i}")})))
            .collect();
        let r =
            resource(json!({"type": "table", "id": "t", "properties": {"ancestors": ancestors}}));
        let error = check_resource(&doc, &r).unwrap_err();
        assert_eq!(error, ChainError::TooDeep(5));
        assert_eq!(error.reason(), Some(Reason::InvalidResource));
    }

    #[test]
    fn p_11_1_ancestors_that_are_not_an_array_of_objects_is_invalid_request() {
        let doc = section_13_document();
        for bad in [json!("x"), json!({"a": 1}), json!(5)] {
            let r = resource(json!({"type": "host", "id": "p", "properties": {"ancestors": bad}}));
            let error = check_resource(&doc, &r).unwrap_err();
            assert_eq!(error, ChainError::AncestorsNotArray);
            assert_eq!(error.reason(), Some(Reason::InvalidRequest));
        }
        for bad in [
            json!([5]),
            json!([{"type": "service"}]),
            json!([{"type": 1, "id": "a"}]),
        ] {
            let r = resource(json!({"type": "host", "id": "p", "properties": {"ancestors": bad}}));
            let error = check_resource(&doc, &r).unwrap_err();
            assert_eq!(error, ChainError::AncestorNotObject { index: 0 });
            assert_eq!(error.reason(), Some(Reason::InvalidRequest));
        }
    }

    #[test]
    fn p_4_1_an_id_is_exact_text_of_1_to_256_bytes() {
        let doc = section_13_document();
        let long = "a".repeat(257);
        let r = resource(
            json!({"type": "host", "id": long, "properties": {"ancestors": [{"type": "service", "id": "datastore"}]}}),
        );
        let error = check_resource(&doc, &r).unwrap_err();
        assert!(matches!(error, ChainError::BadId { index: 1, .. }));
        assert_eq!(error.reason(), None);
        let r = resource(
            json!({"type": "host", "id": "a/b c%2F", "properties": {"ancestors": [{"type": "service", "id": "datastore"}]}}),
        );
        assert!(check_resource(&doc, &r).is_ok());
    }

    #[test]
    fn p_4_4_context_match() {
        let ctx = |v: Value| RequestContext::from_context(v.as_object());
        assert_eq!(ctx(json!({})).unwrap().match_mode, MatchMode::Node);
        assert_eq!(
            ctx(json!({"match": "node"})).unwrap().match_mode,
            MatchMode::Node
        );
        assert_eq!(
            ctx(json!({"match": "subtree"})).unwrap().match_mode,
            MatchMode::Subtree
        );
        for bad in [
            json!({"match": "tree"}),
            json!({"match": 1}),
            json!({"match": null}),
        ] {
            assert_eq!(ctx(bad).unwrap_err()[0].code, "bad_match");
        }
        assert_eq!(
            RequestContext::from_context(None).unwrap(),
            RequestContext::default()
        );
    }

    #[test]
    fn p_6_4_usage_units_is_one() {
        let ctx = |v: Value| RequestContext::from_context(v.as_object());
        assert_eq!(
            ctx(json!({"usage": {"units": 1}})).unwrap().usage_units,
            Some(1)
        );
        for bad in [
            json!({"usage": {"units": 2}}),
            json!({"usage": {"units": 0}}),
            json!({"usage": {"units": 1.0}}),
            json!({"usage": {"units": "1"}}),
            json!({"usage": {"units": -1}}),
        ] {
            assert_eq!(ctx(bad).unwrap_err()[0].code, "bad_units");
        }
        assert_eq!(
            ctx(json!({"usage": {}})).unwrap_err()[0].code,
            "missing_member"
        );
        assert_eq!(ctx(json!({"usage": 1})).unwrap_err()[0].code, "bad_usage");
    }

    #[test]
    fn p_6_4_a_later_member_of_usage_is_ignored() {
        let ctx = json!({"usage": {"units": 1, "remaining": 5}, "other": true});
        assert!(RequestContext::from_context(ctx.as_object()).is_ok());
    }

    #[test]
    fn p_6_11_usage_with_subtree_is_bad() {
        let ctx = json!({"usage": {"units": 1}, "match": "subtree"});
        let error = RequestContext::from_context(ctx.as_object()).unwrap_err();
        assert_eq!(error[0].code, "usage_with_subtree");
        assert_eq!(error[0].rule, "6.11");
    }

    #[test]
    fn p_6_11_usage_in_a_request_with_items_is_bad() {
        let request = json!({
            "subject": {"type": "user", "id": "a"},
            "context": {"usage": {"units": 1}},
            "evaluations": [{"action": {"name": "x"}, "resource": {"type": "service", "id": "s"}},
                            {"action": {"name": "y"}, "resource": {"type": "service", "id": "s"},
                             "context": {"usage": {"units": 1}}}]
        });
        let found = check_usage_placement(&request);
        let paths: Vec<_> = found.iter().map(|f| f.path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["$.context.usage", "$.evaluations[1].context.usage"]
        );
    }

    #[test]
    fn p_6_11_usage_in_a_request_without_items_is_good() {
        let single = json!({"subject": {"type": "user", "id": "a"}, "action": {"name": "x"},
            "resource": {"type": "service", "id": "s"}, "context": {"usage": {"units": 1}}});
        assert!(check_usage_placement(&single).is_empty());
        let mut empty_items = single.clone();
        empty_items["evaluations"] = json!([]);
        assert!(check_usage_placement(&empty_items).is_empty());
        let parsed = EvaluationsRequest::from_value(&empty_items).unwrap();
        assert!(!parsed.has_items);
        assert_eq!(parsed.items.len(), 1);
    }

    #[test]
    fn p_13_the_top_level_gives_the_default_values_of_the_items() {
        let request = json!({
            "subject": {"type": "user", "id": "key:9b1c04e2aa71f0c3"},
            "resource": {"type": "service", "id": "datastore"},
            "context": {"match": "subtree"},
            "evaluations": [{"action": {"name": "data.read"}}, {"action": {"name": "data.write"}}]
        });
        let parsed = EvaluationsRequest::from_value(&request).unwrap();
        assert!(parsed.has_items);
        assert_eq!(parsed.items.len(), 2);
        assert_eq!(parsed.items[1].action.name, "data.write");
        assert_eq!(parsed.items[1].subject.id, "key:9b1c04e2aa71f0c3");
        assert_eq!(
            parsed.items[0].request_context().unwrap().match_mode,
            MatchMode::Subtree
        );
    }

    #[test]
    fn p_13_an_item_overrides_the_default() {
        let request = json!({
            "subject": {"type": "user", "id": "a"}, "action": {"name": "x"},
            "resource": {"type": "service", "id": "s"}, "context": {"match": "subtree"},
            "evaluations": [{"context": {"match": "node"}}]
        });
        let parsed = EvaluationsRequest::from_value(&request).unwrap();
        assert_eq!(
            parsed.items[0].request_context().unwrap().match_mode,
            MatchMode::Node
        );
    }

    #[test]
    fn p_13_an_item_without_a_part_and_without_default_is_bad() {
        let request = json!({"subject": {"type": "user", "id": "a"},
            "evaluations": [{"action": {"name": "x"}}]});
        let findings = EvaluationsRequest::from_value(&request).unwrap_err();
        assert_eq!(findings[0].path.as_str(), "$.evaluations[0]");
        assert_eq!(findings[0].code, "missing_member");
    }

    #[test]
    fn p_13_a_member_of_the_wrong_type_is_bad() {
        let request = json!({"subject": {"type": "user", "id": 5}, "action": {"name": "x"},
            "resource": {"type": "service", "id": "s"}});
        let findings = EvaluationRequest::from_value(&request).unwrap_err();
        assert_eq!(findings[0].path.as_str(), "$.subject.id");
    }

    #[test]
    fn p_1_2_an_unknown_member_is_ignored() {
        let request = json!({"subject": {"type": "user", "id": "a", "x": 1}, "action": {"name": "x"},
            "resource": {"type": "service", "id": "s"}, "extra": true});
        assert!(EvaluationRequest::from_value(&request).is_ok());
    }

    #[test]
    fn p_7_3_the_answer_of_section_13() {
        let value = json!({"decision": true, "context": {"limits": {"max_rows": 100, "max_duration": 30}, "usage": {"units": 1}}});
        let decision = Decision::from_value(&value).unwrap();
        assert!(decision.allows(true));
        assert_eq!(decision.context.limits["max_rows"], 100);
        assert_eq!(decision.context.usage_units, Some(1));
        assert_eq!(decision.to_value(), value);
    }

    #[test]
    fn p_7_3_a_budget_value_never_appears_in_an_answer() {
        let value = json!({"decision": true, "context": {"limits": {"requests": [{"amount": 1, "window": "day"}]}}});
        assert_eq!(
            Decision::from_value(&value).unwrap_err()[0].code,
            "bad_ceiling"
        );
    }

    #[test]
    fn p_6_12_a_true_answer_without_units_counts_as_false_for_a_question_with_usage() {
        let decision = Decision::from_value(&json!({"decision": true})).unwrap();
        assert!(decision.allows(false));
        assert!(!decision.allows(true));
        let zero =
            Decision::from_value(&json!({"decision": true, "context": {"usage": {"units": 0}}}))
                .unwrap();
        assert!(zero.allows(true));
    }

    #[test]
    fn p_6_12_usage_in_an_answer_needs_units() {
        let value = json!({"decision": true, "context": {"usage": {}}});
        assert_eq!(
            Decision::from_value(&value).unwrap_err()[0].code,
            "missing_member"
        );
    }

    #[test]
    fn p_6_12_units_is_zero_or_one() {
        let value = json!({"decision": true, "context": {"usage": {"units": 2}}});
        assert_eq!(
            Decision::from_value(&value).unwrap_err()[0].code,
            "bad_units"
        );
    }

    #[test]
    fn p_11_1_budget_exceeded_has_retry_after() {
        let value =
            json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": 12}});
        let decision = Decision::from_value(&value).unwrap();
        assert!(!decision.allows(true));
        assert_eq!(decision.context.reason, Some(Reason::BudgetExceeded));
        assert_eq!(decision.context.retry_after, Some(12));
        assert_eq!(decision, Decision::budget_exceeded(12));
        assert_eq!(decision.to_value(), value);
    }

    #[test]
    fn p_11_1_budget_exceeded_without_retry_after_is_not_a_valid_answer() {
        let value = json!({"decision": false, "context": {"reason": "budget_exceeded"}});
        assert_eq!(
            Decision::from_value(&value).unwrap_err()[0].code,
            "missing_retry_after"
        );
        for bad in [json!(0), json!(-1), json!(1.5), json!("1")] {
            let value = json!({"decision": false, "context": {"reason": "budget_exceeded", "retry_after": bad}});
            assert_eq!(
                Decision::from_value(&value).unwrap_err()[0].code,
                "bad_retry_after"
            );
        }
    }

    #[test]
    fn p_11_1_the_reasons() {
        for (text, reason) in [
            ("unknown_subject", Reason::UnknownSubject),
            ("invalid_resource", Reason::InvalidResource),
            ("invalid_request", Reason::InvalidRequest),
            ("budget_exceeded", Reason::BudgetExceeded),
            ("other", Reason::Other("other".to_owned())),
        ] {
            assert_eq!(Reason::parse(text), reason);
            assert_eq!(reason.as_str(), text);
        }
    }

    #[test]
    fn p_11_2_a_false_answer_has_no_reason_by_default() {
        assert_eq!(Decision::deny(None).to_value(), json!({"decision": false}));
        assert_eq!(
            Decision::deny(Some(Reason::UnknownSubject)).to_value(),
            json!({"decision": false, "context": {"reason": "unknown_subject"}})
        );
    }

    #[test]
    fn p_10_3_an_answer_that_is_not_valid() {
        for bad in [
            json!({}),
            json!({"decision": "true"}),
            json!([]),
            json!({"decision": 1}),
            json!({"decision": true, "context": 5}),
        ] {
            assert!(Decision::from_value(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn p_13_the_answer_to_a_list_of_actions() {
        let answer = json!({"evaluations": [{"decision": true}, {"decision": false}]});
        let decisions = read_evaluations_answer(&answer).unwrap();
        assert_eq!(decisions.len(), 2);
        assert!(decisions[0].decision && !decisions[1].decision);
        assert_eq!(evaluations_answer_to_value(&decisions), answer);
        assert!(read_evaluations_answer(&json!({})).is_err());
    }

    #[test]
    fn p_4_5_the_service_resource_round_trip() {
        let request =
            EvaluationRequest::new("alice", "mcp.session", &NodePath::service("datastore"));
        assert_eq!(request.resource.resource_type, "service");
        assert_eq!(request.resource.id, "datastore");
    }
}
