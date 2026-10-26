//! The action document of a service (protocol section 5).
//!
//! [`analyze_value`] and [`analyze_str`] check a document and return every
//! finding with its JSON path. A good document becomes a typed
//! [`ActionDocument`]. The checks follow 5.2, 5.3, 5.3c, 6.1 and 7.1.

use std::collections::{BTreeMap, HashMap, HashSet};

use serde_json::{Map, Value, json};

use crate::finding::{Finding, JsonPath, Report, show};
use crate::json::parse_str;
use crate::names::{ACCESS_ACTION, MAX_TYPE_DEPTH, SERVICE, is_action_name, is_type_or_limit_name};
use crate::path::{NodePath, NodeRef, PathError, format_below_service};
use crate::read::{Obj, Unknown};

/// The size that a reader must accept, in bytes (5.3c).
pub const READER_MIN_BYTES: usize = 64 * 1024;
/// The number of actions that a reader must accept (5.3c).
pub const READER_MIN_ACTIONS: usize = 64;
/// The number of types that a reader must accept (5.3c).
pub const READER_MIN_TYPES: usize = 16;
/// The number of resources that a reader must accept (5.3c).
pub const READER_MIN_RESOURCES: usize = 256;
/// The number of limit declarations that a reader must accept (5.3c).
pub const READER_MIN_LIMITS: usize = 16;
/// The length of a label that a reader must accept, in characters (5.3c).
pub const READER_MIN_LABEL: usize = 60;
/// The length of a description that a reader must accept, in characters (5.3c).
pub const READER_MIN_DESCRIPTION: usize = 300;
/// The length of a unit that a reader must accept, in characters (5.3c).
pub const READER_MIN_UNIT: usize = 20;

/// The kind of a limit (6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LimitKind {
    /// The maximum of one use. The PEP applies it.
    Ceiling,
    /// An amount of units for each window. The PDP counts it.
    Budget,
}

impl LimitKind {
    /// The word of the document.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ceiling => "ceiling",
            Self::Budget => "budget",
        }
    }
}

/// A type below the service (5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceType {
    /// The name of the type.
    pub name: String,
    /// The name of the parent: `service` or a declared type.
    pub parent: String,
    /// The description, in English.
    pub description: String,
}

/// An action of the service (5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    /// The name of the action.
    pub name: String,
    /// The types on which a grant of the action is valid: `service` or declared types.
    pub resource_types: Vec<String>,
    /// The description, in English.
    pub description: String,
    /// The names of the limits of the action (6.2).
    pub limits: Vec<String>,
}

/// A node that the service names (5.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceItem {
    /// The nodes of the path, without the service.
    pub nodes: Vec<NodeRef>,
    /// The label, when the document gives one.
    pub label: Option<String>,
    /// The actions of the node, when the document gives them.
    pub actions: Option<Vec<String>>,
}

/// A limit declaration (6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LimitDeclaration {
    /// The name of the limit.
    pub name: String,
    /// The label, in English.
    pub label: String,
    /// The description, in English.
    pub description: String,
    /// The unit of measure.
    pub unit: String,
    /// Ceiling or budget.
    pub kind: LimitKind,
    /// The lowest value of a ceiling. A budget has none.
    pub min: Option<u64>,
    /// The highest value of a ceiling. A budget has none.
    pub max: Option<u64>,
}

/// Why a path does not follow the tree of types of a document.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NodeError {
    /// The first node is not the service of the document.
    #[error("the service is `{found}`, and the document is for `{expected}`")]
    WrongService {
        /// The id in the document.
        expected: String,
        /// The id in the path.
        found: String,
    },
    /// The type of a node is not declared.
    #[error("node {index} has the type `{node_type}`, and the document does not declare it")]
    UnknownType {
        /// The position of the node in the path, from 0 for the service.
        index: usize,
        /// The type.
        node_type: String,
    },
    /// The type of a node does not have the type of the node before it as its parent.
    #[error(
        "node {index} has the type `{node_type}`, whose parent is `{expected}`, but the node before it has the type `{found}`"
    )]
    WrongParent {
        /// The position of the node in the path, from 0 for the service.
        index: usize,
        /// The type.
        node_type: String,
        /// The parent in the document.
        expected: String,
        /// The type of the node before it.
        found: String,
    },
}

/// A good action document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionDocument {
    /// The id of the service.
    pub server: String,
    /// The tree of types below the service.
    pub resource_types: Vec<ResourceType>,
    /// The actions.
    pub actions: Vec<Action>,
    /// The nodes that the service names.
    pub resources: Vec<ResourceItem>,
    /// The limit declarations.
    pub limits: Vec<LimitDeclaration>,
}

impl ActionDocument {
    /// Read and check a document from JSON text.
    ///
    /// # Errors
    /// Returns every finding when the document is bad.
    pub fn parse_str(text: &str) -> Result<Self, Vec<Finding>> {
        let analysis = analyze_str(text);
        match analysis.document {
            Some(document) => Ok(document),
            None => Err(analysis.report.into_findings()),
        }
    }

    /// Read and check a document from a JSON value.
    ///
    /// # Errors
    /// Returns every finding when the document is bad.
    pub fn from_value(value: &Value) -> Result<Self, Vec<Finding>> {
        let analysis = analyze_value(value);
        match analysis.document {
            Some(document) => Ok(document),
            None => Err(analysis.report.into_findings()),
        }
    }

    /// The type with this name.
    pub fn resource_type(&self, name: &str) -> Option<&ResourceType> {
        self.resource_types.iter().find(|t| t.name == name)
    }

    /// The parent of a type. The parent of `service` does not exist.
    pub fn parent_of(&self, name: &str) -> Option<&str> {
        self.resource_type(name).map(|t| t.parent.as_str())
    }

    /// The depth of a type (4.1): 0 for `service`, 1 for a type whose parent is `service`.
    pub fn type_depth(&self, name: &str) -> Option<usize> {
        if name == SERVICE {
            return Some(0);
        }
        let mut depth = 0;
        let mut current = name;
        while current != SERVICE {
            current = self.parent_of(current)?;
            depth += 1;
            if depth > self.resource_types.len() {
                return None;
            }
        }
        Some(depth)
    }

    /// Check that a path follows the tree of types of this document (4.1).
    /// The first node must be the service of the document.
    ///
    /// # Errors
    /// Returns the first node that breaks the tree.
    pub fn check_path(&self, path: &NodePath) -> Result<(), NodeError> {
        let nodes = path.nodes();
        if nodes[0].id != self.server {
            return Err(NodeError::WrongService {
                expected: self.server.clone(),
                found: nodes[0].id.clone(),
            });
        }
        for (index, pair) in nodes.windows(2).enumerate() {
            let node = &pair[1];
            let Some(parent) = self.parent_of(&node.node_type) else {
                return Err(NodeError::UnknownType {
                    index: index + 1,
                    node_type: node.node_type.clone(),
                });
            };
            if parent != pair[0].node_type {
                return Err(NodeError::WrongParent {
                    index: index + 1,
                    node_type: node.node_type.clone(),
                    expected: parent.to_owned(),
                    found: pair[0].node_type.clone(),
                });
            }
        }
        Ok(())
    }

    /// The action with this name.
    pub fn action(&self, name: &str) -> Option<&Action> {
        self.actions.iter().find(|a| a.name == name)
    }

    /// The limit declaration with this name.
    pub fn limit(&self, name: &str) -> Option<&LimitDeclaration> {
        self.limits.iter().find(|l| l.name == name)
    }

    /// True when the action lists at least one budget (6.2, 6.4).
    pub fn action_lists_budget(&self, action: &str) -> bool {
        self.action(action).is_some_and(|a| {
            a.limits.iter().any(|name| {
                self.limit(name)
                    .is_some_and(|l| l.kind == LimitKind::Budget)
            })
        })
    }

    /// The paths of the nodes that the service names, with the service first.
    pub fn named_nodes(&self) -> Vec<NodePath> {
        self.resources
            .iter()
            .filter_map(|item| {
                let mut nodes = vec![NodeRef::service(&self.server)];
                nodes.extend(item.nodes.iter().cloned());
                NodePath::from_nodes(nodes).ok()
            })
            .collect()
    }

    /// The document as a JSON value, in the form of 5.2.
    pub fn to_value(&self) -> Value {
        let types: Vec<Value> = self
            .resource_types
            .iter()
            .map(|t| json!({"name": t.name, "parent": t.parent, "description": t.description}))
            .collect();
        let actions: Vec<Value> = self
            .actions
            .iter()
            .map(|a| {
                let mut m = Map::new();
                m.insert("name".into(), json!(a.name));
                m.insert("resource_types".into(), json!(a.resource_types));
                m.insert("description".into(), json!(a.description));
                if !a.limits.is_empty() {
                    m.insert("limits".into(), json!(a.limits));
                }
                Value::Object(m)
            })
            .collect();
        let mut doc = Map::new();
        doc.insert("server".into(), json!(self.server));
        doc.insert("resource_types".into(), Value::Array(types));
        doc.insert("actions".into(), Value::Array(actions));
        if !self.resources.is_empty() {
            let resources: Vec<Value> = self
                .resources
                .iter()
                .map(|r| {
                    let mut m = Map::new();
                    m.insert("path".into(), json!(format_below_service(&r.nodes)));
                    if let Some(label) = &r.label {
                        m.insert("label".into(), json!(label));
                    }
                    if let Some(actions) = &r.actions {
                        m.insert("actions".into(), json!(actions));
                    }
                    Value::Object(m)
                })
                .collect();
            doc.insert("resources".into(), Value::Array(resources));
        }
        if !self.limits.is_empty() {
            let limits: Vec<Value> = self
                .limits
                .iter()
                .map(|l| {
                    let mut m = Map::new();
                    m.insert("name".into(), json!(l.name));
                    m.insert("label".into(), json!(l.label));
                    m.insert("description".into(), json!(l.description));
                    m.insert("unit".into(), json!(l.unit));
                    m.insert("kind".into(), json!(l.kind.as_str()));
                    if let Some(min) = l.min {
                        m.insert("min".into(), json!(min));
                    }
                    if let Some(max) = l.max {
                        m.insert("max".into(), json!(max));
                    }
                    Value::Object(m)
                })
                .collect();
            doc.insert("limits".into(), Value::Array(limits));
        }
        Value::Object(doc)
    }
}

/// The result of a check: every finding, and the typed document when it is good.
#[derive(Clone, Debug)]
pub struct Analysis {
    /// The document. It is `None` when at least one finding is an error.
    pub document: Option<ActionDocument>,
    /// All findings, in the order of the document.
    pub report: Report,
}

/// Check a document that is a JSON value.
pub fn analyze_value(value: &Value) -> Analysis {
    let mut report = Report::new();
    let document = check_into(value, &JsonPath::root(), &mut report);
    Analysis { document, report }
}

/// Check a document that is JSON text. The reader is strict: it rejects a
/// duplicate member. A text above 64 KiB gets a warning (5.3c).
pub fn analyze_str(text: &str) -> Analysis {
    match parse_str(text) {
        Ok(value) => {
            let mut analysis = analyze_value(&value);
            if text.len() > READER_MIN_BYTES {
                let mut report = Report::new();
                report.warning(
                    &JsonPath::root(),
                    "5.3c",
                    "above_reader_minimum",
                    format!(
                        "The document has {} bytes. A reader must accept {READER_MIN_BYTES} bytes.",
                        text.len()
                    ),
                );
                report.extend(analysis.report.into_findings());
                analysis.report = report;
            }
            analysis
        }
        Err(error) => {
            let mut report = Report::new();
            report.error(
                &error.path,
                "5.3",
                "bad_json",
                format!(
                    "The text is not valid JSON, line {}, column {}: {}.",
                    error.line, error.column, error.kind
                ),
            );
            Analysis {
                document: None,
                report,
            }
        }
    }
}

/// Check a document that sits at `base` inside a larger document. The
/// function adds the findings to `report`. It returns the document when it
/// adds no error.
pub fn check_into(value: &Value, base: &JsonPath, report: &mut Report) -> Option<ActionDocument> {
    let errors_before = report.error_count();
    let mut top = Obj::new(value, base, "5.2", Unknown::Warn, report)?;
    let scan = Scan::new(&top);

    let server = top.string("server", report).unwrap_or_default().to_owned();
    if top.has_string("server") {
        check_server(&server, &top.member_path("server"), report);
    }
    let types = top
        .array("resource_types", report)
        .map_or_else(Vec::new, |items| {
            read_types(items, &top.member_path("resource_types"), &scan, report)
        });
    let actions = top.array("actions", report).map_or_else(Vec::new, |items| {
        read_actions(items, &top.member_path("actions"), &scan, report)
    });
    let resources = top
        .array_opt("resources", report)
        .map_or_else(Vec::new, |items| {
            read_resources(items, &top.member_path("resources"), &scan, report)
        });
    let limits = top
        .array_opt("limits", report)
        .map_or_else(Vec::new, |items| {
            read_limits(items, &top.member_path("limits"), report)
        });
    top.finish(report);

    warn_count(
        report,
        &top.member_path("resource_types"),
        types.len(),
        READER_MIN_TYPES,
        "types",
    );
    warn_count(
        report,
        &top.member_path("actions"),
        actions.len(),
        READER_MIN_ACTIONS,
        "actions",
    );
    warn_count(
        report,
        &top.member_path("resources"),
        resources.len(),
        READER_MIN_RESOURCES,
        "resources",
    );
    warn_count(
        report,
        &top.member_path("limits"),
        limits.len(),
        READER_MIN_LIMITS,
        "limit declarations",
    );

    (report.error_count() == errors_before).then_some(ActionDocument {
        server,
        resource_types: types,
        actions,
        resources,
        limits,
    })
}

fn warn_count(report: &mut Report, path: &JsonPath, count: usize, minimum: usize, what: &str) {
    if count > minimum {
        report.warning(
            path,
            "5.3c",
            "above_reader_minimum",
            format!("The document has {count} {what}. A reader must accept {minimum}."),
        );
    }
}

fn warn_length(report: &mut Report, path: &JsonPath, text: &str, minimum: usize, what: &str) {
    let length = text.chars().count();
    if length > minimum {
        report.warning(
            path,
            "5.3c",
            "above_reader_minimum",
            format!("The {what} has {length} characters. A reader must accept {minimum}."),
        );
    }
}

fn check_server(server: &str, path: &JsonPath, report: &mut Report) {
    if let Err(error) = crate::names::validate_id(server) {
        report.error(
            path,
            "5.2",
            "bad_server",
            format!("Member `server` {}: {error}.", show(&json!(server))),
        );
    }
}

/// The names that the three lists declare. A check of one list uses it to
/// check a name in another list, whatever the order of the members.
struct Scan {
    type_parent: HashMap<String, String>,
    limit_names: HashSet<String>,
    action_names: HashSet<String>,
}

impl Scan {
    fn new(top: &Obj<'_>) -> Self {
        let mut scan = Self {
            type_parent: HashMap::new(),
            limit_names: HashSet::new(),
            action_names: HashSet::new(),
        };
        let items = |key: &str| top.peek_items(key);
        for item in items("resource_types") {
            if let (Some(name), Some(parent)) = (
                item.get("name").and_then(Value::as_str),
                item.get("parent").and_then(Value::as_str),
            ) && is_type_or_limit_name(name)
                && name != SERVICE
            {
                scan.type_parent
                    .entry(name.to_owned())
                    .or_insert_with(|| parent.to_owned());
            }
        }
        for item in items("limits") {
            if let Some(name) = item.get("name").and_then(Value::as_str)
                && is_type_or_limit_name(name)
            {
                scan.limit_names.insert(name.to_owned());
            }
        }
        for item in items("actions") {
            if let Some(name) = item.get("name").and_then(Value::as_str)
                && is_action_name(name)
            {
                scan.action_names.insert(name.to_owned());
            }
        }
        scan
    }

    fn is_type(&self, name: &str) -> bool {
        self.type_parent.contains_key(name)
    }
}

fn read_types(
    items: &[Value],
    base: &JsonPath,
    scan: &Scan,
    report: &mut Report,
) -> Vec<ResourceType> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "5.2", Unknown::Warn, report) else {
            continue;
        };
        let name = obj.string("name", report).unwrap_or_default();
        let parent = obj.string("parent", report).unwrap_or_default();
        let description = obj.string("description", report).unwrap_or_default();
        obj.finish(report);
        warn_length(
            report,
            &path.key("description"),
            description,
            READER_MIN_DESCRIPTION,
            "description",
        );

        if obj.has_string("name") {
            if name == SERVICE {
                report.error(
                    &path.key("name"),
                    "5.2",
                    "reserved_type_name",
                    "The type name `service` is not valid. The document does not declare `service`.",
                );
            } else if !is_type_or_limit_name(name) {
                report.error(
                    &path.key("name"),
                    "5.2",
                    "bad_type_name",
                    format!(
                        "Type name {}: expected 1 to 32 characters, a to z first, then a to z, 0 to 9 or underscore.",
                        show(&json!(name))
                    ),
                );
            } else if !seen.insert(name.to_owned()) {
                report.error(
                    &path.key("name"),
                    "5.2",
                    "duplicate_type_name",
                    format!("Type name `{name}` occurs more than one time."),
                );
            }
        }
        if obj.has_string("parent") {
            check_parent(name, parent, scan, &path.key("parent"), report);
        }
        out.push(ResourceType {
            name: name.to_owned(),
            parent: parent.to_owned(),
            description: description.to_owned(),
        });
    }
    out
}

fn check_parent(name: &str, parent: &str, scan: &Scan, path: &JsonPath, report: &mut Report) {
    if parent != SERVICE && !scan.is_type(parent) {
        report.error(
            path,
            "5.2",
            "undeclared_parent",
            format!("Parent `{parent}` is not `service` and is not a declared type."),
        );
        return;
    }
    if !is_type_or_limit_name(name) || name == SERVICE {
        return;
    }
    let mut depth = 1;
    let mut current = parent;
    let mut visited: HashSet<&str> = HashSet::from([name]);
    while current != SERVICE {
        if !visited.insert(current) {
            report.error(
                path,
                "5.2",
                "type_cycle",
                format!("The parents of type `{name}` make a cycle."),
            );
            return;
        }
        let Some(next) = scan.type_parent.get(current) else {
            return;
        };
        current = next;
        depth += 1;
    }
    if depth > MAX_TYPE_DEPTH {
        report.error(
            path,
            "4.1",
            "type_too_deep",
            format!("Type `{name}` has depth {depth}. The maximum depth is {MAX_TYPE_DEPTH}."),
        );
    }
}

fn read_actions(items: &[Value], base: &JsonPath, scan: &Scan, report: &mut Report) -> Vec<Action> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "5.2", Unknown::Warn, report) else {
            continue;
        };
        let name = obj.string("name", report).unwrap_or_default();
        let types = obj.strings("resource_types", report);
        let description = obj.string("description", report).unwrap_or_default();
        let limits = obj.strings_opt("limits", report);
        obj.finish(report);
        warn_length(
            report,
            &path.key("description"),
            description,
            READER_MIN_DESCRIPTION,
            "description",
        );

        if obj.has_string("name") {
            if name == ACCESS_ACTION {
                report.error(
                    &path.key("name"),
                    "5.2",
                    "access_in_list",
                    "The list must not have the action `access`. It opens the service to a subject (8.3).",
                );
            } else if !is_action_name(name) {
                report.error(
                    &path.key("name"),
                    "5.2",
                    "bad_action_name",
                    format!(
                        "Action name {}: expected 1 to 64 characters, parts of a to z, 0 to 9 and underscore, with `.` between the parts.",
                        show(&json!(name))
                    ),
                );
            } else if !seen.insert(name.to_owned()) {
                report.error(
                    &path.key("name"),
                    "5.2",
                    "duplicate_action_name",
                    format!("Action name `{name}` occurs more than one time."),
                );
            }
        }
        let types = types.unwrap_or_default();
        let mut seen_types = HashSet::new();
        for (i, t) in types.iter().enumerate() {
            let tpath = path.key("resource_types").index(i);
            if *t != SERVICE && !scan.is_type(t) {
                report.error(
                    &tpath,
                    "5.2",
                    "undeclared_type",
                    format!("Resource type `{t}` is not `service` and is not a declared type."),
                );
            } else if !seen_types.insert(*t) {
                report.error(
                    &tpath,
                    "5.2",
                    "duplicate_type",
                    format!("Resource type `{t}` occurs more than one time."),
                );
            }
        }
        let limits = limits.unwrap_or_default();
        let mut seen_limits = HashSet::new();
        for (i, l) in limits.iter().enumerate() {
            let lpath = path.key("limits").index(i);
            if !scan.limit_names.contains(*l) {
                report.error(
                    &lpath,
                    "5.2",
                    "undeclared_limit",
                    format!("Limit `{l}` is not declared in `limits`."),
                );
            } else if !seen_limits.insert(*l) {
                report.error(
                    &lpath,
                    "5.2",
                    "duplicate_limit",
                    format!("Limit `{l}` occurs more than one time."),
                );
            }
        }
        out.push(Action {
            name: name.to_owned(),
            resource_types: types.iter().map(|t| (*t).to_owned()).collect(),
            description: description.to_owned(),
            limits: limits.iter().map(|l| (*l).to_owned()).collect(),
        });
    }
    out
}

fn read_resources(
    items: &[Value],
    base: &JsonPath,
    scan: &Scan,
    report: &mut Report,
) -> Vec<ResourceItem> {
    let mut out = Vec::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "5.2", Unknown::Warn, report) else {
            continue;
        };
        let text = obj.string("path", report);
        let label = obj.string_opt("label", report);
        let actions = obj.strings_opt("actions", report);
        obj.finish(report);
        if let Some(label) = label {
            warn_length(report, &path.key("label"), label, READER_MIN_LABEL, "label");
        }
        let nodes = text.map_or_else(Vec::new, |text| {
            check_resource_path(text, scan, &path.key("path"), report)
        });
        if let Some(names) = &actions {
            let mut seen = HashSet::new();
            for (i, name) in names.iter().enumerate() {
                let apath = path.key("actions").index(i);
                if !scan.action_names.contains(*name) {
                    report.error(
                        &apath,
                        "5.2",
                        "undeclared_action",
                        format!("Action `{name}` is not declared in `actions`."),
                    );
                } else if !seen.insert(*name) {
                    report.error(
                        &apath,
                        "5.2",
                        "duplicate_action",
                        format!("Action `{name}` occurs more than one time."),
                    );
                }
            }
        }
        out.push(ResourceItem {
            nodes,
            label: label.map(str::to_owned),
            actions: actions.map(|a| a.into_iter().map(str::to_owned).collect()),
        });
    }
    out
}

fn check_resource_path(
    text: &str,
    scan: &Scan,
    path: &JsonPath,
    report: &mut Report,
) -> Vec<NodeRef> {
    let nodes = match NodePath::parse_below_service(text) {
        Ok(nodes) => nodes,
        Err(error) => {
            let code = if matches!(error, PathError::TooDeep(_)) {
                "type_too_deep"
            } else {
                "bad_path"
            };
            report.error(
                path,
                "5.2",
                code,
                format!("Path {}: {error}.", show(&json!(text))),
            );
            return Vec::new();
        }
    };
    let mut before = SERVICE;
    for (index, node) in nodes.iter().enumerate() {
        match scan.type_parent.get(&node.node_type) {
            None => {
                report.error(
                    path,
                    "5.2",
                    "undeclared_type",
                    format!(
                        "Segment {index}: type `{}` is not a declared type.",
                        node.node_type
                    ),
                );
                break;
            }
            Some(parent) if parent != before => {
                report.error(
                    path,
                    "5.2",
                    "wrong_parent",
                    format!(
                        "Segment {index}: the parent of type `{}` is `{parent}`, but the segment before it has the type `{before}`.",
                        node.node_type
                    ),
                );
                break;
            }
            Some(_) => before = &node.node_type,
        }
    }
    nodes
}

fn read_limits(items: &[Value], base: &JsonPath, report: &mut Report) -> Vec<LimitDeclaration> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let path = base.index(index);
        let Some(mut obj) = Obj::new(item, &path, "6.1", Unknown::Error, report)
            .map(|obj| obj.with_unknown_rule("5.3"))
        else {
            continue;
        };
        let name = obj.string("name", report).unwrap_or_default();
        let label = obj.string("label", report).unwrap_or_default();
        let description = obj.string("description", report).unwrap_or_default();
        let unit = obj.string("unit", report).unwrap_or_default();
        let kind_text = obj.string("kind", report);
        let min_value = obj.optional("min");
        let max_value = obj.optional("max");
        let min_present = min_value.is_some();
        let max_present = max_value.is_some();
        obj.finish(report);
        warn_length(report, &path.key("label"), label, READER_MIN_LABEL, "label");
        warn_length(
            report,
            &path.key("description"),
            description,
            READER_MIN_DESCRIPTION,
            "description",
        );
        warn_length(report, &path.key("unit"), unit, READER_MIN_UNIT, "unit");

        let kind = match kind_text {
            Some("ceiling") => Some(LimitKind::Ceiling),
            Some("budget") => Some(LimitKind::Budget),
            Some(other) => {
                report.error(
                    &path.key("kind"),
                    "6.1",
                    "bad_kind",
                    format!(
                        "Member `kind`: expected `ceiling` or `budget`, found {}.",
                        show(&json!(other))
                    ),
                );
                None
            }
            None => None,
        };
        if obj.has_string("name") {
            if !is_type_or_limit_name(name) {
                report.error(
                    &path.key("name"),
                    "5.2",
                    "bad_limit_name",
                    format!(
                        "Limit name {}: expected 1 to 32 characters, a to z first, then a to z, 0 to 9 or underscore.",
                        show(&json!(name))
                    ),
                );
            } else if !seen.insert(name.to_owned()) {
                report.error(
                    &path.key("name"),
                    "6.1",
                    "duplicate_limit_name",
                    format!("Limit name `{name}` occurs more than one time."),
                );
            }
        }
        let mut min = None;
        let mut max = None;
        match kind {
            Some(LimitKind::Budget) => {
                if name.starts_with("max_") {
                    report.error(
                        &path.key("name"),
                        "6.1",
                        "budget_name_max",
                        format!("Budget name `{name}` must not start with `max_` (7.1)."),
                    );
                }
                for (present, key) in [(min_present, "min"), (max_present, "max")] {
                    if present {
                        report.error(
                            &path.key(key),
                            "6.1",
                            if key == "min" {
                                "budget_with_min"
                            } else {
                                "budget_with_max"
                            },
                            format!("A budget declaration has no `{key}`."),
                        );
                    }
                }
            }
            Some(LimitKind::Ceiling) => {
                if !name.starts_with("max_") && is_type_or_limit_name(name) {
                    report.warning(
                        &path.key("name"),
                        "7.1",
                        "ceiling_name",
                        format!("Ceiling name `{name}` should be `max_` and a noun."),
                    );
                }
                min = read_bound("min", min_value, &path, report);
                max = read_bound("max", max_value, &path, report);
                if let (Some(low), Some(high)) = (min, max)
                    && low > high
                {
                    report.error(
                        &path.key("min"),
                        "6.1",
                        "min_above_max",
                        format!("Member `min` is {low}, and it is above `max`, which is {high}."),
                    );
                }
            }
            None => {}
        }
        out.push(LimitDeclaration {
            name: name.to_owned(),
            label: label.to_owned(),
            description: description.to_owned(),
            unit: unit.to_owned(),
            kind: kind.unwrap_or(LimitKind::Budget),
            min,
            max,
        });
    }
    out
}

fn read_bound(
    key: &str,
    value: Option<&Value>,
    path: &JsonPath,
    report: &mut Report,
) -> Option<u64> {
    let Some(value) = value else {
        report.error(
            path,
            "6.1",
            "ceiling_without_bound",
            format!("A ceiling declaration needs the member `{key}`."),
        );
        return None;
    };
    if let Some(number) = value.as_u64() {
        Some(number)
    } else {
        report.error(
            &path.key(key),
            "6.1",
            "bad_bound",
            format!(
                "Member `{key}`: expected a whole number of 0 or more, found {}.",
                show(value)
            ),
        );
        None
    }
}

/// A count of the types of each depth, for a tool that shows the tree.
pub fn types_by_depth(document: &ActionDocument) -> BTreeMap<usize, Vec<&str>> {
    let mut out: BTreeMap<usize, Vec<&str>> = BTreeMap::new();
    for t in &document.resource_types {
        if let Some(depth) = document.type_depth(&t.name) {
            out.entry(depth).or_default().push(&t.name);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    /// The action document of protocol section 13.
    fn section_13() -> Value {
        json!({
            "server": "datastore",
            "resource_types": [
                {"name": "host", "parent": "service", "description": "One database server."},
                {"name": "database", "parent": "host", "description": "One database."},
                {"name": "table", "parent": "database", "description": "One table."}
            ],
            "actions": [
                {"name": "data.read", "resource_types": ["service", "host", "database", "table"],
                 "description": "Read data.", "limits": ["requests", "max_rows", "max_duration"]},
                {"name": "data.write", "resource_types": ["service", "host", "database", "table"],
                 "description": "Change data.", "limits": ["requests", "max_duration"]}
            ],
            "resources": [{"path": "host:prod", "label": "Production"}],
            "limits": [
                {"name": "requests", "label": "Requests", "description": "Requests that run.",
                 "unit": "request", "kind": "budget"},
                {"name": "max_rows", "label": "Most rows", "description": "The most rows that one read gives.",
                 "unit": "row", "kind": "ceiling", "min": 1, "max": 1000000},
                {"name": "max_duration", "label": "Longest run", "description": "The longest run of one use, in seconds.",
                 "unit": "second", "kind": "ceiling", "min": 1, "max": 600}
            ]
        })
    }

    fn findings_of(value: &Value) -> Vec<(String, &'static str, Severity)> {
        analyze_value(value)
            .report
            .findings()
            .iter()
            .map(|f| (f.path.as_str().to_owned(), f.code, f.severity))
            .collect()
    }

    fn errors_of(value: &Value) -> Vec<(String, &'static str)> {
        findings_of(value)
            .into_iter()
            .filter(|(_, _, s)| *s == Severity::Error)
            .map(|(p, c, _)| (p, c))
            .collect()
    }

    fn one_error(value: &Value, path: &str, code: &str) {
        let errors = errors_of(value);
        assert!(
            errors.len() == 1 && errors[0].0 == path && errors[0].1 == code,
            "wrong findings: {errors:?}"
        );
    }

    #[test]
    fn p_13_example_document_is_good() {
        let analysis = analyze_value(&section_13());
        assert!(
            analysis.report.findings().is_empty(),
            "{:?}",
            analysis.report
        );
        let doc = analysis.document.unwrap();
        assert_eq!(doc.server, "datastore");
        assert_eq!(doc.type_depth("table"), Some(3));
        assert_eq!(doc.type_depth("service"), Some(0));
        assert!(doc.action_lists_budget("data.read"));
        assert_eq!(doc.limit("max_rows").unwrap().max, Some(1_000_000));
        assert_eq!(doc.to_value(), section_13());
    }

    #[test]
    fn p_5_2_top_level_must_be_an_object() {
        one_error(&json!([]), "$", "wrong_type");
    }

    #[test]
    fn p_5_2_mandatory_members() {
        let errors = errors_of(&json!({}));
        let codes: Vec<_> = errors.iter().map(|(_, c)| *c).collect();
        assert_eq!(codes, vec!["missing_member"; 3]);
    }

    #[test]
    fn p_5_2_server_is_an_id() {
        let mut doc = section_13();
        doc["server"] = json!("");
        one_error(&doc, "$.server", "bad_server");
        doc["server"] = json!(5);
        one_error(&doc, "$.server", "wrong_type");
    }

    #[test]
    fn p_5_3_unknown_member_outside_a_limit_declaration_is_a_warning() {
        let mut doc = section_13();
        doc["extra"] = json!(1);
        doc["actions"][0]["extra"] = json!(1);
        let found = findings_of(&doc);
        assert_eq!(found.len(), 2);
        assert!(
            found
                .iter()
                .all(|(_, c, s)| *c == "unknown_member" && *s == Severity::Warning)
        );
        assert!(analyze_value(&doc).document.is_some());
    }

    #[test]
    fn p_5_3_unknown_member_of_a_limit_declaration_is_bad() {
        let mut doc = section_13();
        doc["limits"][0]["scope"] = json!("x");
        one_error(&doc, "$.limits[0].scope", "unknown_member");
        let analysis = analyze_value(&doc);
        assert_eq!(analysis.report.findings()[0].rule, "5.3");
        assert!(analysis.document.is_none());
    }

    #[test]
    fn p_5_3_duplicate_member_in_the_text_is_bad() {
        let text = r#"{"server": "a", "server": "b", "resource_types": [], "actions": []}"#;
        let analysis = analyze_str(text);
        assert!(analysis.document.is_none());
        let finding = &analysis.report.findings()[0];
        assert_eq!(finding.code, "bad_json");
        assert_eq!(finding.path.as_str(), "$.server");
    }

    #[test]
    fn p_5_3_every_error_is_listed_with_its_path() {
        let mut doc = section_13();
        doc["actions"][1]["limits"] = json!(["requests", "nope"]);
        doc["limits"][0]["min"] = json!(1);
        doc["resource_types"][2]["parent"] = json!("nowhere");
        let errors = errors_of(&doc);
        assert_eq!(
            errors,
            vec![
                ("$.resource_types[2].parent".to_owned(), "undeclared_parent"),
                ("$.actions[1].limits[1]".to_owned(), "undeclared_limit"),
                ("$.limits[0].min".to_owned(), "budget_with_min"),
            ]
        );
    }

    #[test]
    fn p_5_2_type_names() {
        let mut doc = section_13();
        doc["resource_types"][0]["name"] = json!("service");
        one_error_in_types(&doc, "reserved_type_name");
        doc["resource_types"][0]["name"] = json!("Host");
        one_error_in_types(&doc, "bad_type_name");
        doc["resource_types"][0]["name"] = json!("database");
        let codes: Vec<_> = errors_of(&doc).into_iter().map(|(_, c)| c).collect();
        assert!(codes.contains(&"duplicate_type_name"));
    }

    fn one_error_in_types(doc: &Value, code: &str) {
        let errors = errors_of(doc);
        assert!(
            errors
                .iter()
                .any(|(p, c)| p == "$.resource_types[0].name" && *c == code),
            "{errors:?}"
        );
    }

    #[test]
    fn p_5_2_parent_must_be_declared() {
        let mut doc = section_13();
        doc["resource_types"][1]["parent"] = json!("ghost");
        one_error(&doc, "$.resource_types[1].parent", "undeclared_parent");
    }

    #[test]
    fn p_5_2_a_cycle_of_parents_is_bad() {
        let doc = json!({
            "server": "s",
            "resource_types": [
                {"name": "a", "parent": "b", "description": "A."},
                {"name": "b", "parent": "a", "description": "B."}
            ],
            "actions": []
        });
        let errors = errors_of(&doc);
        assert_eq!(
            errors,
            vec![
                ("$.resource_types[0].parent".to_owned(), "type_cycle"),
                ("$.resource_types[1].parent".to_owned(), "type_cycle"),
            ]
        );
    }

    #[test]
    fn p_5_2_a_type_that_is_its_own_parent_is_bad() {
        let doc = json!({
            "server": "s",
            "resource_types": [{"name": "a", "parent": "a", "description": "A."}],
            "actions": []
        });
        one_error(&doc, "$.resource_types[0].parent", "type_cycle");
    }

    fn chain_of_types(count: usize) -> Value {
        let types: Vec<Value> = (1..=count)
            .map(|i| {
                let parent = if i == 1 {
                    "service".to_owned()
                } else {
                    format!("t{}", i - 1)
                };
                json!({"name": format!("t{i}"), "parent": parent, "description": "A type."})
            })
            .collect();
        json!({"server": "s", "resource_types": types, "actions": []})
    }

    #[test]
    fn p_4_1_depth_four_is_good() {
        assert!(analyze_value(&chain_of_types(4)).document.is_some());
    }

    #[test]
    fn p_4_1_depth_five_is_bad() {
        one_error(
            &chain_of_types(5),
            "$.resource_types[4].parent",
            "type_too_deep",
        );
    }

    #[test]
    fn p_5_2_action_names() {
        let mut doc = section_13();
        doc["actions"][0]["name"] = json!("Data.read");
        one_error(&doc, "$.actions[0].name", "bad_action_name");
        doc["actions"][0]["name"] = json!("data.write");
        one_error(&doc, "$.actions[1].name", "duplicate_action_name");
    }

    #[test]
    fn p_5_2_the_list_never_has_the_action_access() {
        let mut doc = section_13();
        doc["actions"][0]["name"] = json!("access");
        one_error(&doc, "$.actions[0].name", "access_in_list");
    }

    #[test]
    fn p_5_2_action_resource_types() {
        let mut doc = section_13();
        doc["actions"][0]["resource_types"] = json!(["service", "ghost", "host", "host"]);
        let errors = errors_of(&doc);
        assert_eq!(
            errors,
            vec![
                (
                    "$.actions[0].resource_types[1]".to_owned(),
                    "undeclared_type"
                ),
                (
                    "$.actions[0].resource_types[3]".to_owned(),
                    "duplicate_type"
                ),
            ]
        );
    }

    #[test]
    fn p_5_2_action_limits_must_be_declared_and_occur_once() {
        let mut doc = section_13();
        doc["actions"][0]["limits"] = json!(["requests", "requests", "ghost"]);
        let errors = errors_of(&doc);
        assert_eq!(
            errors,
            vec![
                ("$.actions[0].limits[1]".to_owned(), "duplicate_limit"),
                ("$.actions[0].limits[2]".to_owned(), "undeclared_limit"),
            ]
        );
    }

    #[test]
    fn p_5_2_resources_paths() {
        let mut doc = section_13();
        doc["resources"] = json!([
            {"path": "host:prod/database:a%2Fb", "label": "A", "actions": ["data.read"]},
            {"path": "database:x"},
            {"path": "host:a/b"},
            {"path": "host:a b"},
            {"path": "host:prod", "actions": ["data.read", "data.read", "ghost"]},
            {"path": "ghost:x"},
            {"path": "service:datastore"}
        ]);
        let errors = errors_of(&doc);
        assert_eq!(
            errors,
            vec![
                ("$.resources[1].path".to_owned(), "wrong_parent"),
                ("$.resources[2].path".to_owned(), "bad_path"),
                ("$.resources[3].path".to_owned(), "bad_path"),
                ("$.resources[4].actions[1]".to_owned(), "duplicate_action"),
                ("$.resources[4].actions[2]".to_owned(), "undeclared_action"),
                ("$.resources[5].path".to_owned(), "undeclared_type"),
                ("$.resources[6].path".to_owned(), "bad_path"),
            ]
        );
    }

    #[test]
    fn p_5_2_resources_path_decodes_the_id() {
        let mut doc = section_13();
        doc["resources"] = json!([{"path": "host:prod/database:a%2Fb"}]);
        let document = analyze_value(&doc).document.unwrap();
        assert_eq!(document.resources[0].nodes[1].id, "a/b");
        assert_eq!(
            document.named_nodes()[0].to_string(),
            "service:datastore/host:prod/database:a%2Fb"
        );
    }

    #[test]
    fn p_6_1_a_budget_has_no_min_or_max() {
        let mut doc = section_13();
        doc["limits"][0]["min"] = json!(0);
        doc["limits"][0]["max"] = json!(5);
        let errors = errors_of(&doc);
        assert_eq!(
            errors,
            vec![
                ("$.limits[0].min".to_owned(), "budget_with_min"),
                ("$.limits[0].max".to_owned(), "budget_with_max"),
            ]
        );
    }

    #[test]
    fn p_6_1_a_ceiling_has_min_and_max() {
        let mut doc = section_13();
        doc["limits"][1].as_object_mut().unwrap().remove("min");
        one_error(&doc, "$.limits[1]", "ceiling_without_bound");
    }

    #[test]
    fn p_6_1_min_is_not_above_max() {
        let mut doc = section_13();
        doc["limits"][1]["min"] = json!(5);
        doc["limits"][1]["max"] = json!(4);
        one_error(&doc, "$.limits[1].min", "min_above_max");
        doc["limits"][1]["max"] = json!(5);
        assert!(analyze_value(&doc).document.is_some());
    }

    #[test]
    fn p_6_1_bounds_are_whole_numbers_of_zero_or_more() {
        let mut doc = section_13();
        doc["limits"][1]["min"] = json!(-1);
        one_error(&doc, "$.limits[1].min", "bad_bound");
        doc["limits"][1]["min"] = json!(1.5);
        one_error(&doc, "$.limits[1].min", "bad_bound");
        doc["limits"][1]["min"] = json!(1.0);
        one_error(&doc, "$.limits[1].min", "bad_bound");
        doc["limits"][1]["min"] = json!("1");
        one_error(&doc, "$.limits[1].min", "bad_bound");
        doc["limits"][1]["min"] = json!(0);
        assert!(analyze_value(&doc).document.is_some());
    }

    #[test]
    fn p_6_1_kind_is_ceiling_or_budget() {
        let mut doc = section_13();
        doc["limits"][0]["kind"] = json!("quota");
        one_error(&doc, "$.limits[0].kind", "bad_kind");
    }

    #[test]
    fn p_6_1_limit_names_are_unique() {
        let mut doc = section_13();
        doc["limits"][1]["name"] = json!("requests");
        let errors = errors_of(&doc);
        assert!(errors.contains(&("$.limits[1].name".to_owned(), "duplicate_limit_name")));
    }

    #[test]
    fn p_7_1_a_budget_name_never_starts_with_max() {
        let mut doc = section_13();
        doc["limits"][0]["name"] = json!("max_requests");
        doc["actions"][0]["limits"] = json!(["max_requests"]);
        doc["actions"][1]["limits"] = json!([]);
        one_error(&doc, "$.limits[0].name", "budget_name_max");
    }

    #[test]
    fn p_7_1_a_ceiling_name_should_start_with_max() {
        let mut doc = section_13();
        doc["limits"][1]["name"] = json!("rows");
        doc["actions"][0]["limits"] = json!(["requests", "rows", "max_duration"]);
        let found = findings_of(&doc);
        assert_eq!(
            found,
            vec![(
                "$.limits[1].name".to_owned(),
                "ceiling_name",
                Severity::Warning
            )]
        );
    }

    #[test]
    fn p_5_3c_a_reader_minimum_document_is_good_without_warning() {
        let types: Vec<Value> = (0..16)
            .map(|i| json!({"name": format!("t{i}"), "parent": "service", "description": "d".repeat(300)}))
            .collect();
        let limits: Vec<Value> = (0..16)
            .map(|i| {
                json!({"name": format!("b{i}"), "label": "l".repeat(60), "description": "d",
                       "unit": "u".repeat(20), "kind": "budget"})
            })
            .collect();
        let actions: Vec<Value> = (0..64)
            .map(|i| json!({"name": format!("a{i}"), "resource_types": ["service"], "description": "d"}))
            .collect();
        let resources: Vec<Value> = (0..256)
            .map(|i| json!({"path": format!("t0:{i}"), "label": "l".repeat(60)}))
            .collect();
        let doc = json!({"server": "s", "resource_types": types, "actions": actions,
                         "resources": resources, "limits": limits});
        let analysis = analyze_value(&doc);
        assert!(
            analysis.report.findings().is_empty(),
            "{:?}",
            analysis.report
        );
        assert!(analysis.document.is_some());
    }

    #[test]
    fn p_5_3c_a_document_above_the_minimum_gets_warnings() {
        let mut doc = chain_of_types(1);
        doc["actions"] = Value::Array(
            (0..65)
                .map(|i| json!({"name": format!("a{i}"), "resource_types": ["service"], "description": "d".repeat(301)}))
                .collect(),
        );
        let found = findings_of(&doc);
        assert!(
            found
                .iter()
                .all(|(_, c, s)| *c == "above_reader_minimum" && *s == Severity::Warning)
        );
        assert_eq!(found.len(), 66);
        assert!(analyze_value(&doc).document.is_some());
    }

    #[test]
    fn p_5_3c_a_text_above_64_kib_gets_a_warning() {
        let mut doc = chain_of_types(1);
        doc["pad"] = json!("x".repeat(READER_MIN_BYTES));
        let analysis = analyze_str(&doc.to_string());
        assert_eq!(analysis.report.findings()[0].code, "above_reader_minimum");
        assert_eq!(analysis.report.findings()[0].path.as_str(), "$");
    }

    #[test]
    fn p_5_2_parse_str_returns_the_findings() {
        let findings = ActionDocument::parse_str("{}").unwrap_err();
        assert_eq!(findings.len(), 3);
        assert!(ActionDocument::parse_str(&section_13().to_string()).is_ok());
    }
}
