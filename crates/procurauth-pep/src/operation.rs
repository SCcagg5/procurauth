//! One operation of a client, as the PEP asks the PDP about it (5.5, 5.5a, 10.1).
//!
//! An operation has one use and it can have other permissions. A use has one
//! action and one node (5.5). The caller builds the node with its chain from
//! its own data, never from the client (4.5).
//!
//! ```
//! use procurauth_pep::operation::{Operation, node};
//!
//! // The copy of 10.1a: read the table `orders` of `test1`, and write the database `test2`.
//! let source = node("datastore", &[("host", "prod"), ("database", "test1"), ("table", "orders")])?;
//! let target = node("datastore", &[("host", "prod"), ("database", "test2")])?;
//! let operation = Operation::new("data.write", target).also("data.read", source);
//! assert_eq!(operation.uses().len(), 1);
//! assert_eq!(operation.others().len(), 1);
//! # Ok::<(), procurauth_core::path::PathError>(())
//! ```

pub use procurauth_core::path::{NodePath, NodeRef, PathError};

/// One action on one node. The node holds its chain: the path starts at the service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Permission {
    /// The name of the action.
    pub action: String,
    /// The node, with the chain of its ancestors (4.1).
    pub node: NodePath,
}

impl Permission {
    /// A permission for an action on a node.
    pub fn new(action: impl Into<String>, node: NodePath) -> Self {
        Self {
            action: action.into(),
            node,
        }
    }
}

/// The path of a node, from the id of the service and the nodes below it.
/// Each pair is a type and an id. The ids are not encoded (4.1).
///
/// # Errors
/// Returns an error when the path is deeper than 4 steps below the service.
pub fn node(service_id: &str, below: &[(&str, &str)]) -> Result<NodePath, PathError> {
    let mut nodes = vec![NodeRef::service(service_id)];
    nodes.extend(below.iter().map(|(t, i)| NodeRef::new(*t, *i)));
    NodePath::from_nodes(nodes)
}

/// One operation of a client: the use, and the other permissions that it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operation {
    uses: Vec<Permission>,
    others: Vec<Permission>,
}

impl Operation {
    /// An operation with one use: one action on one node.
    pub fn new(action: impl Into<String>, node: NodePath) -> Self {
        Self {
            uses: vec![Permission::new(action, node)],
            others: Vec::new(),
        }
    }

    /// Add another permission that the operation needs (5.5a). The PEP asks it
    /// without `context.usage`, and it applies its ceilings to the part of the
    /// operation that it lets run.
    #[must_use]
    pub fn also(mut self, action: impl Into<String>, node: NodePath) -> Self {
        self.others.push(Permission::new(action, node));
        self
    }

    /// Add a second action for the use. The PEP then chooses among the actions
    /// in the order of the calls (10.1). It stops at the first `true` answer
    /// or at the first `budget_exceeded`.
    #[must_use]
    pub fn or_else_use(mut self, action: impl Into<String>, node: NodePath) -> Self {
        self.uses.push(Permission::new(action, node));
        self
    }

    /// The actions that can be the use, in the order of preference. The list has one item or more.
    pub fn uses(&self) -> &[Permission] {
        &self.uses
    }

    /// The other permissions of the operation (5.5a).
    pub fn others(&self) -> &[Permission] {
        &self.others
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_4_1_a_node_has_the_service_first() {
        let path = node("datastore", &[("host", "prod"), ("database", "test2")]).unwrap();
        let types: Vec<_> = path.nodes().iter().map(|n| n.node_type.as_str()).collect();
        assert_eq!(types, ["service", "host", "database"]);
        assert_eq!(path.service_id(), "datastore");
    }

    #[test]
    fn p_4_1_a_node_below_depth_4_is_refused() {
        let deep = [("a", "1"), ("b", "2"), ("c", "3"), ("d", "4"), ("e", "5")];
        assert!(node("s", &deep).is_err());
    }

    #[test]
    fn p_5_5a_an_operation_keeps_the_order_of_its_permissions() {
        let a = node("s", &[("host", "a")]).unwrap();
        let b = node("s", &[("host", "b")]).unwrap();
        let operation = Operation::new("x.write", a.clone())
            .or_else_use("x.read", b.clone())
            .also("x.list", b);
        assert_eq!(operation.uses()[0].action, "x.write");
        assert_eq!(operation.uses()[1].action, "x.read");
        assert_eq!(operation.others()[0].action, "x.list");
    }
}
