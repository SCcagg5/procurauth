//! Nodes and paths.
//!
//! A node is a pair of a type and an id. A path is the list of nodes from
//! the service down to one node. The text form of a path is the notation of
//! protocol section 13: `service:datastore/host:prod`. The notation is for
//! examples and for conformance data. It is not a wire format.

use std::fmt;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::names::{
    DecodeError, IdError, MAX_TYPE_DEPTH, SERVICE, decode_id, encode_id, is_type_or_limit_name,
    validate_id,
};

/// One node: the type and the id (4.1). It is also one item of the chain.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct NodeRef {
    /// The type of the node. The service has the type `service`.
    #[serde(rename = "type")]
    pub node_type: String,
    /// The id of the node. It is exact text, and nobody encodes it (4.1).
    pub id: String,
}

impl NodeRef {
    /// A node.
    pub fn new(node_type: impl Into<String>, id: impl Into<String>) -> Self {
        Self {
            node_type: node_type.into(),
            id: id.into(),
        }
    }

    /// The node of a service.
    pub fn service(id: impl Into<String>) -> Self {
        Self::new(SERVICE, id)
    }
}

/// Why a text is not a valid path.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum PathError {
    /// The path has no segment.
    #[error("the path is empty")]
    Empty,
    /// A segment has no `:` between the type and the id.
    #[error("segment {index} has no `:` between the type and the id")]
    NoColon {
        /// The position of the segment, from 0.
        index: usize,
    },
    /// The type of a segment is not a valid type name.
    #[error("segment {index} has a type that is not a valid type name")]
    BadType {
        /// The position of the segment, from 0.
        index: usize,
    },
    /// The id of a segment is not percent-encoded as 5.2 says.
    #[error("segment {index}: {source}")]
    BadEncoding {
        /// The position of the segment, from 0.
        index: usize,
        /// The cause.
        source: DecodeError,
    },
    /// The id of a segment breaks the rules of 4.1.
    #[error("segment {index}: {source}")]
    BadId {
        /// The position of the segment, from 0.
        index: usize,
        /// The cause.
        source: IdError,
    },
    /// The first segment of a full path is not the service.
    #[error("the first segment of a full path must have the type `service`")]
    NoService,
    /// The path has more segments than the maximum depth.
    #[error("the path has {0} segments below the service, and the maximum is 4")]
    TooDeep(usize),
}

/// The nodes from the service down to one node. The first node is the service.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodePath(Vec<NodeRef>);

impl NodePath {
    /// A path from its nodes. The first node must be the service.
    ///
    /// # Errors
    /// Returns an error when the list is empty or when the first node is not the service.
    /// It also returns an error when the list is deeper than 4 steps below the service.
    pub fn from_nodes(nodes: Vec<NodeRef>) -> Result<Self, PathError> {
        match nodes.first() {
            None => return Err(PathError::Empty),
            Some(first) if first.node_type != SERVICE => return Err(PathError::NoService),
            Some(_) => {}
        }
        if nodes.len() - 1 > MAX_TYPE_DEPTH {
            return Err(PathError::TooDeep(nodes.len() - 1));
        }
        Ok(Self(nodes))
    }

    /// The path of the service itself.
    pub fn service(id: impl Into<String>) -> Self {
        Self(vec![NodeRef::service(id)])
    }

    /// The nodes, from the service down.
    pub fn nodes(&self) -> &[NodeRef] {
        &self.0
    }

    /// The id of the service, which is the id of the first node.
    pub fn service_id(&self) -> &str {
        &self.0[0].id
    }

    /// The depth: 0 for the service, 1 for a child of the service, and so on.
    pub fn depth(&self) -> usize {
        self.0.len() - 1
    }

    /// The last node of the path.
    pub fn node(&self) -> &NodeRef {
        &self.0[self.0.len() - 1]
    }

    /// The path of a child of this node.
    #[must_use]
    pub fn child(&self, node: NodeRef) -> Self {
        let mut nodes = self.0.clone();
        nodes.push(node);
        Self(nodes)
    }

    /// True when this path is the same as `other`, or a start of it.
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        self.0.len() <= other.0.len() && self.0.iter().zip(&other.0).all(|(a, b)| a == b)
    }

    /// Read a full path in the notation of section 13, for example
    /// `service:datastore/host:prod`.
    ///
    /// # Errors
    /// Returns the first problem of the text.
    pub fn parse(text: &str) -> Result<Self, PathError> {
        let nodes = parse_segments(text, true)?;
        Self::from_nodes(nodes)
    }

    /// Read a path that does not hold the service, as the member `path` of a
    /// resource of the action document does (5.2). Return its nodes.
    ///
    /// # Errors
    /// Returns the first problem of the text.
    pub fn parse_below_service(text: &str) -> Result<Vec<NodeRef>, PathError> {
        let nodes = parse_segments(text, false)?;
        if nodes.len() > MAX_TYPE_DEPTH {
            return Err(PathError::TooDeep(nodes.len()));
        }
        Ok(nodes)
    }
}

fn parse_segments(text: &str, allow_service: bool) -> Result<Vec<NodeRef>, PathError> {
    if text.is_empty() {
        return Err(PathError::Empty);
    }
    let mut nodes = Vec::new();
    for (index, segment) in text.split('/').enumerate() {
        let (node_type, encoded) = segment
            .split_once(':')
            .ok_or(PathError::NoColon { index })?;
        let is_root = allow_service && index == 0;
        let valid_type = is_type_or_limit_name(node_type) && (is_root || node_type != SERVICE);
        if !valid_type {
            return Err(PathError::BadType { index });
        }
        let id = decode_id(encoded).map_err(|source| PathError::BadEncoding { index, source })?;
        validate_id(&id).map_err(|source| PathError::BadId { index, source })?;
        nodes.push(NodeRef::new(node_type, id));
    }
    Ok(nodes)
}

impl fmt::Display for NodePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, node) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("/")?;
            }
            write!(f, "{}:{}", node.node_type, encode_id(&node.id))?;
        }
        Ok(())
    }
}

/// Write nodes that do not hold the service in the notation of 5.2.
pub fn format_below_service(nodes: &[NodeRef]) -> String {
    nodes
        .iter()
        .map(|node| format!("{}:{}", node.node_type, encode_id(&node.id)))
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn p_13_notation_round_trip() {
        let text = "service:datastore/host:prod/database:a%2Fb/table:orders";
        let path = NodePath::parse(text).unwrap();
        assert_eq!(path.depth(), 3);
        assert_eq!(path.nodes()[2], NodeRef::new("database", "a/b"));
        assert_eq!(path.to_string(), text);
        assert_eq!(path.service_id(), "datastore");
    }

    #[test]
    fn p_13_notation_errors() {
        assert_eq!(NodePath::parse(""), Err(PathError::Empty));
        assert_eq!(NodePath::parse("host:prod"), Err(PathError::NoService));
        assert_eq!(
            NodePath::parse("service:d/host"),
            Err(PathError::NoColon { index: 1 })
        );
        assert_eq!(
            NodePath::parse("service:d/Host:p"),
            Err(PathError::BadType { index: 1 })
        );
        assert!(matches!(
            NodePath::parse("service:d/host:a/b"),
            Err(PathError::NoColon { index: 2 })
        ));
        assert!(matches!(
            NodePath::parse("service:d/host:%00"),
            Err(PathError::BadId { index: 1, .. })
        ));
        assert!(matches!(
            NodePath::parse("service:d/host:"),
            Err(PathError::BadId { index: 1, .. })
        ));
        assert_eq!(
            NodePath::parse("service:d/a:1/b:1/c:1/d:1/e:1"),
            Err(PathError::TooDeep(5))
        );
    }

    #[test]
    fn p_5_2_path_below_the_service() {
        let nodes = NodePath::parse_below_service("host:prod/database:a%2Fb").unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(format_below_service(&nodes), "host:prod/database:a%2Fb");
        assert!(NodePath::parse_below_service("service:datastore").is_err());
        assert!(NodePath::parse_below_service("host:a b").is_err());
    }

    #[test]
    fn p_4_3_prefix_relation() {
        let host = NodePath::parse("service:d/host:prod").unwrap();
        let db = NodePath::parse("service:d/host:prod/database:t1").unwrap();
        assert!(host.is_prefix_of(&db));
        assert!(host.is_prefix_of(&host));
        assert!(!db.is_prefix_of(&host));
    }
}
