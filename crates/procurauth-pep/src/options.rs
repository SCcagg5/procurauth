//! The options route (5.6 to 5.8).
//!
//! A service MAY publish `GET /.well-known/procurauth/resources`. The route lists
//! the children of a node, page by page, for a form of grants. This module gives
//! two parts:
//!
//! - [`OptionsQuery::parse`] reads and checks the query parameters (5.7). A bad
//!   parameter is an error, and the service answers HTTP 400.
//! - [`Pep::options`] builds the answer (5.8). It gets the children from the
//!   service. It asks the PDP with `context.match` equal to `subtree` for each
//!   child (5.6). It keeps the children that the subject can see.
//!
//! The route needs an identity token, as each other route does (9.4). The caller
//! checks the token with [`Pep::authenticate`] before it reads the query.

use std::fmt;

use procurauth_core::action_document::ActionDocument;
use procurauth_core::names::{SERVICE, decode_id, is_type_or_limit_name, validate_id};
use procurauth_core::options::{OptionItem, OptionsAnswer};
use procurauth_core::path::{NodePath, NodeRef};

use crate::identity::Identity;
use crate::operation::Permission;
use crate::pep::Pep;
use crate::refusal::Refusal;

/// The number of items of one answer when the request has no `limit`. A caller
/// must accept 50 items (5.8), so a service stays within this number.
pub const MAX_ITEMS: usize = 50;

/// Why a query is not valid. The service answers HTTP 400 (5.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QueryError {
    /// A known parameter occurs more than one time.
    Duplicate(&'static str),
    /// The request has no `type`.
    MissingType,
    /// A value has a percent-escape that is not valid, or a byte that must be encoded (5.7).
    BadEncoding(&'static str),
    /// The value of `limit` is not a whole number from 1.
    BadLimit,
    /// The value of `parent` is not a path of nodes that follows the action document (5.2).
    BadParent,
    /// The type is not declared, or its parent is not the type of the node of `parent` (5.7).
    BadType,
}

impl fmt::Display for QueryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Duplicate(name) => write!(f, "the parameter `{name}` occurs more than one time"),
            Self::MissingType => f.write_str("the parameter `type` is absent"),
            Self::BadEncoding(name) => write!(f, "the parameter `{name}` has a bad percent-encoding"),
            Self::BadLimit => f.write_str("the parameter `limit` is not a whole number from 1"),
            Self::BadParent => f.write_str("the parameter `parent` is not a path of the document"),
            Self::BadType => f.write_str(
                "the parameter `type` is not a type whose parent is the type of the node of `parent`",
            ),
        }
    }
}

impl std::error::Error for QueryError {}

/// The parameters of a request to the options route, after the checks of 5.7.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionsQuery {
    /// The node whose children the route lists. Without `parent`, it is the service.
    pub parent: NodePath,
    /// The type of the children.
    pub type_name: String,
    /// The search text.
    pub q: Option<String>,
    /// The most items that the caller wants.
    pub limit: Option<usize>,
    /// The cursor of the previous answer.
    pub after: Option<String>,
}

impl OptionsQuery {
    /// Read the query string of a request, without the `?`.
    ///
    /// The function decodes each `%XX` one time. It does not read `+` as a
    /// space. It ignores a parameter that 5.7 does not name.
    ///
    /// # Errors
    /// Returns the first rule of 5.7 that the query breaks.
    pub fn parse(query: &str, document: &ActionDocument) -> Result<Self, QueryError> {
        const NAMES: [&str; 5] = ["parent", "type", "q", "limit", "after"];
        let mut values: [Option<&str>; 5] = [None; 5];
        for pair in query.split('&').filter(|p| !p.is_empty()) {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            if let Some(index) = NAMES.iter().position(|n| *n == name) {
                if values[index].is_some() {
                    return Err(QueryError::Duplicate(NAMES[index]));
                }
                values[index] = Some(value);
            }
        }
        let decode = |index: usize| -> Result<Option<String>, QueryError> {
            values[index]
                .map(|text| decode_id(text).map_err(|_| QueryError::BadEncoding(NAMES[index])))
                .transpose()
        };
        let parent_text = decode(0)?;
        let type_name = decode(1)?.ok_or(QueryError::MissingType)?;
        let q = decode(2)?;
        let after = decode(4)?;
        let limit = match values[3] {
            None => None,
            Some(text) => {
                if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
                    return Err(QueryError::BadLimit);
                }
                match text.parse::<usize>() {
                    Ok(n) if n >= 1 => Some(n),
                    _ => return Err(QueryError::BadLimit),
                }
            }
        };
        let service = NodeRef::service(&document.server);
        let parent = match parent_text {
            None => NodePath::service(&document.server),
            Some(text) => {
                let mut nodes = vec![service];
                nodes.extend(
                    NodePath::parse_below_service(&text).map_err(|_| QueryError::BadParent)?,
                );
                let path = NodePath::from_nodes(nodes).map_err(|_| QueryError::BadParent)?;
                document
                    .check_path(&path)
                    .map_err(|_| QueryError::BadParent)?;
                path
            }
        };
        if !is_type_or_limit_name(&type_name) || type_name == SERVICE {
            return Err(QueryError::BadType);
        }
        if document.parent_of(&type_name) != Some(parent.node().node_type.as_str()) {
            return Err(QueryError::BadType);
        }
        Ok(Self {
            parent,
            type_name,
            q,
            limit,
            after,
        })
    }
}

/// One child that the service proposes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Candidate {
    /// The id of the child. Do not encode it (4.1).
    pub id: String,
    /// A short text for the form.
    pub label: String,
    /// True when the route can list children below this child.
    pub has_children: bool,
    /// An opaque text for the position after this child. The caller of the route
    /// gives the cursor of the last child that the PEP asked about as `after`.
    pub cursor: String,
}

/// A page of candidates.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CandidatePage {
    /// The candidates, in the order of the service. The list has at most the number that the PEP asked for.
    pub candidates: Vec<Candidate>,
    /// True when more candidates follow the last one.
    pub more: bool,
}

/// The data of the service: the children of a node.
pub trait OptionsSource {
    /// The children of `parent` with the type `node_type`, after the position `after`.
    /// A node that does not exist has no child. `q` is the search text: the
    /// service chooses its own rules (5.7). Return at most `max` candidates.
    fn children(
        &self,
        parent: &NodePath,
        node_type: &str,
        q: Option<&str>,
        after: Option<&str>,
        max: usize,
    ) -> CandidatePage;
}

impl Pep {
    /// Build the answer of the options route (5.8).
    ///
    /// For each child, the PEP asks the PDP with `context.match` equal to
    /// `subtree`, without `context.usage` (5.6). The question names `action`.
    /// Without `action`, the PEP takes the first action of the document whose
    /// `resource_types` holds the type of the child (5.6). The PEP asks at most
    /// `display_max_questions` questions for one request. At this bound, it
    /// gives the items that it has, and a `next` value (5.6).
    ///
    /// # Errors
    /// Returns [`Refusal::Unavailable`] when the PDP gives no valid answer for a
    /// child (5.6, 10.3). It returns [`Refusal::Internal`] when no action fits the type.
    pub fn options(
        &self,
        who: &Identity,
        query: &OptionsQuery,
        action: Option<&str>,
        source: &dyn OptionsSource,
    ) -> Result<OptionsAnswer, Refusal> {
        let action = match action {
            Some(name) => name.to_owned(),
            None => self
                .document()
                .actions
                .iter()
                .find(|a| a.resource_types.contains(&query.type_name))
                .map(|a| a.name.clone())
                .ok_or_else(|| {
                    Refusal::Internal(format!(
                        "no action of the document lists the type `{}`",
                        query.type_name
                    ))
                })?,
        };
        let page_size = query.limit.map_or(MAX_ITEMS, |l| l.min(MAX_ITEMS));
        let mut questions_left = self.display_max_questions();
        let mut after = query.after.clone();
        let mut last_cursor: Option<String> = None;
        let mut items: Vec<OptionItem> = Vec::new();
        let mut exhausted = false;
        while items.len() < page_size && questions_left > 0 {
            let want = (page_size - items.len()).min(questions_left);
            let page = source.children(
                &query.parent,
                &query.type_name,
                query.q.as_deref(),
                after.as_deref(),
                want,
            );
            let candidates: Vec<&Candidate> = page.candidates.iter().take(want).collect();
            if candidates.is_empty() {
                exhausted = true;
                break;
            }
            let mut permissions = Vec::with_capacity(candidates.len());
            for candidate in &candidates {
                validate_id(&candidate.id).map_err(|e| {
                    Refusal::Internal(format!("the service gave a child with a bad id: {e}"))
                })?;
                permissions.push(Permission::new(
                    action.clone(),
                    query
                        .parent
                        .child(NodeRef::new(&query.type_name, &candidate.id)),
                ));
            }
            let visible = self.display(who, &permissions)?;
            questions_left -= candidates.len();
            for (candidate, seen) in candidates.iter().zip(visible) {
                if seen {
                    items.push(OptionItem {
                        id: candidate.id.clone(),
                        label: candidate.label.clone(),
                        has_children: candidate.has_children,
                    });
                }
                last_cursor = Some(candidate.cursor.clone());
            }
            after = last_cursor.clone();
            if !page.more && candidates.len() == page.candidates.len() {
                exhausted = true;
                break;
            }
        }
        Ok(OptionsAnswer {
            items,
            next: if exhausted { None } else { last_cursor },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::document::ActionDocumentBuilder;

    fn document() -> ActionDocument {
        ActionDocumentBuilder::new("datastore")
            .resource_type("host", "service", "One database server.")
            .resource_type("database", "host", "One database.")
            .resource_type("table", "database", "One table.")
            .action(
                "data.read",
                &["service", "host", "database", "table"],
                "Read data.",
                &[],
            )
            .build()
            .unwrap()
    }

    fn parse(query: &str) -> Result<OptionsQuery, QueryError> {
        OptionsQuery::parse(query, &document())
    }

    #[test]
    fn p_5_7_the_first_level_has_no_parent() {
        let q = parse("type=host").unwrap();
        assert_eq!(q.parent, NodePath::service("datastore"));
        assert_eq!(q.type_name, "host");
        assert_eq!((q.q, q.limit, q.after), (None, None, None));
    }

    #[test]
    fn p_5_7_the_example_of_the_text_is_read() {
        let q = parse("parent=host%3Aprod&type=database&q=test&limit=2").unwrap();
        assert_eq!(q.parent.to_string(), "service:datastore/host:prod");
        assert_eq!(q.q.as_deref(), Some("test"));
        assert_eq!(q.limit, Some(2));
    }

    #[test]
    fn p_5_7_a_parent_with_an_id_that_has_a_slash_is_decoded_one_time_then_per_id() {
        let q = parse("parent=host%3Aprod%2Fdatabase%3Aa%252Fb&type=table").unwrap();
        let nodes = q.parent.nodes();
        assert_eq!(nodes[2].id, "a/b");
    }

    #[test]
    fn p_5_7_a_plus_is_not_a_space() {
        // The value `a+b` has a byte that 5.7 requires to be encoded, so it is not valid.
        assert_eq!(parse("type=host&q=a+b"), Err(QueryError::BadEncoding("q")));
        let q = parse("type=host&q=a%2Bb").unwrap();
        assert_eq!(q.q.as_deref(), Some("a+b"));
    }

    #[test]
    fn p_5_7_the_request_needs_the_type() {
        assert_eq!(parse(""), Err(QueryError::MissingType));
        assert_eq!(parse("limit=5"), Err(QueryError::MissingType));
    }

    #[test]
    fn p_5_7_a_parameter_that_occurs_two_times_is_bad() {
        assert_eq!(
            parse("type=host&type=host"),
            Err(QueryError::Duplicate("type"))
        );
        assert_eq!(
            parse("type=host&limit=2&limit=2"),
            Err(QueryError::Duplicate("limit"))
        );
        // An unknown parameter that occurs two times is ignored.
        assert!(parse("type=host&x=1&x=2").is_ok());
    }

    #[test]
    fn p_5_7_the_limit_is_a_whole_number_from_1() {
        for bad in ["0", "-1", "abc", "1.5", "", "+1", "99999999999999999999999"] {
            assert_eq!(
                parse(&format!("type=host&limit={bad}")),
                Err(QueryError::BadLimit),
                "{bad}"
            );
        }
        assert_eq!(parse("type=host&limit=7").unwrap().limit, Some(7));
    }

    #[test]
    fn p_5_7_the_type_has_the_type_of_the_parent_as_its_parent() {
        assert_eq!(parse("type=database"), Err(QueryError::BadType));
        assert_eq!(
            parse("parent=host%3Aprod&type=host"),
            Err(QueryError::BadType)
        );
        assert_eq!(
            parse("parent=host%3Aprod&type=table"),
            Err(QueryError::BadType)
        );
        assert_eq!(parse("type=nothing"), Err(QueryError::BadType));
        assert_eq!(parse("type=service"), Err(QueryError::BadType));
        assert!(parse("parent=host%3Aprod&type=database").is_ok());
    }

    #[test]
    fn p_5_7_a_bad_percent_escape_is_bad() {
        assert_eq!(
            parse("parent=%zz&type=host"),
            Err(QueryError::BadEncoding("parent"))
        );
        assert_eq!(
            parse("parent=host%3aprod&type=database"),
            Err(QueryError::BadEncoding("parent"))
        );
        assert_eq!(
            parse("parent=host:prod&type=database"),
            Err(QueryError::BadEncoding("parent"))
        );
    }

    #[test]
    fn p_5_7_a_parent_that_does_not_follow_the_document_is_bad() {
        assert_eq!(
            parse("parent=table%3At&type=host"),
            Err(QueryError::BadParent)
        );
        assert_eq!(
            parse("parent=nothing&type=host"),
            Err(QueryError::BadParent)
        );
        assert_eq!(
            parse("parent=host%3Aa%2Ftable%3At&type=host"),
            Err(QueryError::BadParent)
        );
    }
}
