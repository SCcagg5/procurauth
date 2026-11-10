//! The action document of the service (section 5).
//!
//! The service declares its types, its actions and its limits in a document, and it
//! publishes the document at `/.well-known/procurauth/actions` (5.1). The core crate
//! owns the type [`ActionDocument`] and the checks of 5.2, 5.3 and 6.1. This
//! module adds three things: a builder, a loader for a file, and the reply for the
//! route of 5.1.
//!
//! ```
//! use procurauth_pep::document::ActionDocumentBuilder;
//!
//! let document = ActionDocumentBuilder::new("notes")
//!     .resource_type("folder", "service", "One folder.")
//!     .action("notes.read", &["service", "folder"], "Read notes.", &["requests", "max_items"])
//!     .budget("requests", "Requests", "Requests that run.", "request")
//!     .ceiling("max_items", "Most items", "The most items of one read.", "item", 1, 1000)
//!     .build()?;
//! assert!(document.action_lists_budget("notes.read"));
//! # Ok::<(), Vec<procurauth_core::finding::Finding>>(())
//! ```

use std::fs;
use std::io::Read;
use std::path::Path;

use procurauth_core::action_document::analyze_value;
pub use procurauth_core::action_document::{
    Action, ActionDocument, LimitDeclaration, LimitKind, ResourceItem, ResourceType,
};
use procurauth_core::finding::{Finding, JsonPath, Report};
use procurauth_core::path::NodePath;

use crate::reply::HttpReply;

/// The bound on the size of a document file that [`load_file`] reads, in bytes.
/// The reader of 5.3c must accept 64 KiB, and a service stays within it.
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;

/// A builder for the action document. [`ActionDocumentBuilder::build`] checks
/// the document as 5.2, 5.3 and 6.1 say.
#[derive(Debug)]
pub struct ActionDocumentBuilder {
    document: ActionDocument,
    problems: Report,
}

impl ActionDocumentBuilder {
    /// A builder for the service with this id.
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            document: ActionDocument {
                server: server.into(),
                resource_types: Vec::new(),
                actions: Vec::new(),
                resources: Vec::new(),
                limits: Vec::new(),
            },
            problems: Report::new(),
        }
    }

    /// Declare a type. The parent is `service` or a type that the document declares (5.2).
    #[must_use]
    pub fn resource_type(mut self, name: &str, parent: &str, description: &str) -> Self {
        self.document.resource_types.push(ResourceType {
            name: name.to_owned(),
            parent: parent.to_owned(),
            description: description.to_owned(),
        });
        self
    }

    /// Declare an action, with the types where a grant is valid and the names of its limits (5.2, 6.2).
    #[must_use]
    pub fn action(
        mut self,
        name: &str,
        resource_types: &[&str],
        description: &str,
        limits: &[&str],
    ) -> Self {
        self.document.actions.push(Action {
            name: name.to_owned(),
            resource_types: resource_types.iter().map(|s| (*s).to_owned()).collect(),
            description: description.to_owned(),
            limits: limits.iter().map(|s| (*s).to_owned()).collect(),
        });
        self
    }

    /// Declare a budget (6.1).
    #[must_use]
    pub fn budget(mut self, name: &str, label: &str, description: &str, unit: &str) -> Self {
        self.document.limits.push(LimitDeclaration {
            name: name.to_owned(),
            label: label.to_owned(),
            description: description.to_owned(),
            unit: unit.to_owned(),
            kind: LimitKind::Budget,
            min: None,
            max: None,
        });
        self
    }

    /// Declare a ceiling with its smallest and largest value (6.1, 7.1).
    #[must_use]
    pub fn ceiling(
        mut self,
        name: &str,
        label: &str,
        description: &str,
        unit: &str,
        min: u64,
        max: u64,
    ) -> Self {
        self.document.limits.push(LimitDeclaration {
            name: name.to_owned(),
            label: label.to_owned(),
            description: description.to_owned(),
            unit: unit.to_owned(),
            kind: LimitKind::Ceiling,
            min: Some(min),
            max: Some(max),
        });
        self
    }

    /// Name a node of the service, for example `host:prod` (5.2). The path does not hold the service.
    #[must_use]
    pub fn resource(mut self, path: &str, label: Option<&str>) -> Self {
        match NodePath::parse_below_service(path) {
            Ok(nodes) => self.document.resources.push(ResourceItem {
                nodes,
                label: label.map(str::to_owned),
                actions: None,
            }),
            Err(error) => self.problems.error(
                &JsonPath::root().key("resources"),
                "5.2",
                "bad_path",
                format!("The path {path:?} is not valid: {error}."),
            ),
        }
        self
    }

    /// Check the document and return it.
    ///
    /// # Errors
    /// Returns every error of 5.2, 5.3 and 6.1.
    pub fn build(self) -> Result<ActionDocument, Vec<Finding>> {
        let Self {
            document,
            mut problems,
        } = self;
        match check(&document) {
            Ok(checked) if !problems.has_errors() => Ok(checked),
            Ok(_) => Err(problems.into_findings()),
            Err(findings) => {
                problems.extend(findings);
                Err(problems.into_findings())
            }
        }
    }
}

/// Check a document that the caller built by hand. The function writes the
/// document as JSON. Then it reads the JSON with the core reader. Thus all
/// the rules of 5.2, 5.3 and 6.1 apply.
///
/// # Errors
/// Returns every error of the document.
pub fn check(document: &ActionDocument) -> Result<ActionDocument, Vec<Finding>> {
    let analysis = analyze_value(&document.to_value());
    match analysis.document {
        Some(checked) => Ok(checked),
        None => Err(analysis.report.into_findings()),
    }
}

/// Why a document file cannot be loaded.
#[derive(Debug)]
pub enum LoadError {
    /// The file cannot be read, or it is larger than [`MAX_FILE_BYTES`].
    File(String),
    /// The document is not valid. The list has every finding.
    Invalid(Vec<Finding>),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::File(text) => f.write_str(text),
            Self::Invalid(findings) => {
                for (index, finding) in findings.iter().enumerate() {
                    if index > 0 {
                        f.write_str("\n")?;
                    }
                    write!(f, "{finding}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for LoadError {}

/// Load and check the action document from a file.
///
/// # Errors
/// Returns [`LoadError::File`] when the file is absent, unreadable, too large
/// or not UTF-8. Returns [`LoadError::Invalid`] when the document is bad.
pub fn load_file(path: &Path) -> Result<ActionDocument, LoadError> {
    let name = path.display();
    let file = fs::File::open(path)
        .map_err(|e| LoadError::File(format!("Cannot read the file {name}: {e}.")))?;
    let mut text = String::new();
    let mut limited = file.take(MAX_FILE_BYTES + 1);
    limited
        .read_to_string(&mut text)
        .map_err(|e| LoadError::File(format!("Cannot read the file {name}: {e}.")))?;
    if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(LoadError::File(format!(
            "The file {name} is larger than {MAX_FILE_BYTES} bytes."
        )));
    }
    ActionDocument::parse_str(&text).map_err(LoadError::Invalid)
}

/// The document, ready for the route of 5.1.
#[derive(Clone, Debug)]
pub struct ServedDocument {
    body: Vec<u8>,
}

impl ServedDocument {
    /// Check the document and write its body one time.
    ///
    /// # Errors
    /// Returns every error of the document.
    pub fn new(document: &ActionDocument) -> Result<Self, Vec<Finding>> {
        let checked = check(document)?;
        Ok(Self {
            body: checked.to_value().to_string().into_bytes(),
        })
    }

    /// The body of the reply: the document as compact JSON.
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// The reply for a request of the route of 5.1 with the method `GET` or
    /// `HEAD`. Any other method gets 405 with the header `Allow`.
    pub fn reply(&self, method: &str) -> HttpReply {
        let ok = HttpReply {
            status: 200,
            headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
            body: Vec::new(),
        };
        match method {
            "GET" => HttpReply {
                body: self.body.clone(),
                ..ok
            },
            "HEAD" => ok,
            _ => HttpReply::empty(405).with_header("Allow", "GET, HEAD"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn builder() -> ActionDocumentBuilder {
        ActionDocumentBuilder::new("datastore")
            .resource_type("host", "service", "One database server.")
            .resource_type("database", "host", "One database.")
            .action(
                "data.read",
                &["service", "host", "database"],
                "Read data.",
                &["requests", "max_rows"],
            )
            .budget("requests", "Requests", "Requests that run.", "request")
            .ceiling(
                "max_rows",
                "Most rows",
                "The most rows that one read gives.",
                "row",
                1,
                1_000_000,
            )
            .resource("host:prod", Some("Production"))
    }

    #[test]
    fn p_5_2_the_builder_makes_a_good_document() {
        let document = builder().build().unwrap();
        assert_eq!(document.server, "datastore");
        assert_eq!(document.actions.len(), 1);
        assert!(document.action_lists_budget("data.read"));
        assert_eq!(document.resources.len(), 1);
    }

    #[test]
    fn p_5_3_the_builder_returns_every_error_of_the_core() {
        let findings = builder()
            .action("data.read", &["nowhere"], "Again.", &["undeclared"])
            .resource("bad path", None)
            .build()
            .unwrap_err();
        let rules: Vec<_> = findings.iter().map(|f| f.code).collect();
        assert!(rules.len() >= 3, "{findings:?}");
        assert!(findings.iter().any(|f| f.code == "bad_path"));
    }

    #[test]
    fn p_6_1_a_budget_with_a_ceiling_range_is_not_possible_and_a_ceiling_range_is_checked() {
        let findings = builder()
            .ceiling("max_time", "Time", "Seconds.", "second", 10, 5)
            .build()
            .unwrap_err();
        assert!(!findings.is_empty());
    }

    #[test]
    fn p_5_1_the_reply_for_get_has_the_document_and_the_content_type() {
        let served = ServedDocument::new(&builder().build().unwrap()).unwrap();
        let reply = served.reply("GET");
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("content-type"), Some("application/json"));
        let value: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(value["server"], "datastore");
        // The reader of the core accepts the body that the service publishes.
        assert!(ActionDocument::parse_str(std::str::from_utf8(&reply.body).unwrap()).is_ok());
    }

    #[test]
    fn p_5_1_head_has_no_body_and_other_methods_get_405() {
        let served = ServedDocument::new(&builder().build().unwrap()).unwrap();
        assert!(served.reply("HEAD").body.is_empty());
        assert_eq!(served.reply("HEAD").status, 200);
        let reply = served.reply("POST");
        assert_eq!(reply.status, 405);
        assert_eq!(reply.header("allow"), Some("GET, HEAD"));
    }

    #[test]
    fn p_5_3_a_file_is_read_and_checked() {
        let dir = std::env::temp_dir().join(format!("pep-doc-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let good = dir.join("good.json");
        let text = builder().build().unwrap().to_value().to_string();
        fs::File::create(&good)
            .unwrap()
            .write_all(text.as_bytes())
            .unwrap();
        assert!(load_file(&good).is_ok());
        let bad = dir.join("bad.json");
        fs::File::create(&bad)
            .unwrap()
            .write_all(br#"{"server": "x", "server": "y"}"#)
            .unwrap();
        assert!(matches!(load_file(&bad), Err(LoadError::Invalid(_))));
        assert!(matches!(
            load_file(&dir.join("absent.json")),
            Err(LoadError::File(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }
}
