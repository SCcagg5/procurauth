//! Shared core of the ProcurAuth tools.
//!
//! This crate is a library. It has no command line, no network code and no
//! clock. Each tool of the repository uses it, and so can a PEP library. The
//! crate reads no environment variable. A function that needs the time takes
//! it as an argument.
//!
//! # Modules
//!
//! | Module | Protocol | Content |
//! | --- | --- | --- |
//! | [`json`] | | A strict JSON reader that rejects a duplicate member. |
//! | [`finding`], [`read`] | | Findings with a JSON path, and the reader of typed members. |
//! | [`names`], [`path`] | 4.1, 5.2 | Names, ids, percent-encoding, nodes and paths. |
//! | [`action_document`] | 5, 6.1 | The action document, with every error and its path. |
//! | [`options`] | 5.6 to 5.8 | The answer of the options route. |
//! | [`limits`], [`grants`] | 6 to 8 | Limit values, windows, grants and the lowest value. |
//! | [`subject`] | 3 | The form of a subject id. |
//! | [`coverage`] | 3.5, 4.3, 4.4 | Coverage and the decision for a key, as pure functions. |
//! | [`authzen`] | 4.1, 6.4, 11 | The AuthZEN messages, the chain and the members of the context. |
//! | [`jws`], [`identity`] | 9 | Keys, signatures, claims and the checks of the identity token. |
//! | [`key_format`] | 3.8 | The text format of a key, as data. |
//! | [`directory`] | | The data of the test PDP. |
//!
//! # Rules of the readers
//!
//! Each reader parses a document one time into a typed structure. The reader
//! does not change a value to make it fit. It returns every finding, and
//! each finding names the JSON path, the rule and the value. A finding is an
//! error or a warning. A document is good when it has no error.
//!
//! ```
//! use procurauth_core::action_document::analyze_str;
//!
//! let analysis = analyze_str(r#"{"server": "s", "resource_types": [], "actions": []}"#);
//! assert!(analysis.document.is_some());
//!
//! let analysis = analyze_str(r#"{"server": "s", "server": "t"}"#);
//! assert!(analysis.document.is_none());
//! ```
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod action_document;
pub mod authzen;
pub mod coverage;
pub mod directory;
pub mod finding;
pub mod grants;
pub mod identity;
pub mod json;
pub mod jws;
pub mod key_format;
pub mod limits;
pub mod names;
pub mod options;
pub mod path;
pub mod read;
pub mod subject;
