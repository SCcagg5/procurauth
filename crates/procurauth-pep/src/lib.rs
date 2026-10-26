//! The reference PEP library of ProcurAuth.
//!
//! A service that follows the protocol is a PEP (policy enforcement point). This
//! library gives the steps of paragraph 10.0 as a small API. The API does
//! not depend on a web framework. The application gives the headers of a
//! request and it sends the reply that the library returns.
//!
//! # The seven steps of 10.0
//!
//! | Step | What the PEP does | Where |
//! | --- | --- | --- |
//! | 1 | Check the identity token, and send `sub` as the subject. | [`Pep::authenticate`] |
//! | 2 | Refuse a request with no valid token. | [`Refusal::to_http`] |
//! | 3 | Give each use one action and one resource with its chain. | [`operation::Operation`], [`document`] |
//! | 4 | Ask the PDP. Keep answers for `cache_ttl` at most. | [`Pep::decide`], [`Pep::check`], [`Pep::display`] |
//! | 5 | Send `context.usage` for a use of an action that lists a budget. | [`Pep::decide`] |
//! | 6 | Apply each ceiling of `context.limits`. | [`ceilings::Ceilings`] |
//! | 7 | Map each refusal with 10.3. | [`Refusal::to_http`] |
//!
//! # Modules
//!
//! | Module | Content |
//! | --- | --- |
//! | [`config`] | The typed configuration, the documented defaults and the checks. |
//! | [`pep`] | The object [`Pep`], and the types [`Outcome`] and [`Allowed`]. |
//! | [`operation`] | One operation: the use and the other permissions. |
//! | [`document`] | The action document: a builder, a loader and the reply of 5.1. |
//! | [`ceilings`] | The ceilings of an answer, and the way to apply them. |
//! | [`refusal`] | The refusals and their HTTP form (10.3). |
//! | [`options`] | The options route (5.6 to 5.8). |
//! | [`transport`], [`http_client`] | The link to the PDP, and a client for `http`. |
//! | [`metadata`] | The metadata of the PDP and the four members of this protocol. |
//! | [`clock`], [`reply`], [`url`] | Small parts: the clock, the HTTP reply and the URL. |
//! | `mcp` | The MCP binding. It needs the feature `mcp`, which is on by default. |
//!
//! # The link to the PDP needs TLS
//!
//! The PEP must secure the link to the PDP (10.0, step 4). The configuration
//! refuses an `http` URL, unless the flag `allow_insecure_pdp_link` is set. The
//! client of this library, [`http_client::HttpTransport`], has no TLS. For a
//! deployment, implement [`transport::PdpTransport`] with a TLS client.
//!
//! # Rules of the code
//!
//! The library reads no environment variable, no file except the action
//! document that the caller names, and it never writes to a log. It reads the
//! system clock only in [`clock::SystemClock`]. It has no `unsafe` code.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use procurauth_core::jws::KeySet;
//! use procurauth_pep::config::{PdpConfig, PepConfig, Secret};
//! use procurauth_pep::document::ActionDocumentBuilder;
//! use procurauth_pep::http_client::{HttpTransport, HttpTransportConfig};
//! use procurauth_pep::operation::{Operation, node};
//! use procurauth_pep::Pep;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let document = ActionDocumentBuilder::new("notes")
//!     .resource_type("folder", "service", "One folder.")
//!     .action("notes.read", &["service", "folder"], "Read notes.", &[])
//!     .build()
//!     .map_err(|findings| format!("{findings:?}"))?;
//! let mut pdp = PdpConfig::new("https://pdp.example", Secret::new("credential"));
//! pdp.allow_insecure_pdp_link = false;
//! let keys = KeySet::from_jwks_str(r#"{"keys": []}"#).unwrap_or_default();
//! let config = PepConfig::new("notes", "X-Identity-Token", "https://edge.example", keys, 300, 30, pdp);
//! let transport = Arc::new(HttpTransport::new(HttpTransportConfig::from_pdp(&config.pdp)));
//! let pep = Pep::new(config, document, transport).map_err(|e| format!("{e:?}"))?;
//!
//! // For each request: check the token, ask the PDP, apply the ceilings.
//! let headers = [("X-Identity-Token", "eyJ...")];
//! match pep.authenticate(headers) {
//!     Err(refusal) => { /* send refusal.to_http() */ }
//!     Ok(who) => {
//!         let folder = node("notes", &[("folder", "work")])?;
//!         let outcome = pep.decide(&who, &Operation::new("notes.read", folder));
//!         match outcome.into_result() {
//!             Ok(allowed) => { let _ceilings = allowed.ceilings(); /* run the use */ }
//!             Err(refusal) => { /* send refusal.to_http() */ }
//!         }
//!     }
//! }
//! # Ok(())
//! # }
//! ```
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod cache;
pub mod ceilings;
pub mod clock;
pub mod config;
pub mod document;
pub mod http_client;
pub mod identity;
#[cfg(feature = "mcp")]
pub mod mcp;
pub mod metadata;
pub mod operation;
pub mod options;
mod pdp_client;
pub mod pep;
pub mod refusal;
pub mod reply;
pub mod transport;
pub mod url;

pub use identity::Identity;
pub use pep::{Allowed, Granted, Outcome, Pep};
pub use refusal::Refusal;
