//! The reference edge of ProcurAuth.
//!
//! The edge is a small HTTP reverse proxy. It is the edge of protocol sections 8.3
//! and 9 and of the MCP binding section 6. It reads the text of a key from
//! `Authorization: Bearer`. It asks the PDP for the action `access` on the service.
//! It makes an identity token, and it sends the request to the service in the token
//! header. It removes the text of the key and each copy of the token header that
//! the client sent.
//!
//! The edge is the test subject of the series E of the conformance cases. The crate is
//! a library and a program. The program `reference-edge` reads a configuration file and serves.
//!
//! # Modules
//!
//! | Module | Content |
//! | --- | --- |
//! | [`config`] | The table of keys, the strict reader and the effective configuration. |
//! | [`keys`] | The keys file: the digest of each key text, its subject and its owner. |
//! | [`edge`] | The decision for each request, and the request for the service. |
//! | [`token`] | The identity token and the kept tokens (9.9). |
//! | [`http`] | The HTTP/1.1 layer of the client side. |
//! | [`proxy`] | The link to the service, and the relay of its answer. |
//! | [`server`] | The threads, the listener and the stop. |
//! | [`cli`] | The command line. |
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod cli;
pub mod config;
pub mod edge;
pub mod http;
pub mod keys;
pub mod proxy;
pub mod server;
pub mod token;
