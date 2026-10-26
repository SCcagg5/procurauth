//! The reference service of ProcurAuth.
//!
//! The service is the test subject of the series U of the conformance cases. It
//! is the `datastore` example of protocol section 13, with a small HTTP/1.1
//! layer. It uses the library `procurauth-pep` for the seven steps of
//! paragraph 10.0. The crate is a library and a program. The program
//! `reference-service` reads a configuration file and serves.
//!
//! # Modules
//!
//! | Module | Content |
//! | --- | --- |
//! | [`config`] | The table of keys, the strict reader and the effective configuration. |
//! | [`http`] | The HTTP/1.1 layer. |
//! | [`app`] | The routes. |
//! | [`data`] | The data of the service, in memory. |
//! | [`document`] | The action document. |
//! | `mcp_app` | The MCP endpoint. It needs the feature `mcp`. |
//! | [`service`] | The threads, the listener and the stop. |
//!
//! The file `PROFILE.md` of the crate gives the route of each operation of the
//! conformance cases.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod app;
pub mod cli;
pub mod config;
pub mod data;
pub mod document;
pub mod http;
#[cfg(feature = "mcp")]
pub mod mcp_app;
pub mod service;
