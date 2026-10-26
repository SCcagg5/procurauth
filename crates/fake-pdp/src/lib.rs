//! A test decision point (PDP) for ProcurAuth.
//!
//! The crate answers like a real ProcurAuth PDP, from fixed data. A service
//! (a PEP) and the conformance suite can then run without the real backend.
//! The binary `fake-pdp` is a thin wrapper. Other tools start the server in
//! the same process through this library.
//!
//! # Modules
//!
//! | Module | Content |
//! | --- | --- |
//! | [`server`] | [`Server`] and [`RunningServer`]: build, bind, serve and stop. |
//! | [`config`] | The options, the defaults and the table of keys. |
//! | [`pdp`] | The decisions, from the directory and the counters. |
//! | [`counters`] | The counters with fixed windows. |
//! | [`clock`] | A clock that a test can move. |
//! | [`faults`] | The failures that the server makes on purpose. |
//! | [`log`] | The text log and the entries in memory. |
//! | [`error`] | The errors. |
//!
//! # Start a server in a test
//!
//! ```
//! use fake_pdp::{Options, Server};
//!
//! let data = serde_json::json!({"services": [], "subjects": [], "clock": {"now": 1792569648}});
//! let server = Server::from_value(&data, Options::default()).unwrap();
//! let running = server.start("127.0.0.1:0").unwrap();
//! assert_ne!(running.local_addr().port(), 0);
//! running.clock().advance(60).unwrap();
//! running.shutdown();
//! ```
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod admin;
pub mod clock;
pub mod config;
pub mod counters;
pub mod error;
pub mod faults;
mod http;
pub mod log;
pub mod pdp;
pub mod server;
mod service;

pub use clock::Clock;
pub use config::{ConfigLine, Credential, Options, Settings};
pub use error::{ClockError, StartError};
pub use faults::{Fault, FaultKind};
pub use server::{RunningServer, Server};
