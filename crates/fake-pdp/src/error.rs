//! The errors of the library.
//!
//! Each message names the key, the expected type or range, and the value
//! that the program found. A configuration error stops the program before
//! the port opens.

use std::fmt;
use std::io;

use procurauth_core::finding::Finding;

/// The clock cannot take a time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClockError {
    /// The time in seconds is too large for a clock in milliseconds.
    OutOfRange {
        /// The value that the caller gave, in seconds.
        seconds: u64,
    },
}

impl fmt::Display for ClockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange { seconds } => write!(
                f,
                "Clock time: expected a whole number of seconds from 0 to {}, found {seconds}.",
                crate::clock::MAX_SECONDS
            ),
        }
    }
}

impl std::error::Error for ClockError {}

/// Why the server does not start.
#[derive(Debug)]
pub enum StartError {
    /// The data has errors. The list has every finding, each with its path.
    Data(Vec<Finding>),
    /// A value is bad, or two keys contradict each other.
    Config(String),
    /// The server cannot open its port.
    Bind {
        /// The address that the server tried to open.
        address: String,
        /// The cause.
        source: io::Error,
    },
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Data(findings) => {
                write!(f, "The data has {} finding(s).", findings.len())
            }
            Self::Config(message) => write!(f, "{message}"),
            Self::Bind { address, source } => {
                write!(f, "Cannot listen on {address}: {source}.")
            }
        }
    }
}

impl std::error::Error for StartError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bind { source, .. } => Some(source),
            _ => None,
        }
    }
}
