//! The library of the tool `access-token`.
//!
//! The tool makes and checks the identity tokens of ProcurAuth (protocol
//! section 9). The function [`run`] does all the work. The program `main`
//! only gives it the arguments, the streams and the clock. Thus a test can
//! call [`run`] with no process.
//!
//! # Modules
//!
//! | Module | Content |
//! | --- | --- |
//! | [`cli`] | The command line, as clap types. |
//! | [`config`] | The strict reader of the configuration of a service. |
//! | [`make`] | The making of good and bad tokens. |
//! | [`check`] | The check of a token and the two forms of the result. |
//! | [`files`] | The reading of input files, with a size bound. |
//!
//! # Rules
//!
//! The program reads no environment variable. It reads the system clock only
//! when the flag `--now` is absent. A private key comes only from a file. No
//! output holds a private key.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::ffi::OsString;
use std::io::{Read, Write};

use clap::Parser as _;
use clap::error::ErrorKind;

pub mod check;
pub mod cli;
pub mod config;
pub mod files;
pub mod make;

/// The exit code when the work finds nothing.
pub const EXIT_OK: u8 = 0;
/// The exit code when the work has at least one finding.
pub const EXIT_FINDING: u8 = 1;
/// The exit code for a usage error or an input that cannot be read.
pub const EXIT_USAGE: u8 = 2;

/// An error that stops the program with the exit code 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    lines: Vec<String>,
}

impl Fault {
    /// A fault with one message.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            lines: vec![message.into()],
        }
    }

    /// A fault with several messages.
    pub fn many(lines: Vec<String>) -> Self {
        Self { lines }
    }

    /// The messages.
    pub fn lines(&self) -> &[String] {
        &self.lines
    }
}

/// The streams and the clock that [`run`] uses.
pub struct Io<'a> {
    /// The standard input.
    pub stdin: &'a mut dyn Read,
    /// The standard output: the results.
    pub stdout: &'a mut dyn Write,
    /// The standard error: the diagnostics.
    pub stderr: &'a mut dyn Write,
    /// The clock, in seconds since the Unix epoch. `check` calls it only without `--now`.
    pub clock: &'a dyn Fn() -> Result<u64, String>,
}

/// Run the tool with the arguments and return the exit code.
///
/// The first argument is the name of the program.
pub fn run<I, T>(arguments: I, io: &mut Io<'_>) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match cli::Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            let text = error.to_string();
            return match error.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    finish(io.stdout.write_all(text.as_bytes()), io.stderr, EXIT_OK)
                }
                _ => finish(io.stderr.write_all(text.as_bytes()), io.stderr, EXIT_USAGE),
            };
        }
    };
    let outcome = match &cli.command {
        cli::Command::Make(args) => make::run_make(args, io),
        cli::Command::Check(args) => check::run_check(args, io),
    };
    match outcome {
        Ok(code) => code,
        Err(fault) => {
            let mut text = String::new();
            for line in fault.lines() {
                text.push_str("error: ");
                text.push_str(line);
                text.push('\n');
            }
            finish(io.stderr.write_all(text.as_bytes()), io.stderr, EXIT_USAGE)
        }
    }
}

/// Turn the result of a write into an exit code. A failed write gives the code 2.
fn finish(written: std::io::Result<()>, stderr: &mut dyn Write, code: u8) -> u8 {
    match written {
        Ok(()) => code,
        Err(error) => {
            let _ = writeln!(stderr, "error: Cannot write the result: {error}.");
            EXIT_USAGE
        }
    }
}

/// Write a text to a stream, and report a failure as a fault.
///
/// # Errors
/// Returns a fault when the write fails.
pub(crate) fn emit(stream: &mut dyn Write, text: &str) -> Result<(), Fault> {
    stream
        .write_all(text.as_bytes())
        .map_err(|error| Fault::new(format!("Cannot write the result: {error}.")))
}
