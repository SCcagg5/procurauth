//! The library of the program `keycheck`.
//!
//! `keycheck` reads the text of a key on the standard input. It checks the text
//! against a key format document (protocol 3.8), and it prints the verdict.
//! A good text gets its SHA-256 digest and a hint of at most 4 characters.
//! The program never prints the text of the key. It never writes the text to a
//! log, and no error message holds it.
//!
//! The function [`run`] does all the work. It takes the arguments and the
//! streams as values, so that a test can call it without a process. It reads
//! no environment variable. The binary only calls it.
//!
//! The exit codes are in [`Exit`]. The JSON output has the schema
//! `schemas/keycheck-output.schema.json`.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod cli;
mod format_file;
mod input;
mod report;

use std::ffi::OsString;
use std::io::{Read, Write};
use std::process::ExitCode;

use clap::Parser;
use procurauth_core::key_format::{KeyFormat, KeyFormatError, KeyInfo};

pub use cli::{Cli, OutputFormat, VERSION_TEXT};
pub use format_file::MAX_FORMAT_FILE_BYTES;
pub use input::{KeyText, MAX_INPUT_BYTES, read_key, strip_line_end};
pub use report::{render_json, render_text};

/// The exit code of the program.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    /// 0: the text is a good key, or the program shows help or the version.
    Clean,
    /// 1: the text is not a key of the format.
    Findings,
    /// 2: the command line is not valid, or an input is not readable.
    Usage,
}

impl Exit {
    /// The number of the exit code.
    pub fn code(self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Findings => 1,
            Self::Usage => 2,
        }
    }
}

impl From<Exit> for ExitCode {
    fn from(exit: Exit) -> Self {
        Self::from(exit.code())
    }
}

/// The verdict for a text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The text has the format. The value holds the digest and the hint.
    Good(KeyInfo),
    /// The text does not have the format. The value gives the first cause.
    Bad(KeyFormatError),
}

/// Check a text against a format. The verdict never holds the text.
pub fn judge(format: &KeyFormat, text: &KeyText) -> Verdict {
    match format.check(text.as_str()) {
        Ok(info) => Verdict::Good(info),
        Err(error) => Verdict::Bad(error),
    }
}

/// Run the program.
///
/// `args` is the command line, with the name of the program first. The text of
/// the key comes from `stdin`. The result goes to `stdout`, and the diagnostics
/// go to `stderr`. The function returns the exit code.
pub fn run<I, A, R, O, E>(args: I, stdin: R, stdout: &mut O, stderr: &mut E) -> Exit
where
    I: IntoIterator<Item = A>,
    A: Into<OsString> + Clone,
    R: Read,
    O: Write,
    E: Write,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => return cli::handle_error(&error, stdout, stderr),
    };
    let format = match format_file::load(&cli.format_file) {
        Ok(format) => format,
        Err(lines) => return fail(stderr, &lines),
    };
    let text = match read_key(stdin) {
        Ok(text) => text,
        Err(error) => return fail(stderr, &[error.to_string()]),
    };
    let verdict = judge(&format, &text);
    let rendered = match cli.format {
        OutputFormat::Text => render_text(&verdict),
        OutputFormat::Json => render_json(&verdict),
    };
    if stdout.write_all(rendered.as_bytes()).is_err() || stdout.flush().is_err() {
        return fail(stderr, &["Cannot write to the standard output.".to_owned()]);
    }
    match verdict {
        Verdict::Good(_) => Exit::Clean,
        Verdict::Bad(_) => Exit::Findings,
    }
}

/// Write the diagnostic lines to `stderr`, and give the exit code 2.
fn fail<E: Write>(stderr: &mut E, lines: &[String]) -> Exit {
    for line in lines {
        // A failed write to stderr has no better place to go.
        let _ = writeln!(stderr, "keycheck: {line}");
    }
    Exit::Usage
}
