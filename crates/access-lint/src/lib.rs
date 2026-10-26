//! `access-lint` checks the files of a ProcurAuth service before the service publishes them.
//!
//! The tool checks an action document (protocol 5.2, 5.3, 6.1, 7.1). It can also check a file
//! of grants against the document, and an answer of the options route (5.6 to 5.8).
//! The binary is thin. The function [`run`] does the work, so a test can call it without a process.
//!
//! Each finding has a severity, a JSON path, the paragraph of the protocol and a short text.
//! An error makes the exit code 1. A warning shows a SHOULD or a harmless input, and it does not.
//! The file `RULES.md` lists each rule with its paragraph.
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

pub mod check;
pub mod http;
pub mod input;
pub mod output;
mod query;
pub mod rules;

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Parser, ValueEnum};

use crate::output::InputResult;
use crate::rules::Scope;

/// The form of the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum Format {
    /// One line for each finding.
    Text,
    /// One JSON document. `schemas/access-lint-output.schema.json` describes it.
    Json,
}

/// Check an action document of ProcurAuth.
///
/// The tool prints one line for each finding: the JSON path, the rule and a short text.
/// A document without error gives exit code 0, and a document with an error gives 1.
/// A usage error, or an input that the tool cannot read, gives 2.
#[derive(Debug, Parser)]
#[command(
    name = "access-lint",
    version = concat!(env!("CARGO_PKG_VERSION"), "\nApache-2.0"),
    override_usage = "access-lint [--format text|json] [--grants FILE] [--options FILE] <document>",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// The form of the output: `text` or `json`.
    #[arg(long, value_enum, default_value_t = Format::Text, value_name = "text|json")]
    pub format: Format,
    /// A file of grants. The tool checks each limit value against the document.
    #[arg(long, value_name = "FILE")]
    pub grants: Option<PathBuf>,
    /// A file with an answer of the options route, and optionally its query.
    #[arg(long, value_name = "FILE")]
    pub options: Option<PathBuf>,
    /// The action document: a file, or an http URL.
    #[arg(value_name = "document")]
    pub document: String,
}

/// Run the tool. The function returns the exit code.
///
/// The results go to `stdout`. The diagnostics go to `stderr`.
/// The code is 0 for no error, 1 for at least one error, and 2 for a usage error or an unreadable input.
pub fn run<I, T>(args: I, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(cli) => cli,
        Err(error) => {
            return match error.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    let _ = write!(stdout, "{error}");
                    0
                }
                _ => {
                    let _ = write!(stderr, "{error}");
                    2
                }
            };
        }
    };
    execute(&cli, stdout, stderr)
}

/// The texts of the inputs, as the tool read them.
struct Texts {
    document: String,
    grants: Option<String>,
    options: Option<String>,
}

/// Read all the inputs. The function names each input that it cannot read.
fn read_inputs(cli: &Cli, stderr: &mut dyn Write) -> Option<Texts> {
    let document = input::read_document(&cli.document, http::DEFAULT_LIMITS);
    let grants = cli.grants.as_deref().map(input::read_file).transpose();
    let options = cli.options.as_deref().map(input::read_file).transpose();
    let mut failed = false;
    for error in [
        document.as_ref().err(),
        grants.as_ref().err(),
        options.as_ref().err(),
    ]
    .into_iter()
    .flatten()
    {
        let _ = writeln!(stderr, "access-lint: {error}");
        failed = true;
    }
    match (document, grants, options) {
        (Ok(document), Ok(grants), Ok(options)) if !failed => Some(Texts {
            document,
            grants,
            options,
        }),
        _ => None,
    }
}

fn execute(cli: &Cli, stdout: &mut dyn Write, stderr: &mut dyn Write) -> u8 {
    let Some(texts) = read_inputs(cli, stderr) else {
        return 2;
    };
    let (document, findings) = check::check_document(&texts.document);
    let mut results = vec![InputResult {
        scope: Scope::Document,
        source: cli.document.clone(),
        findings,
    }];
    if let (Some(path), Some(text)) = (&cli.grants, &texts.grants) {
        results.push(InputResult {
            scope: Scope::Grants,
            source: path.display().to_string(),
            findings: check::check_grants(text, document.as_ref()),
        });
    }
    if let (Some(path), Some(text)) = (&cli.options, &texts.options) {
        results.push(InputResult {
            scope: Scope::Options,
            source: path.display().to_string(),
            findings: check::check_options(text, document.as_ref()),
        });
    }
    let text = match cli.format {
        Format::Text => output::render_text(&results),
        Format::Json => output::render_json(&results),
    };
    let _ = stdout.write_all(text.as_bytes());
    u8::from(!output::passes(&results))
}
