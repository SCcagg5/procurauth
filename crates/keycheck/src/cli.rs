//! The command line of `keycheck`.

use std::io::Write;
use std::path::PathBuf;

use clap::error::ErrorKind;
use clap::{Parser, ValueEnum};

use crate::Exit;

/// The text of `--version`: the version, a line end and the licence.
pub const VERSION_TEXT: &str = concat!(env!("CARGO_PKG_VERSION"), "\nApache-2.0");

/// The form of the output.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    /// Lines of text. This is the default.
    Text,
    /// One JSON object on one line.
    Json,
}

/// Check the text of a key against a key format.
///
/// The text of the key comes from the standard input, and never from an
/// argument. The program prints the verdict on the standard output. For a good
/// key it prints the SHA-256 digest and a hint of at most 4 characters.
/// The program never prints the text of the key.
#[derive(Debug, Parser)]
#[command(
    name = "keycheck",
    version = VERSION_TEXT,
    long_version = VERSION_TEXT,
    override_usage = "keycheck [--format text|json] <format-file>",
    after_help = "Exit codes: 0 for a good key, 1 for a bad key, 2 for a usage error or an input that the program cannot read.",
    disable_help_subcommand = true
)]
pub struct Cli {
    /// The form of the output.
    #[arg(long, value_enum, default_value_t = OutputFormat::Text, value_name = "text|json")]
    pub format: OutputFormat,

    /// The file of the key format: a JSON document with `prefix`, `length`, `alphabet` and `checksum`.
    #[arg(value_name = "format-file")]
    pub format_file: PathBuf,
}

/// Show the help or the version, or give a usage error. The text of an
/// argument never goes to the output, because a user can give a key by mistake.
pub(crate) fn handle_error<O: Write, E: Write>(
    error: &clap::Error,
    stdout: &mut O,
    stderr: &mut E,
) -> Exit {
    let shown = match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let text = error.render().to_string();
            let _ = stdout.write_all(text.as_bytes());
            return Exit::Clean;
        }
        ErrorKind::MissingRequiredArgument => {
            "The command line has no format file. Run `keycheck --help`."
        }
        ErrorKind::UnknownArgument => {
            "The command line has an argument that the program does not know. The program does not show it, because it can be a key. Run `keycheck --help`."
        }
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            "The value of `--format` is not valid. Expected `text` or `json`."
        }
        ErrorKind::ArgumentConflict => {
            "An argument occurs two times. The program accepts each argument one time."
        }
        ErrorKind::InvalidUtf8 => "An argument is not UTF-8 text.",
        _ => "The command line is not valid. Run `keycheck --help`.",
    };
    let _ = writeln!(stderr, "keycheck: usage error: {shown}");
    Exit::Usage
}
