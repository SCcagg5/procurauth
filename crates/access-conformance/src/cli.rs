//! The command line of `access-conformance`, as clap types.
//!
//! The doc comments of the fields are the text of `--help`. The program reads
//! no environment variable. A flag that occurs two times is an error.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

/// The words that `--help` shows after the usage line.
const AFTER_HELP: &str = "\
Exit codes: 0 each case that ran passed, 1 at least one case failed, 2 usage error, bad profile or unreachable target.
A skipped case is not a failure. A failed case of a SHOULD rule is a warning and does not change the exit code.
The licence is Apache-2.0.";

/// The implementation under test.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum RoleArg {
    /// A service: the series U.
    Pep,
    /// A decision point: the series D.
    Pdp,
    /// An edge: the series E.
    Edge,
}

/// The series of the cases.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum SeriesArg {
    /// The cases for a PEP.
    #[value(name = "U")]
    U,
    /// The cases for a PDP.
    #[value(name = "D")]
    D,
    /// The cases for an edge.
    #[value(name = "E")]
    E,
}

/// The form of the result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum Format {
    /// One line for each case.
    Text,
    /// One JSON document.
    Json,
}

/// Run the conformance cases of ProcurAuth against a PEP, a PDP or an edge.
///
/// The runner sends the requests of the cases to the target. For a PEP, it acts
/// as the edge and as the PDP. For an edge, it acts as the client, as the
/// service behind the edge and as the PDP. The profile gives what the runner
/// needs: the operations, the keys and the listen addresses.
#[derive(Debug, Parser)]
#[command(
    name = "access-conformance",
    version = concat!(env!("CARGO_PKG_VERSION"), "\nApache-2.0"),
    after_help = AFTER_HELP,
    disable_help_subcommand = true,
    arg_required_else_help = true
)]
pub(crate) struct Cli {
    /// The implementation under test.
    #[arg(long, value_enum)]
    pub(crate) role: RoleArg,

    /// The profile of the target, as one JSON file.
    #[arg(long, value_name = "FILE")]
    pub(crate) profile: PathBuf,

    /// The URL of the target, for example http://127.0.0.1:8000. A PDP can run with no URL when the profile starts fake-pdp.
    #[arg(long, value_name = "URL")]
    pub(crate) url: Option<String>,

    /// Run only these cases. Give ids with commas, for example U01,U05.
    #[arg(long, value_name = "ID,ID,...", value_delimiter = ',')]
    pub(crate) cases: Vec<String>,

    /// Run only this series. It must fit the role.
    #[arg(long, value_enum)]
    pub(crate) series: Option<SeriesArg>,

    /// The form of the result.
    #[arg(long, value_enum, default_value_t = Format::Text)]
    pub(crate) format: Format,

    /// Read the cases from this directory, in the layout of the directory conformance/. Without it, the program uses its own copy.
    #[arg(long, value_name = "DIR")]
    pub(crate) cases_dir: Option<PathBuf>,

    /// Check the profile and the files, write the values that apply, and stop.
    #[arg(long)]
    pub(crate) print_config: bool,
}
