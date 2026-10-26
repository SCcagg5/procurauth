//! The library of the tool `access-conformance`.
//!
//! The tool runs the conformance cases of ProcurAuth against a PEP, a PDP or
//! an edge. The function [`run`] does all the work. The program `main` only
//! gives it the arguments, the streams and the clock. Thus a test can call
//! [`run`] with no process.
//!
//! # Modules
//!
//! | Module | Content |
//! | --- | --- |
//! | `cli` | The command line, as clap types. |
//! | `model` | The typed model of a case. |
//! | `catalog` | The cases and the directories that the program holds. |
//! | `profile` | The strict reader of the profile of the target. |
//! | `vars` | The variables and the matchers. |
//! | `http` | A small HTTP/1.1 client and server on the standard library. |
//! | `testpdp`, `upstream` | The test listeners: the scripted PDP and the service behind an edge. |
//! | `tokens` | The identity tokens: make them for a PEP, check them for an edge. |
//! | `ops` | The operations of the data model, as requests. |
//! | `check` | The check of the result of a step. |
//! | `exec` | The run of a case. |
//! | `report` | The text form and the JSON form of the result. |
//!
//! # Rules
//!
//! The program reads no environment variable. It reads the system clock only
//! to make tokens. A secret comes only from a file that the profile names. No
//! output holds a secret.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::ffi::OsString;
use std::io::Write;
use std::path::Path;

use clap::Parser as _;
use clap::error::ErrorKind;

mod catalog;
mod check;
mod cli;
mod exec;
mod http;
mod model;
mod ops;
mod pdpcheck;
mod profile;
mod reference;
mod report;
mod setup;
mod testpdp;
mod tokens;
mod upstream;
mod vars;

use catalog::Catalog;
use cli::{Cli, Format, RoleArg, SeriesArg};
use model::{Case, Role};
use profile::Profile;

/// The exit code when each case that ran passed.
pub const EXIT_OK: u8 = 0;
/// The exit code when at least one case failed.
pub const EXIT_FAILED: u8 = 1;
/// The exit code for a usage error, a bad profile or a target that is not reachable.
pub const EXIT_USAGE: u8 = 2;

/// The largest profile that the program reads.
const MAX_PROFILE_BYTES: u64 = 1024 * 1024;

/// The streams and the clock that [`run`] uses.
pub struct Io<'a> {
    /// The standard output: the results.
    pub stdout: &'a mut dyn Write,
    /// The standard error: the diagnostics.
    pub stderr: &'a mut dyn Write,
    /// The clock, in seconds since the Unix epoch. The program uses it to make tokens.
    pub clock: &'a dyn Fn() -> u64,
}

/// The table of keys as a Markdown table: the options and the keys of the profile.
/// The README of the crate holds the same text, and a test compares the two.
pub fn reference_table() -> String {
    reference::reference_table()
}

/// An error that stops the program with the exit code 2.
struct Fault(Vec<String>);

impl From<String> for Fault {
    fn from(message: String) -> Self {
        Self(vec![message])
    }
}

impl From<Vec<String>> for Fault {
    fn from(messages: Vec<String>) -> Self {
        Self(messages)
    }
}

/// Run the tool with the arguments and return the exit code.
///
/// The first argument is the name of the program.
pub fn run<I, T>(arguments: I, io: &mut Io<'_>) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(arguments) {
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
    match execute(&cli, io) {
        Ok(code) => code,
        Err(Fault(lines)) => {
            let mut text = String::new();
            for line in lines {
                text.push_str("error: ");
                text.push_str(&line);
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

fn role_of(arg: RoleArg) -> Role {
    match arg {
        RoleArg::Pep => Role::Pep,
        RoleArg::Pdp => Role::Pdp,
        RoleArg::Edge => Role::Edge,
    }
}

/// Check that the options fit each other and the role. Return the target.
fn check_options(
    cli: &Cli,
    role: Role,
    profile: &Profile,
) -> Result<Option<http::Authority>, Fault> {
    if let Some(series) = cli.series {
        let letter = match series {
            SeriesArg::U => 'U',
            SeriesArg::D => 'D',
            SeriesArg::E => 'E',
        };
        if letter != role.series() {
            return Err(format!(
                "Options `--series` and `--role` contradict each other: expected the series {} for the role {}, found the series {letter}.",
                role.series(),
                role.name()
            )
            .into());
        }
    }
    let target = match &cli.url {
        Some(text) => Some(setup::parse_target(text)?),
        None => None,
    };
    match role {
        Role::Pep | Role::Edge => {
            if target.is_none() {
                return Err(format!(
                    "Option `--url` is absent, and the role {} needs it.",
                    role.name()
                )
                .into());
            }
        }
        Role::Pdp => {
            let spawn = profile.pdp.as_ref().is_some_and(|p| p.spawn_fake_pdp);
            if spawn && target.is_some() {
                return Err("Option `--url` and the profile key `pdp.spawn_fake_pdp` contradict each other: give a URL, or let the runner start fake-pdp, but not both.".to_owned().into());
            }
            if !spawn && target.is_none() {
                return Err("Option `--url` is absent, and the profile key `pdp.spawn_fake_pdp` is not true: give a URL, or set the key to true.".to_owned().into());
            }
        }
    }
    Ok(target)
}

/// Read the cases that the options select.
fn select<'a>(catalog: &'a Catalog, cli: &Cli, role: Role) -> Result<Vec<&'a Case>, Fault> {
    let all = catalog.cases_of(role);
    if cli.cases.is_empty() {
        return Ok(all);
    }
    let mut chosen: Vec<&Case> = Vec::new();
    for id in &cli.cases {
        let Some(case) = catalog.case(id) else {
            return Err(
                format!("Option `--cases`: expected the id of a case, found \"{id}\".").into(),
            );
        };
        if case.role != role {
            return Err(format!(
                "Option `--cases`: the case {id} is for the role {}, and the run has the role {}.",
                case.role.name(),
                role.name()
            )
            .into());
        }
        if chosen.iter().any(|c| c.id == *id) {
            return Err(format!("Option `--cases`: the id \"{id}\" occurs two times.").into());
        }
        chosen.push(case);
    }
    // Keep the order of the data, so that the output does not depend on the order of the options.
    Ok(all
        .into_iter()
        .filter(|c| chosen.iter().any(|x| x.id == c.id))
        .collect())
}

fn read_profile(path: &Path) -> Result<Profile, Fault> {
    let meta = std::fs::metadata(path).map_err(|e| {
        format!(
            "Option `--profile`: cannot read the file `{}`: {e}.",
            path.display()
        )
    })?;
    if meta.len() > MAX_PROFILE_BYTES {
        return Err(format!(
            "Option `--profile`: expected a file of {MAX_PROFILE_BYTES} bytes at most, found {} bytes in `{}`.",
            meta.len(),
            path.display()
        )
        .into());
    }
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "Option `--profile`: cannot read the file `{}` as UTF-8 text: {e}.",
            path.display()
        )
    })?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    Profile::parse(&text, base).map_err(|errors| {
        Fault(
            errors
                .into_iter()
                .map(|e| format!("Profile `{}`: {e}", path.display()))
                .collect(),
        )
    })
}

fn execute(cli: &Cli, io: &mut Io<'_>) -> Result<u8, Fault> {
    let role = role_of(cli.role);
    let catalog = match &cli.cases_dir {
        Some(dir) => Catalog::from_dir(dir),
        None => Catalog::embedded(),
    }?;
    let profile = read_profile(&cli.profile)?;
    let has_section = match role {
        Role::Pep => profile.pep.is_some(),
        Role::Pdp => profile.pdp.is_some(),
        Role::Edge => profile.edge.is_some(),
    };
    if !has_section {
        return Err(format!(
            "Profile `{}`: the member `{}` is absent, and the role {} needs it.",
            cli.profile.display(),
            role.name(),
            role.name()
        )
        .into());
    }
    let target = check_options(cli, role, &profile)?;
    let cases = select(&catalog, cli, role)?;
    let base = cli.profile.parent().unwrap_or_else(|| Path::new("."));
    let lines = reference::effective(cli, role, &profile.raw, base);
    if cli.print_config {
        setup::check_files(&profile, role, &catalog)?;
        let mut text = String::new();
        for line in &lines {
            text.push_str(&line.text());
            text.push('\n');
        }
        return Ok(finish(
            io.stdout.write_all(text.as_bytes()),
            io.stderr,
            EXIT_OK,
        ));
    }
    let mut log = String::new();
    for line in &lines {
        log.push_str("config: ");
        log.push_str(&line.text());
        log.push('\n');
    }
    finish(io.stderr.write_all(log.as_bytes()), io.stderr, EXIT_OK);
    if (io.clock)() == 0 {
        return Err("The system clock is before 1970.".to_owned().into());
    }
    let clock = io.clock;
    let mut runner = match (role, &profile.pep, &profile.pdp, &profile.edge) {
        (Role::Pep, Some(pep), _, _) => {
            let target = target.ok_or_else(|| "Option `--url` is absent.".to_owned())?;
            setup::pep_runner(&profile, pep, target, &catalog, clock)?
        }
        (Role::Edge, _, _, Some(edge)) => {
            let target = target.ok_or_else(|| "Option `--url` is absent.".to_owned())?;
            setup::edge_runner(&profile, edge, target, &catalog, clock)?
        }
        (Role::Pdp, _, Some(pdp), _) => setup::pdp_runner(&profile, pdp, target, &catalog, clock)?,
        _ => return Err("The profile has no section for the role.".to_owned().into()),
    };
    let outcome = drive(&mut runner, &cases);
    let notes = runner.notes.lock().map(|n| n.clone()).unwrap_or_default();
    setup::stop(runner);
    for note in notes {
        finish(writeln!(io.stderr, "note: {note}"), io.stderr, EXIT_OK);
    }
    let results = outcome?;
    let text = match cli.format {
        Format::Text => report::render_text(&results),
        Format::Json => report::render_json(
            role.name(),
            cli.url.as_deref(),
            env!("CARGO_PKG_VERSION"),
            &results,
        ),
    };
    let summary = report::Summary::of(&results);
    let code = summary.exit_code();
    Ok(finish(
        io.stdout.write_all(text.as_bytes()),
        io.stderr,
        code,
    ))
}

/// Check the cases, the target and the data, and then run the cases.
fn drive(runner: &mut exec::Runner<'_>, cases: &[&Case]) -> Result<Vec<report::CaseResult>, Fault> {
    let problems = runner.validate(cases);
    if !problems.is_empty() {
        return Err(problems.into());
    }
    setup::reach(runner)?;
    setup::discover(runner)?;
    runner.preflight_directories(cases)?;
    Ok(runner.run(cases)?)
}
