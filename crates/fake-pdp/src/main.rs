//! The program `fake-pdp`: a test decision point for ProcurAuth.
//!
//! This file reads the command line and the files, then it starts the
//! server of the library and waits for a stop request. Exit codes: 0 after a
//! stop request, 1 when the port cannot open, 2 for a usage error or a bad file.

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

use std::fs::File;
use std::io::{self, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use clap::Parser;
use fake_pdp::config::{DEFAULT_LISTEN, DEFAULT_WORKERS, MAX_WORKERS, METADATA_PATH};
use fake_pdp::faults::read_faults_str;
use fake_pdp::{ConfigLine, Credential, Options, Server, StartError};

/// The largest file that the program reads.
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

/// A test decision point (PDP) for ProcurAuth.
///
/// The program answers like a real PDP, from the fixed data of one file.
/// It serves the AuthZEN 1.0 endpoints and the metadata on one address.
/// It keeps its counters in memory. It reads no environment variable.
///
/// Exit code 0: stopped on request. Exit code 1: the port cannot open.
/// Exit code 2: usage error or bad file.
#[derive(Parser, Debug)]
#[command(
    name = "fake-pdp",
    version = concat!(env!("CARGO_PKG_VERSION"), "\nApache-2.0"),
    disable_help_subcommand = true
)]
struct Cli {
    /// The data file: services, subjects, grants, counters and failures.
    #[arg(value_name = "DATA_FILE")]
    data_file: PathBuf,

    /// The address of the listener. The default is 127.0.0.1:8181. Port 0 chooses a free port.
    #[arg(long, value_name = "ADDRESS:PORT", value_parser = parse_listen)]
    listen: Option<SocketAddr>,

    /// Fix the clock at this time. The clock then moves only through the admin endpoint.
    #[arg(long, value_name = "UNIX_SECONDS", value_parser = parse_seconds)]
    clock_start: Option<u64>,

    /// Enable the admin endpoints under /__fake/. Use it on a trusted network only.
    #[arg(long)]
    admin: bool,

    /// Read the credential of the PEP from this file. The PDP then requires a Bearer credential.
    #[arg(long, value_name = "FILE")]
    credential_file: Option<PathBuf>,

    /// Read more failures from this file. It can use the kinds close, invalid_json and no_units.
    #[arg(long, value_name = "FILE")]
    failures: Option<PathBuf>,

    /// The number of worker threads, from 1 to 256. The default is 8.
    #[arg(long, value_name = "N", value_parser = parse_workers)]
    workers: Option<usize>,

    /// Check all the files, print the values that apply, and exit with 0. The port stays closed.
    #[arg(long)]
    print_config: bool,
}

fn parse_listen(text: &str) -> Result<SocketAddr, String> {
    text.parse::<SocketAddr>().map_err(|_| {
        format!("expected an address and a port, as ADDRESS:PORT with a numeric address, found \"{text}\"")
    })
}

fn parse_seconds(text: &str) -> Result<u64, String> {
    text.parse::<u64>()
        .map_err(|_| format!("expected a whole number of seconds from 0, found \"{text}\""))
}

fn parse_workers(text: &str) -> Result<usize, String> {
    match text.parse::<usize>() {
        Ok(n) if (1..=MAX_WORKERS).contains(&n) => Ok(n),
        _ => Err(format!(
            "expected a whole number from 1 to {MAX_WORKERS}, found \"{text}\""
        )),
    }
}

/// Read a file of at most [`MAX_FILE_BYTES`] bytes as UTF-8 text.
fn read_text(path: &Path, what: &str) -> Result<String, String> {
    let file =
        File::open(path).map_err(|e| format!("{what} {}: cannot read: {e}", path.display()))?;
    let mut text = String::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|e| format!("{what} {}: cannot read as UTF-8 text: {e}", path.display()))?;
    if text.len() as u64 > MAX_FILE_BYTES {
        return Err(format!(
            "{what} {}: expected a file of {MAX_FILE_BYTES} bytes at most, found a larger file",
            path.display()
        ));
    }
    Ok(text)
}

fn say(text: &str) {
    let mut err = io::stderr().lock();
    let _ = writeln!(err, "{text}");
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    run(&cli)
}

/// Build the server from the arguments and the files. Every error stops the program before the port opens.
fn build(cli: &Cli) -> Result<Server, u8> {
    let mut problems = 0_u32;
    let mut options = Options {
        admin: cli.admin,
        clock_start: cli.clock_start,
        workers: cli.workers.unwrap_or(DEFAULT_WORKERS),
        log: Some(Box::new(io::stdout())),
        diagnostics: Some(Box::new(io::stderr())),
        ..Options::default()
    };
    if let Some(path) = &cli.credential_file {
        match read_text(path, "Key `--credential-file`: file").and_then(|t| {
            Credential::from_file_text(&t, &format!("file:{}", path.display()))
                .map_err(|e| e.to_string())
        }) {
            Ok(credential) => options.credential = Some(credential),
            Err(message) => {
                say(&format!("fake-pdp: {message}"));
                problems += 1;
            }
        }
    }
    if let Some(path) = &cli.failures {
        match read_text(path, "Key `--failures`: file") {
            Ok(text) => match read_faults_str(&text) {
                Ok(faults) => options.extra_faults = faults,
                Err(findings) => {
                    for finding in &findings {
                        say(&format!("{}: {finding}", path.display()));
                    }
                    problems += 1;
                }
            },
            Err(message) => {
                say(&format!("fake-pdp: {message}"));
                problems += 1;
            }
        }
    }
    let server = match read_text(&cli.data_file, "Argument `DATA_FILE`: file") {
        Ok(text) => match Server::from_text(&text, options) {
            Ok(server) => Some(server),
            Err(StartError::Data(findings)) => {
                for finding in &findings {
                    say(&format!("{}: {finding}", cli.data_file.display()));
                }
                say(&format!(
                    "fake-pdp: the data file {} has {} finding(s) and the server does not start.",
                    cli.data_file.display(),
                    findings.len()
                ));
                problems += 1;
                None
            }
            Err(other) => {
                say(&format!("fake-pdp: {other}"));
                problems += 1;
                None
            }
        },
        Err(message) => {
            say(&format!("fake-pdp: {message}"));
            problems += 1;
            None
        }
    };
    match server {
        Some(server) if problems == 0 => {
            for warning in server.warnings() {
                say(&format!("{}: {warning}", cli.data_file.display()));
            }
            Ok(server)
        }
        _ => Err(2),
    }
}

fn config_lines(cli: &Cli, server: &Server) -> Vec<ConfigLine> {
    let listen = cli.listen.map_or_else(
        || (DEFAULT_LISTEN.to_owned(), "default"),
        |a| (a.to_string(), "flag"),
    );
    let mut lines = vec![
        ConfigLine {
            key: "data-file".to_owned(),
            value: cli.data_file.display().to_string(),
            source: "argument".to_owned(),
        },
        ConfigLine {
            key: "--listen".to_owned(),
            value: listen.0,
            source: listen.1.to_owned(),
        },
    ];
    lines.extend(server.effective_config());
    if let Some(path) = &cli.failures {
        lines.push(ConfigLine {
            key: "--failures".to_owned(),
            value: path.display().to_string(),
            source: "flag".to_owned(),
        });
    }
    lines
}

fn run(cli: &Cli) -> ExitCode {
    let server = match build(cli) {
        Ok(server) => server,
        Err(code) => return ExitCode::from(code),
    };
    let lines = config_lines(cli, &server);
    if cli.print_config {
        let mut out = io::stdout().lock();
        for line in &lines {
            let _ = writeln!(out, "{} = {}  ({})", line.key, line.value, line.source);
        }
        return ExitCode::SUCCESS;
    }
    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = Arc::clone(&stop);
        if let Err(error) = ctrlc::set_handler(move || stop.store(true, Ordering::SeqCst)) {
            say(&format!(
                "fake-pdp: cannot install the stop handler: {error}."
            ));
            return ExitCode::from(1);
        }
    }
    let address = cli.listen.map_or_else(
        || DEFAULT_LISTEN.parse::<SocketAddr>(),
        Ok::<SocketAddr, std::net::AddrParseError>,
    );
    let Ok(address) = address else {
        say("fake-pdp: the default address is not valid.");
        return ExitCode::from(2);
    };
    let running = match server.start(address) {
        Ok(running) => running,
        Err(error) => {
            say(&format!("fake-pdp: {error}"));
            return ExitCode::from(1);
        }
    };
    for line in &lines {
        say(&format!(
            "config {} = {}  ({})",
            line.key, line.value, line.source
        ));
    }
    {
        let mut out = io::stdout().lock();
        let _ = writeln!(
            out,
            "fake-pdp {} on {}",
            env!("CARGO_PKG_VERSION"),
            running.url()
        );
        let _ = writeln!(out, "metadata {METADATA_PATH}");
        let _ = out.flush();
    }
    while !stop.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(50));
    }
    running.shutdown();
    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listen_value_must_be_a_numeric_address_and_a_port() {
        assert!(parse_listen("127.0.0.1:8181").is_ok());
        assert!(parse_listen("[::1]:0").is_ok());
        for bad in ["localhost:80", "127.0.0.1", ":80", "127.0.0.1:99999", ""] {
            let message = parse_listen(bad).unwrap_err();
            assert!(message.contains(bad), "{message}");
            assert!(message.contains("ADDRESS:PORT"));
        }
    }

    #[test]
    fn the_seconds_must_be_a_whole_number() {
        assert_eq!(parse_seconds("1792569648"), Ok(1_792_569_648));
        for bad in ["-1", "1.5", "x", "", "+1 "] {
            assert!(parse_seconds(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_workers_must_be_in_range() {
        assert_eq!(parse_workers("1"), Ok(1));
        assert_eq!(parse_workers("256"), Ok(256));
        for bad in ["0", "257", "-1", "x"] {
            let message = parse_workers(bad).unwrap_err();
            assert!(message.contains("1 to 256"), "{message}");
        }
    }

    #[test]
    fn clap_accepts_the_page_usage() {
        let cli = Cli::try_parse_from(["fake-pdp", "--listen", "127.0.0.1:8181", "directory.json"])
            .unwrap();
        assert_eq!(cli.listen, Some("127.0.0.1:8181".parse().unwrap()));
        assert_eq!(cli.data_file, PathBuf::from("directory.json"));
    }

    #[test]
    fn clap_refuses_a_repeated_flag_and_an_unknown_flag() {
        assert!(
            Cli::try_parse_from([
                "fake-pdp",
                "--listen",
                "127.0.0.1:1",
                "--listen",
                "127.0.0.1:2",
                "d.json"
            ])
            .is_err()
        );
        assert!(Cli::try_parse_from(["fake-pdp", "--bogus", "d.json"]).is_err());
        assert!(Cli::try_parse_from(["fake-pdp"]).is_err());
        assert!(Cli::try_parse_from(["fake-pdp", "a.json", "b.json"]).is_err());
    }
}
