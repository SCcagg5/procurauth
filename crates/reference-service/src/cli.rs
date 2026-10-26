//! The command line of the program.
//!
//! `main` only gives the arguments, the streams and the stop flag to [`run`].
//! Thus a test can run the whole program in a thread.
//!
//! The exit codes are:
//!
//! | Code | Meaning |
//! | --- | --- |
//! | 0 | The program stopped on request, or `--print-config` finished. |
//! | 1 | The program could not open the port. |
//! | 2 | The command line or the configuration is not valid. |

use std::ffi::OsString;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use crate::config::{Loaded, Sources, load_file};
use crate::service;
use clap::Parser as _;
use clap::error::ErrorKind;

/// The exit code for a normal end.
pub const EXIT_OK: u8 = 0;
/// The exit code when the port cannot open.
pub const EXIT_RUNTIME: u8 = 1;
/// The exit code for a command line or a configuration that is not valid.
pub const EXIT_USAGE: u8 = 2;

/// The arguments of the program.
#[derive(clap::Parser, Debug)]
#[command(
    name = "reference-service",
    version,
    about = "A reference service for ProcurAuth. It uses the library procurauth-pep.",
    long_about = "A reference service for ProcurAuth. It uses the library procurauth-pep. \
It is the test subject of the series U of the conformance cases. \
The configuration file is the only source of the values. \
The program reads an environment variable only when the file names it with a key that ends in _env.",
    disable_help_subcommand = true
)]
struct Cli {
    /// Check the configuration, print the value that applies for each key and its source, and exit.
    #[arg(long)]
    print_config: bool,

    /// The configuration file, a JSON object. See the README of the crate for the keys.
    config: PathBuf,
}

/// The streams of the program.
pub struct Io<'a> {
    /// The standard output.
    pub stdout: &'a mut dyn Write,
    /// The standard error.
    pub stderr: &'a mut dyn Write,
    /// The log of the requests. The service writes one line for each request.
    pub log: Box<dyn Write + Send>,
    /// The environment and the files that the configuration names.
    pub sources: &'a Sources<'a>,
    /// The flag that stops the service. A signal handler sets it.
    pub stop: Arc<AtomicBool>,
}

fn say(stream: &mut dyn Write, text: &str) {
    let _ = stream.write_all(text.as_bytes());
}

/// Run the program with the arguments, and return the exit code. The first argument is the name of the program.
pub fn run<I, T>(arguments: I, io: &mut Io<'_>) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(arguments) {
        Ok(cli) => cli,
        Err(error) => {
            let text = error.to_string();
            return if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) {
                say(io.stdout, &text);
                EXIT_OK
            } else {
                say(io.stderr, &text);
                EXIT_USAGE
            };
        }
    };
    let loaded = match load_file(&cli.config, io.sources) {
        Ok(loaded) => loaded,
        Err(errors) => {
            for error in errors {
                say(io.stderr, &format!("error: {error}\n"));
            }
            return EXIT_USAGE;
        }
    };
    if cli.print_config {
        say(io.stdout, &loaded.render());
        return EXIT_OK;
    }
    serve(loaded, io)
}

fn serve(loaded: Loaded, io: &mut Io<'_>) -> u8 {
    let Loaded { settings, lines } = loaded;
    // The program logs the values that apply at start. A secret never shows.
    let mut effective = String::from("effective configuration:\n");
    for line in &lines {
        effective.push_str(&format!(
            "  {} = {}  ({})\n",
            line.key,
            line.value,
            line.source.text()
        ));
    }
    say(io.stderr, &effective);
    let log = std::mem::replace(&mut io.log, Box::new(std::io::sink()));
    let app = match service::build_app_with(
        settings.pep,
        settings.mcp_path,
        settings.mcp_session_budget,
        log,
    ) {
        Ok(app) => Arc::new(app),
        Err(errors) => {
            for error in errors {
                say(io.stderr, &format!("error: {error}\n"));
            }
            return EXIT_USAGE;
        }
    };
    let running = match service::start(app, settings.listen, settings.workers, settings.limits) {
        Ok(running) => running,
        Err(error) => {
            say(
                io.stderr,
                &format!(
                    "error: Cannot open the port {}: {error}.\n",
                    settings.listen
                ),
            );
            return EXIT_RUNTIME;
        }
    };
    say(
        io.stdout,
        &format!(
            "reference-service {} on {}\n",
            env!("CARGO_PKG_VERSION"),
            running.url()
        ),
    );
    let _ = io.stdout.flush();
    let flag = running.stop_flag();
    let stop = Arc::clone(&io.stop);
    let watcher = std::thread::spawn(move || {
        while !stop.load(std::sync::atomic::Ordering::SeqCst) {
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        flag.store(true, std::sync::atomic::Ordering::SeqCst);
    });
    running.run_until_stopped();
    let _ = watcher.join();
    EXIT_OK
}
