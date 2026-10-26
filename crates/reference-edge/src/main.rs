//! The program `reference-edge`. The work is in the library: see `cli::run`.

use std::io::Write;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use reference_edge::cli::{Io, run};
use reference_edge::config::real_sources;

fn main() -> ExitCode {
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    if let Err(error) = ctrlc::set_handler(move || flag.store(true, Ordering::SeqCst)) {
        let _ = writeln!(
            std::io::stderr(),
            "error: Cannot set the signal handler: {error}."
        );
        return ExitCode::from(1);
    }
    let code = real_sources(|sources| {
        let mut stdout = std::io::stdout();
        let mut stderr = std::io::stderr();
        let mut io = Io {
            stdout: &mut stdout,
            stderr: &mut stderr,
            log: Box::new(std::io::stderr()),
            sources,
            stop,
        };
        run(std::env::args_os(), &mut io)
    });
    ExitCode::from(code)
}
