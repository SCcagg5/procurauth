//! The program `access-conformance`. It reads the arguments and calls the library.

use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use access_conformance::{Io, run};

/// The system clock, in whole seconds since the Unix epoch.
fn system_clock() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn main() -> ExitCode {
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let code = run(
        std::env::args_os(),
        &mut Io {
            stdout: &mut stdout,
            stderr: &mut stderr,
            clock: &system_clock,
        },
    );
    let _ = stdout.flush();
    ExitCode::from(code)
}
