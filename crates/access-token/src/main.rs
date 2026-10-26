//! The program `access-token`. It reads the arguments and calls the library.

use std::io::{self, Write as _};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use access_token::{Io, run};

/// The system clock, in whole seconds since the Unix epoch.
fn system_clock() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .map_err(|_| "The system clock is before 1970. Give the time with `--now`.".to_owned())
}

fn main() -> ExitCode {
    let mut stdin = io::stdin().lock();
    let mut stdout = io::stdout().lock();
    let mut stderr = io::stderr().lock();
    let code = run(
        std::env::args_os(),
        &mut Io {
            stdin: &mut stdin,
            stdout: &mut stdout,
            stderr: &mut stderr,
            clock: &system_clock,
        },
    );
    let _ = stdout.flush();
    ExitCode::from(code)
}
