//! The program `access-lint`. It reads the arguments, calls [`access_lint::run`] and sets the exit code.

use std::io;
use std::process::ExitCode;

fn main() -> ExitCode {
    let code = access_lint::run(
        std::env::args_os(),
        &mut io::stdout().lock(),
        &mut io::stderr().lock(),
    );
    ExitCode::from(code)
}
