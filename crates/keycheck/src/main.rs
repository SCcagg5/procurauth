//! The program `keycheck`. This file only connects the process to the library.

use std::io::{stderr, stdin, stdout};
use std::process::ExitCode;

fn main() -> ExitCode {
    keycheck::run(
        std::env::args_os(),
        stdin().lock(),
        &mut stdout().lock(),
        &mut stderr().lock(),
    )
    .into()
}
