//! Helpers for the tests of `access-conformance`: run the program in the
//! process, write profiles, and start the scripted mock servers.
#![allow(
    dead_code,
    unreachable_pub,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic
)]

pub mod http;
pub mod loadable_pdp;
pub mod mock_edge;
pub mod mock_pep;

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use access_conformance::{Io, run};
use serde_json::Value;

/// The result of one run.
pub struct Out {
    pub code: u8,
    pub stdout: String,
    pub stderr: String,
}

impl Out {
    /// The lines of the text output, with the id of the case as key.
    pub fn status_of(&self, id: &str) -> Option<String> {
        self.stdout
            .lines()
            .find(|line| line.split_whitespace().next() == Some(id))
            .and_then(|line| line.split_whitespace().nth(1).map(str::to_owned))
    }

    /// The ids of the cases with this status, in the order of the output.
    pub fn ids_with(&self, status: &str) -> Vec<String> {
        self.stdout
            .lines()
            .filter(|line| line.split_whitespace().nth(1) == Some(status))
            .filter_map(|line| line.split_whitespace().next().map(str::to_owned))
            .collect()
    }

    /// The line of one case.
    pub fn line(&self, id: &str) -> String {
        self.stdout
            .lines()
            .find(|line| line.split_whitespace().next() == Some(id))
            .unwrap_or_default()
            .to_owned()
    }

    /// The last line of the text output: the summary.
    pub fn summary(&self) -> String {
        self.stdout.lines().last().unwrap_or_default().to_owned()
    }

    pub fn json(&self) -> Value {
        serde_json::from_str(&self.stdout)
            .unwrap_or_else(|e| panic!("the output is not JSON ({e}): {}", self.stdout))
    }
}

pub fn system_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

/// Run the program with the system clock.
pub fn run_cli(args: &[&str]) -> Out {
    run_with_clock(args, &system_now)
}

/// Run the program with a clock.
pub fn run_with_clock(args: &[&str], clock: &dyn Fn() -> u64) -> Out {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run(
        std::iter::once("access-conformance").chain(args.iter().copied()),
        &mut Io {
            stdout: &mut stdout,
            stderr: &mut stderr,
            clock,
        },
    );
    Out {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

/// The directory `examples/` of the crate.
pub fn examples() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("examples")
}

/// The directory of the repository.
pub fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A directory for the files of one test, in the target directory.
pub fn temp_dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("access-conformance-tests")
        .join(name);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write a file and return its path as text.
pub fn write(dir: &Path, name: &str, content: &str) -> String {
    let path = dir.join(name);
    std::fs::write(&path, content).unwrap();
    path.display().to_string()
}

/// A port that is free at this moment. The ports of one test process differ from each other.
/// They are below the range of the ports that the system gives to a connection.
pub fn free_port() -> u16 {
    use std::sync::atomic::{AtomicU16, Ordering};
    static NEXT: AtomicU16 = AtomicU16::new(0);
    loop {
        let step = NEXT.fetch_add(1, Ordering::SeqCst);
        let offset = (std::process::id() as u16)
            .wrapping_mul(37)
            .wrapping_add(step.wrapping_mul(7));
        let port = 20_000 + offset % 10_000;
        if TcpListener::bind(("127.0.0.1", port)).is_ok() {
            return port;
        }
    }
}
