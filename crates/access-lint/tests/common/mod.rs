//! Helpers for the integration tests.

#![allow(dead_code, clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

/// The result of one run: the exit code, the standard output and the standard error.
pub(crate) struct Run {
    pub(crate) code: u8,
    pub(crate) stdout: String,
    pub(crate) stderr: String,
}

/// Run the tool without a process. The current directory is the directory of the crate.
pub(crate) fn run(args: &[&str]) -> Run {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut full = vec!["access-lint"];
    full.extend_from_slice(args);
    let code = access_lint::run(full, &mut stdout, &mut stderr);
    Run {
        code,
        stdout: String::from_utf8(stdout).unwrap(),
        stderr: String::from_utf8(stderr).unwrap(),
    }
}

/// The root of the repository.
pub(crate) fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// A directory for the files that a test writes.
pub(crate) fn scratch() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("access-lint");
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// Write a file in the scratch directory and give its path.
pub(crate) fn write(name: &str, content: impl AsRef<[u8]>) -> String {
    let path = scratch().join(name);
    fs::write(&path, content).unwrap();
    path.to_str().unwrap().to_owned()
}

/// The first service document of the data file `conformance/directories/datastore.json`.
pub(crate) fn datastore_document() -> serde_json::Value {
    let text =
        fs::read_to_string(repository().join("conformance/directories/datastore.json")).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    value["services"][0]["document"].clone()
}
