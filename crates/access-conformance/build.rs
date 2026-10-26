//! Build script: embed the conformance cases and the directories in the program.
//!
//! The program then needs no data directory. The option `--cases-dir` reads
//! the same data from a directory instead.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

use std::fs;
use std::path::{Path, PathBuf};

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files
}

fn main() {
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = manifest.join("../../conformance").canonicalize().unwrap();
    let mut out = String::new();
    out.push_str("/// The cases: the path below `cases/`, and the text of the file.\n");
    out.push_str("pub(crate) static CASES: &[(&str, &str)] = &[\n");
    for series in ["U", "D", "E"] {
        for path in json_files(&root.join("cases").join(series)) {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            out.push_str(&format!(
                "    ({:?}, include_str!({:?})),\n",
                format!("{series}/{name}"),
                path.display().to_string()
            ));
        }
    }
    out.push_str("];\n\n");
    out.push_str("/// The directory files: the file name, and the text of the file.\n");
    out.push_str("pub(crate) static DIRECTORIES: &[(&str, &str)] = &[\n");
    for path in json_files(&root.join("directories")) {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        out.push_str(&format!(
            "    ({:?}, include_str!({:?})),\n",
            name,
            path.display().to_string()
        ));
    }
    out.push_str("];\n");
    let target = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("embedded.rs");
    fs::write(target, out).unwrap();
    println!("cargo:rerun-if-changed=../../conformance/cases");
    println!("cargo:rerun-if-changed=../../conformance/directories");
    println!("cargo:rerun-if-changed=build.rs");
}
