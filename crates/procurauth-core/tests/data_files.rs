//! The data files of the repository follow the strict rules of the core.
//!
//! Each JSON file in `schemas/` and in `conformance/` is read with the strict
//! reader, so a duplicate member is an error. Each directory file of the
//! conformance data is good, and it gives no warning.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::{Path, PathBuf};

use procurauth_core::directory::{Directory, analyze_value};
use procurauth_core::json::parse_str;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn json_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            if path
                .file_name()
                .is_some_and(|n| n != "target" && n != "schema-check")
            {
                json_files(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "json") {
            out.push(path);
        }
    }
}

#[test]
fn every_json_file_is_read_by_the_strict_reader() {
    let mut files = Vec::new();
    json_files(&root().join("schemas"), &mut files);
    json_files(&root().join("conformance"), &mut files);
    assert!(files.len() > 8 + 18, "the data files are missing");
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        parse_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        assert!(
            text.ends_with('\n'),
            "{}: no line end at the end of the file",
            path.display()
        );
    }
}

#[test]
fn every_directory_file_is_good_and_gives_no_warning() {
    let dir = root().join("conformance/directories");
    let mut count = 0;
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        let (directory, report) = analyze_value(&parse_str(&text).unwrap());
        assert!(
            report.findings().is_empty(),
            "{}: {:?}",
            path.display(),
            report.findings()
        );
        assert!(directory.is_some());
        assert!(Directory::parse_str(&text).is_ok());
        count += 1;
    }
    assert!(count >= 1);
}

#[test]
fn the_example_directory_is_the_data_of_section_13() {
    let text = fs::read_to_string(root().join("conformance/directories/datastore.json")).unwrap();
    let directory = Directory::parse_str(&text).unwrap();
    let alice = directory.subject("alice").unwrap();
    assert_eq!(alice.grants.len(), 5);
    let key = directory.subject("key:9b1c04e2aa71f0c3").unwrap();
    assert_eq!(key.owner.as_deref(), Some("alice"));
    assert_eq!(key.grants.len(), 2);
    assert_eq!(
        directory.services[0].document.as_ref().unwrap().server,
        "datastore"
    );
}
