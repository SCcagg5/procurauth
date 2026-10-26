//! The example files and the README: they stay good, and the configuration table is the table of the code.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::fs;
use std::path::PathBuf;

use fake_pdp::config::reference_table;
use fake_pdp::faults::read_faults_str;
use fake_pdp::{Options, Server};
use procurauth_schema_check::Schemas;

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn examples() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = fs::read_dir(crate_dir().join("examples"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    out.sort();
    out
}

#[test]
fn each_example_data_file_is_valid_against_the_schema_and_loads() {
    let schemas = Schemas::load().unwrap();
    let mut count = 0;
    for path in examples() {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if !name.starts_with("datastore") {
            continue;
        }
        let text = fs::read_to_string(&path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        let errors = schemas.validate("fake-pdp-data", &value).unwrap();
        assert!(errors.is_empty(), "{name}: {errors:?}");
        Server::from_text(&text, Options::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        count += 1;
    }
    assert!(count >= 2);
}

#[test]
fn the_example_failure_file_loads() {
    let text = fs::read_to_string(crate_dir().join("examples/failures.json")).unwrap();
    let faults = read_faults_str(&text).unwrap();
    assert_eq!(faults.len(), 4);
}

#[test]
fn the_example_data_file_of_the_conformance_directory_is_the_same_as_the_example() {
    let a = fs::read_to_string(crate_dir().join("examples/datastore.json")).unwrap();
    let b = fs::read_to_string(crate_dir().join("../../conformance/directories/datastore.json"))
        .unwrap();
    assert_eq!(a, b);
}

#[test]
fn the_readme_holds_the_table_of_keys_of_the_code() {
    let readme = fs::read_to_string(crate_dir().join("README.md")).unwrap();
    let table = reference_table();
    assert!(
        readme.contains(&table),
        "The README must hold this table. Copy it from `fake_pdp::config::reference_table()`:\n{table}"
    );
}
