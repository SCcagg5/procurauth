//! Golden tests: the text and the JSON output of fixed inputs.
//!
//! A golden file holds the expected output. When the file is absent, the test writes it
//! and fails, so that the author can read the new file before the next run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::Path;

use common::run;

const DIR: &str = "tests/fixtures/golden/";

fn golden(name: &str, actual: &str) {
    let normal = actual
        .replace(DIR, "")
        .replace(env!("CARGO_PKG_VERSION"), "VERSION");
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(name);
    match fs::read_to_string(&path) {
        Ok(expected) => assert_eq!(normal, expected, "golden file {name}"),
        Err(_) => {
            fs::write(&path, &normal).unwrap();
            panic!(
                "the golden file {name} was absent, and the test wrote it. Read it, and run again"
            );
        }
    }
}

fn args(format: &str, names: &[&str]) -> Vec<String> {
    let mut out = vec!["--format".to_owned(), format.to_owned()];
    out.extend(names.iter().map(|n| (*n).to_owned()));
    out
}

fn golden_run(name: &str, extension: &str, format: &str, names: &[&str], code: u8) {
    let args = args(format, names);
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let result = run(&refs);
    assert_eq!(result.code, code, "{}", result.stderr);
    assert_eq!(result.stderr, "");
    golden(&format!("{name}.{extension}"), &result.stdout);
}

fn path(name: &str) -> String {
    format!("{DIR}{name}")
}

#[test]
fn p_5_2_the_example_of_the_site_in_text() {
    golden_run("page-example", "txt", "text", &[&path("actions.json")], 1);
}

#[test]
fn p_5_2_the_example_of_the_site_in_json() {
    golden_run("page-example", "json", "json", &[&path("actions.json")], 1);
}

#[test]
fn p_13_a_good_document_in_text() {
    golden_run(
        "clean",
        "txt",
        "text",
        &["tests/fixtures/context/document.json"],
        0,
    );
}

#[test]
fn p_13_a_good_document_in_json() {
    golden_run(
        "clean",
        "json",
        "json",
        &["tests/fixtures/context/document.json"],
        0,
    );
}

#[test]
fn p_5_3c_a_warning_does_not_change_the_exit_code() {
    golden_run(
        "warning-only",
        "txt",
        "text",
        &["tests/fixtures/document/5.3c_above_reader_minimum/fail.json"],
        0,
    );
}

#[test]
fn p_8_3_three_inputs_in_text() {
    golden_run(
        "three-inputs",
        "txt",
        "text",
        &[
            "--grants",
            &path("grants.json"),
            "--options",
            &path("options.json"),
            "tests/fixtures/context/document.json",
        ],
        1,
    );
}

#[test]
fn p_8_3_three_inputs_in_json() {
    golden_run(
        "three-inputs",
        "json",
        "json",
        &[
            "--grants",
            &path("grants.json"),
            "--options",
            &path("options.json"),
            "tests/fixtures/context/document.json",
        ],
        1,
    );
}
