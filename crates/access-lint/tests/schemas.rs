//! The schemas of the tool agree with the readers, and the JSON output follows its schema.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;
use std::path::Path;

use access_lint::check::{check_grants, check_options};
use common::run;
use procurauth_core::action_document::ActionDocument;
use procurauth_core::finding::Severity;
use procurauth_schema_check::Schemas;
use serde_json::Value;

fn fixtures(scope: &str) -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(scope);
    let mut out = Vec::new();
    for dir in fs::read_dir(root).unwrap() {
        let dir = dir.unwrap().path();
        for name in ["fail.json", "pass.json"] {
            let file = dir.join(name);
            out.push((
                format!("{}/{name}", dir.file_name().unwrap().to_string_lossy()),
                fs::read_to_string(file).unwrap(),
            ));
        }
    }
    out
}

fn context() -> ActionDocument {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/context/document.json");
    ActionDocument::parse_str(&fs::read_to_string(path).unwrap()).unwrap()
}

/// A good input must be valid for the schema. An input that the schema refuses must have an error.
fn agree(schema: &str, scope: &str, lint: impl Fn(&str) -> bool) {
    let schemas = Schemas::load().unwrap();
    for (name, text) in fixtures(scope) {
        let has_error = lint(&text);
        match serde_json::from_str::<Value>(&text) {
            Err(_) => assert!(has_error, "{scope}/{name}"),
            Ok(value) => {
                let valid = schemas.is_valid(schema, &value).unwrap();
                assert!(
                    !has_error || !valid || name.ends_with("fail.json"),
                    "{scope}/{name}"
                );
                if !has_error {
                    assert!(
                        valid,
                        "{scope}/{name}: the reader accepts it, the schema does not"
                    );
                }
                if !valid {
                    assert!(
                        has_error,
                        "{scope}/{name}: the schema refuses it, the reader does not"
                    );
                }
            }
        }
    }
}

#[test]
fn p_3_5_the_grants_schema_agrees_with_the_reader() {
    let document = context();
    agree("grants-file", "grants", |text| {
        check_grants(text, Some(&document))
            .iter()
            .any(|f| f.severity == Severity::Error)
    });
}

#[test]
fn p_5_8_the_options_schema_agrees_with_the_reader() {
    let document = context();
    agree("options-file", "options", |text| {
        check_options(text, Some(&document))
            .iter()
            .any(|f| f.severity == Severity::Error)
    });
}

#[test]
fn p_3_5_the_grants_schema_is_closed() {
    let schemas = Schemas::load().unwrap();
    let good: Value = serde_json::from_str(r#"{"grants": []}"#).unwrap();
    assert!(schemas.is_valid("grants-file", &good).unwrap());
    for bad in [
        r#"{}"#,
        r#"{"grants": [], "extra": 1}"#,
        r#"{"grants": [{"action": "a", "resource": "service:s", "extra": 1}]}"#,
        r#"{"grants": [{"action": "a"}]}"#,
        r#"[]"#,
    ] {
        let value: Value = serde_json::from_str(bad).unwrap();
        assert!(!schemas.is_valid("grants-file", &value).unwrap(), "{bad}");
    }
}

#[test]
fn p_5_8_the_options_schema_takes_an_answer_or_an_envelope() {
    let schemas = Schemas::load().unwrap();
    for good in [
        r#"{"items": [], "next": null}"#,
        r#"{"query": "type=a", "answer": {"items": [], "next": null}}"#,
        r#"{"answer": {"items": [], "next": null}}"#,
    ] {
        let value: Value = serde_json::from_str(good).unwrap();
        assert!(schemas.is_valid("options-file", &value).unwrap(), "{good}");
    }
    for bad in [
        r#"{"query": "type=a"}"#,
        r#"{"query": 5, "answer": {"items": [], "next": null}}"#,
        r#"{"answer": {"items": [], "next": null}, "extra": 1}"#,
    ] {
        let value: Value = serde_json::from_str(bad).unwrap();
        assert!(!schemas.is_valid("options-file", &value).unwrap(), "{bad}");
    }
}

#[test]
fn p_5_2_each_json_output_follows_its_schema() {
    let schemas = Schemas::load().unwrap();
    let mut count = 0;
    for scope in ["document", "grants", "options"] {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(scope);
        for dir in fs::read_dir(root).unwrap() {
            let dir = dir.unwrap().path();
            for name in ["fail.json", "pass.json"] {
                let file = dir.join(name);
                let file = file.to_str().unwrap();
                let context = "tests/fixtures/context/document.json";
                let args: Vec<&str> = match scope {
                    "document" => vec!["--format", "json", file],
                    "grants" => vec!["--format", "json", "--grants", file, context],
                    _ => vec!["--format", "json", "--options", file, context],
                };
                let result = run(&args);
                let value: Value = serde_json::from_str(&result.stdout).unwrap();
                let errors = schemas.validate("access-lint-output", &value).unwrap();
                assert!(errors.is_empty(), "{file}: {errors:?}");
                assert_eq!(value["ok"], result.code == 0, "{file}");
                count += 1;
            }
        }
    }
    assert!(count >= 150);
}

#[test]
fn p_5_2_the_output_schema_refuses_an_unknown_member() {
    let schemas = Schemas::load().unwrap();
    let bad: Value = serde_json::from_str(
        r#"{"tool": "access-lint", "version": "1", "ok": true, "inputs": [], "extra": 1}"#,
    )
    .unwrap();
    assert!(!schemas.is_valid("access-lint-output", &bad).unwrap());
}
