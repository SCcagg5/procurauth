//! The example of protocol section 13 and the examples of the schemas lint clean.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;

use access_lint::check::{check_document, check_grants, check_options};
use common::{datastore_document, repository};
use procurauth_core::action_document::ActionDocument;
use serde_json::{Value, json};

fn load(path: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(repository().join(path)).unwrap()).unwrap()
}

fn text(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap()
}

#[test]
fn p_13_the_datastore_document_lints_clean() {
    let (document, findings) = check_document(&text(&datastore_document()));
    assert!(findings.is_empty(), "{findings:?}");
    assert!(document.is_some());
}

#[test]
fn p_13_the_grants_of_each_subject_lint_clean() {
    let directory = load("conformance/directories/datastore.json");
    let document = ActionDocument::from_value(&datastore_document()).unwrap();
    let subjects = directory["subjects"].as_array().unwrap();
    assert!(subjects.len() >= 4);
    for subject in subjects {
        let file = json!({"grants": subject["grants"]});
        let findings = check_grants(&text(&file), Some(&document));
        assert!(findings.is_empty(), "{}: {findings:?}", subject["id"]);
    }
}

#[test]
fn p_5_8_the_example_of_the_options_route_lints_clean() {
    let document = ActionDocument::from_value(&datastore_document()).unwrap();
    let answer = json!({
        "items": [
            {"id": "test1", "label": "test1", "has_children": true},
            {"id": "test2", "label": "test2", "has_children": true}
        ],
        "next": null
    });
    assert!(check_options(&text(&answer), Some(&document)).is_empty());
    let envelope =
        json!({"query": "parent=host%3Aprod&type=database&q=test&limit=2", "answer": answer});
    let findings = check_options(&text(&envelope), Some(&document));
    assert!(findings.is_empty(), "{findings:?}");
}

#[test]
fn p_5_2_each_example_of_the_schemas_lints_clean() {
    let schema = load("schemas/action-document.schema.json");
    let examples = schema["examples"].as_array().unwrap();
    assert!(!examples.is_empty());
    for example in examples {
        let findings = check_document(&text(example)).1;
        assert!(findings.is_empty(), "{findings:?}");
    }
    let schema = load("schemas/options-route-answer.schema.json");
    for example in schema["examples"].as_array().unwrap() {
        let findings = check_options(&text(example), None);
        assert!(findings.is_empty(), "{findings:?}");
    }
    let schema = load("schemas/fake-pdp-data.schema.json");
    for example in schema["examples"].as_array().unwrap() {
        for service in example["services"].as_array().unwrap() {
            let findings = check_document(&text(&service["document"])).1;
            assert!(findings.is_empty(), "{findings:?}");
        }
    }
}

#[test]
fn p_13_the_directory_files_of_the_conformance_data_lint_clean() {
    let dir = repository().join("conformance/directories");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let value: Value = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        for service in value["services"].as_array().unwrap() {
            // A service of the test data can have no document on purpose.
            if service["document"].is_null() {
                continue;
            }
            // The compact form is the size that a service sends. The file holds a document of the maximum size.
            let compact = serde_json::to_string(&service["document"]).unwrap();
            let findings = check_document(&compact).1;
            assert!(findings.is_empty(), "{}: {findings:?}", path.display());
        }
    }
}
