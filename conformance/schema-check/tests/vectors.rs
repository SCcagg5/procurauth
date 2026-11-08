//! The check of the vector files (`conformance/vectors/`).
//!
//! The test validates `effect.json` against the schema `effect-vectors`. It also
//! checks what a schema cannot check: the ids, the groups, the cited paragraph and
//! the rows of `COVERAGE.md`. The hash of each vector is checked by the test
//! `effect_vectors` in `crates/procurauth-core`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;

use procurauth_schema_check::{Schemas, repository_root};
use serde_json::Value;

fn effect_file() -> Value {
    let path = repository_root().join("conformance/vectors/effect.json");
    serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn the_effect_vectors_are_valid_against_the_schema() {
    let schemas = Schemas::load().unwrap();
    let errors = schemas.validate("effect-vectors", &effect_file()).unwrap();
    assert!(errors.is_empty(), "{errors:?}");
}

#[test]
fn the_schema_rejects_a_vector_with_a_bad_effect_or_group() {
    let schemas = Schemas::load().unwrap();
    let mut file = effect_file();
    file["vectors"][0]["effect"] = Value::from("sha256:ABC");
    assert!(!schemas.is_valid("effect-vectors", &file).unwrap());
    let mut file = effect_file();
    file["vectors"][0]["group"] = Value::from("V03");
    assert!(!schemas.is_valid("effect-vectors", &file).unwrap());
    let mut file = effect_file();
    file["vectors"][0]["input"]["op"] = Value::from(1);
    assert!(!schemas.is_valid("effect-vectors", &file).unwrap());
}

#[test]
fn the_effect_vectors_have_unique_ids_and_both_groups() {
    let file = effect_file();
    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 12, "{} vectors", vectors.len());
    let mut ids = BTreeSet::new();
    for vector in vectors {
        let id = vector["id"].as_str().unwrap();
        assert!(ids.insert(id.to_owned()), "{id}: the id occurs two times");
    }
    for group in ["V01", "V02"] {
        assert!(
            vectors.iter().any(|v| v["group"] == group),
            "no vector in the group {group}"
        );
    }
}

#[test]
fn the_vectors_of_v01_have_their_effect_in_one_form_only() {
    // Two inputs with the same text give the same effect, and a different text gives another one.
    let file = effect_file();
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for vector in file["vectors"].as_array().unwrap() {
        if vector["group"] != "V01" {
            continue;
        }
        let canonical = vector["canonical"].as_str().unwrap();
        let effect = vector["effect"].as_str().unwrap();
        for (other_text, other_effect) in &seen {
            assert_eq!(
                canonical == *other_text,
                effect == *other_effect,
                "{}: the text and the effect disagree with another vector",
                vector["id"]
            );
        }
        seen.push((canonical, effect));
    }
}

#[test]
fn the_effect_vectors_cite_a_paragraph_that_exists() {
    let text =
        fs::read_to_string(repository_root().join("protocol/procurauth-protocol.md")).unwrap();
    assert!(
        text.lines().any(|l| l.starts_with("17.3 ")),
        "protocol 17.3 is missing"
    );
    assert!(
        effect_file()["description"]
            .as_str()
            .unwrap()
            .contains("protocol 17.3")
    );
}

#[test]
fn coverage_lists_each_group_of_vectors() {
    let text = fs::read_to_string(repository_root().join("conformance/COVERAGE.md")).unwrap();
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if let Some(title) = line.strip_prefix("## ") {
            inside = title.trim() == "Vectors";
            continue;
        }
        if inside && line.starts_with('|') {
            let cells: Vec<String> = line
                .trim()
                .trim_matches('|')
                .split('|')
                .map(|c| c.trim().to_owned())
                .collect();
            assert_eq!(cells.len(), 4, "COVERAGE.md: bad row {line}");
            if cells[0] != "Id" && !cells[0].starts_with("---") {
                rows.push(cells);
            }
        }
    }
    let file = effect_file();
    for group in ["V01", "V02"] {
        let row = rows
            .iter()
            .find(|r| r[0] == group)
            .unwrap_or_else(|| panic!("COVERAGE.md: no row for the group {group}"));
        assert_eq!(row[1], "17.3", "{group}: paragraph");
        assert_eq!(row[2], "`vectors/effect.json`", "{group}: file");
        assert!(
            file["vectors"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v["group"] == group)
        );
    }
    assert_eq!(
        rows.len(),
        2,
        "COVERAGE.md: the table Vectors has other rows"
    );
}
