//! The check of the conformance data (`conformance/`).
//!
//! The test validates each case file against the schema `conformance-case`.
//! It also checks what a schema cannot check. These are the id and the file
//! name, the cited paragraphs, the regular expressions, the variables, the
//! tokens and the files that a case names.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use procurauth_schema_check::{Schemas, repository_root};
use serde_json::Value;

const VARIABLES: [&str; 10] = [
    "service",
    "action",
    "resource_type",
    "resource_id",
    "ancestors",
    "token_header",
    "unknown_key_text",
    "valid_key_text",
    "valid_key_subject",
    "valid_key_owner",
];

fn conformance_dir() -> PathBuf {
    repository_root().join("conformance")
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", dir.display()))
        .map(|entry| entry.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    files
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap();
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

struct CaseFile {
    series: char,
    stem: String,
    value: Value,
}

fn cases() -> Vec<CaseFile> {
    let mut out = Vec::new();
    for series in ['U', 'D', 'E'] {
        for path in json_files(&conformance_dir().join(series.to_string())) {
            out.push(CaseFile {
                series,
                stem: path.file_stem().unwrap().to_string_lossy().into_owned(),
                value: read_json(&path),
            });
        }
    }
    out
}

#[test]
fn every_case_file_is_valid_against_the_schema() {
    let schemas = Schemas::load().unwrap();
    let validator = schemas.validator("conformance-case").unwrap();
    for case in cases() {
        let errors: Vec<String> = validator
            .iter_errors(&case.value)
            .map(|e| format!("{}: {e}", e.instance_path))
            .collect();
        assert!(errors.is_empty(), "{}: {errors:?}", case.stem);
    }
}

#[test]
fn every_series_has_at_least_six_cases() {
    let all = cases();
    for series in ['U', 'D', 'E'] {
        let count = all.iter().filter(|c| c.series == series).count();
        assert!(count >= 6, "series {series} has {count} cases");
    }
}

#[test]
fn the_id_is_the_file_name_and_the_directory_is_the_series() {
    let mut seen = BTreeSet::new();
    for case in cases() {
        let id = case.value["id"].as_str().unwrap();
        assert_eq!(id, case.stem, "the id and the file name differ");
        assert_eq!(
            id.chars().next().unwrap(),
            case.series,
            "{id}: wrong directory"
        );
        assert!(seen.insert(id.to_owned()), "{id}: the id occurs two times");
        let role = match case.series {
            'U' => "pep",
            'D' => "pdp",
            _ => "edge",
        };
        assert_eq!(case.value["role"], role, "{id}: wrong role");
    }
}

#[test]
fn the_ids_of_the_mcp_binding_are_not_used() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap();
        let number: u32 = id[1..].parse().unwrap();
        let reserved = match case.series {
            'U' => number == 18 || number == 23 || (25..=31).contains(&number),
            'E' => number == 1,
            _ => false,
        };
        assert!(!reserved, "{id} belongs to the MCP binding");
    }
}

/// The numbers of the paragraphs and of the sections of a text, without the paragraphs that are unused.
fn paragraph_numbers(path: &Path) -> BTreeSet<String> {
    let text = fs::read_to_string(path).unwrap();
    let mut found = BTreeSet::new();
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("## ") {
            if let Some((number, _)) = rest.split_once(". ")
                && number.chars().all(|c| c.is_ascii_digit())
            {
                found.insert(number.to_owned());
            }
            continue;
        }
        let Some((number, rest)) = line.split_once(' ') else {
            continue;
        };
        let mut parts = number.split('.');
        let (Some(a), Some(b), None) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let b_digits = b.trim_end_matches(|c: char| c.is_ascii_lowercase());
        let good = !a.is_empty()
            && a.chars().all(|c| c.is_ascii_digit())
            && !b_digits.is_empty()
            && b_digits.chars().all(|c| c.is_ascii_digit())
            && b.len() - b_digits.len() <= 1;
        if good && !rest.starts_with("Unused") {
            found.insert(number.to_owned());
        }
    }
    found
}

#[test]
fn every_cited_paragraph_exists_and_is_not_unused() {
    let root = repository_root();
    let protocol = paragraph_numbers(&root.join("protocol/procurauth-protocol.md"));
    let binding = paragraph_numbers(&root.join("bindings/mcp/procurauth-mcp-binding.md"));
    assert!(protocol.contains("6.4") && protocol.contains("10.1a") && protocol.contains("5.3c"));
    assert!(!protocol.contains("7.2"), "7.2 is unused");
    for case in cases() {
        let id = case.value["id"].as_str().unwrap();
        for paragraph in case.value["paragraphs"].as_array().unwrap() {
            let text = paragraph.as_str().unwrap();
            let (set, number) = match text.strip_prefix("mcp:") {
                Some(number) => (&binding, number),
                None => (&protocol, text),
            };
            assert!(
                set.contains(number),
                "{id}: the paragraph {text} does not exist, or it is unused"
            );
        }
    }
}

fn walk<'a>(value: &'a Value, path: &str, visit: &mut dyn FnMut(&str, &'a Value)) {
    visit(path, value);
    match value {
        Value::Object(map) => {
            for (key, item) in map {
                walk(item, &format!("{path}/{key}"), visit);
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                walk(item, &format!("{path}/{index}"), visit);
            }
        }
        _ => {}
    }
}

fn variables_in(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            break;
        };
        out.push(after[..end].to_owned());
        rest = &after[end + 2..];
    }
    out
}

#[test]
fn every_variable_is_known() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap().to_owned();
        let mut check = |path: &str, value: &Value| {
            let mut texts = Vec::new();
            if let Value::String(text) = value {
                texts.push(text.clone());
            }
            // The member names of an object are texts too.
            if let Value::Object(map) = value {
                texts.extend(map.keys().cloned());
            }
            for text in texts {
                for name in variables_in(&text) {
                    assert!(
                        VARIABLES.contains(&name.as_str()),
                        "{id}: unknown variable {{{{{name}}}}} at {path}"
                    );
                }
            }
        };
        walk(&case.value, "", &mut check);
    }
}

#[test]
fn every_regular_expression_compiles() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap().to_owned();
        let mut check = |path: &str, value: &Value| {
            if let Some(Value::String(expression)) = value.as_object().and_then(|m| m.get("regex"))
            {
                regex::Regex::new(expression)
                    .unwrap_or_else(|e| panic!("{id}: bad regular expression at {path}: {e}"));
            }
        };
        walk(&case.value, "", &mut check);
    }
}

#[test]
fn every_matcher_has_exactly_one_member() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap().to_owned();
        let known = ["equals", "absent", "present", "regex", "one_of"];
        let mut check = |path: &str, value: &Value| {
            if let Value::Object(map) = value {
                let hits = map.keys().filter(|k| known.contains(&k.as_str())).count();
                // A step has no member with these names, so a hit means a matcher.
                if hits > 0
                    && !path.ends_with("/body")
                    && !path.contains("/body/")
                    && !path.contains("/given/tokens")
                {
                    assert_eq!(
                        map.len(),
                        1,
                        "{id}: matcher at {path} has more than one member"
                    );
                }
            }
        };
        walk(&case.value, "", &mut check);
    }
}

#[test]
fn the_members_of_a_step_fit_the_role() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap();
        let role = case.value["role"].as_str().unwrap();
        for step in case.value["steps"].as_array().unwrap() {
            let request = step["request"].as_object().unwrap();
            let expect = step["expect"].as_object().unwrap();
            if request.contains_key("operation") {
                assert_eq!(role, "pep", "{id}: operation is for a PEP");
            }
            if request.contains_key("endpoint") {
                assert_eq!(role, "pdp", "{id}: endpoint is for a PDP");
            }
            if expect.contains_key("pdp_questions") {
                assert_eq!(role, "pep", "{id}: pdp_questions is for a PEP");
            }
            if expect.contains_key("upstream") {
                assert_eq!(role, "edge", "{id}: upstream is for an edge");
            }
            if role == "pdp" {
                assert!(
                    request.contains_key("endpoint"),
                    "{id}: a PDP step names an endpoint"
                );
            }
        }
        if role != "pep" {
            assert!(
                case.value["given"].get("pdp_script").is_none(),
                "{id}: pdp_script is for a PEP"
            );
        }
    }
}

#[test]
fn every_token_that_a_step_uses_exists_and_every_token_is_used() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap();
        let defined: BTreeSet<&str> = case.value["given"]
            .get("tokens")
            .and_then(Value::as_object)
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        let used: BTreeSet<&str> = case.value["steps"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|s| s["request"].get("token").and_then(Value::as_str))
            .collect();
        for name in &used {
            assert!(
                defined.contains(name),
                "{id}: the step uses the token {name}, and the case does not define it"
            );
        }
        for name in &defined {
            assert!(used.contains(name), "{id}: the token {name} is not used");
        }
    }
}

#[test]
fn every_directory_file_that_a_case_names_exists() {
    let dir = conformance_dir().join("directories");
    let mut named = BTreeMap::new();
    for case in cases() {
        if let Some(name) = case.value["given"].get("directory").and_then(Value::as_str) {
            assert!(
                dir.join(name).is_file(),
                "{}: the directory file {name} does not exist",
                case.stem
            );
            *named.entry(name.to_owned()).or_insert(0) += 1;
        }
    }
    assert!(named.contains_key("datastore.json"));
}

#[test]
fn every_directory_file_is_valid_against_the_schema() {
    let schemas = Schemas::load().unwrap();
    let files = json_files(&conformance_dir().join("directories"));
    assert!(!files.is_empty());
    for path in files {
        let errors = schemas
            .validate("fake-pdp-data", &read_json(&path))
            .unwrap();
        assert!(errors.is_empty(), "{}: {errors:?}", path.display());
    }
}

#[test]
fn a_case_that_needs_a_budget_says_so() {
    // The cases that need a budget action have the condition no_budget_action.
    for case in cases() {
        let text = case.value.to_string();
        let uses_budget = text.contains("\"use_budget\"");
        let skips = case.value["skip_if"]
            .as_array()
            .is_some_and(|a| a.iter().any(|c| c == "no_budget_action"));
        if uses_budget {
            assert!(
                skips,
                "{}: the case uses use_budget and has no skip_if",
                case.stem
            );
        }
        let uses_options = text.contains("\"list_options\"");
        let skips = case.value["skip_if"]
            .as_array()
            .is_some_and(|a| a.iter().any(|c| c == "no_options_route"));
        if uses_options {
            assert!(
                skips,
                "{}: the case uses list_options and has no skip_if",
                case.stem
            );
        }
    }
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            rust_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The paragraph that a test name gives: `p_5_3_unknown_member_is_bad` gives `5.3`.
fn paragraph_of_test_name(name: &str) -> Option<String> {
    let rest = name.strip_prefix("p_")?;
    let mut parts = rest.split('_');
    let first = parts.next()?;
    let second = parts.next()?;
    if first.is_empty() || !first.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let digits = second.trim_end_matches(|c: char| c.is_ascii_lowercase());
    if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_digit()) {
        // A test of a whole section: p_13_example_is_good gives the section 13.
        return Some(first.to_owned());
    }
    Some(format!("{first}.{second}"))
}

#[test]
fn every_test_named_after_a_paragraph_names_a_real_paragraph() {
    let root = repository_root();
    let protocol = paragraph_numbers(&root.join("protocol/procurauth-protocol.md"));
    let mut files = Vec::new();
    rust_files(&root.join("crates"), &mut files);
    let mut count = 0;
    for path in files {
        let text = fs::read_to_string(&path).unwrap();
        for line in text.lines() {
            let Some(name) = line.trim_start().strip_prefix("fn ") else {
                continue;
            };
            let name = name.split('(').next().unwrap();
            if let Some(paragraph) = paragraph_of_test_name(name) {
                assert!(
                    protocol.contains(&paragraph),
                    "{}: the test {name} names the paragraph {paragraph}, which does not exist or is unused",
                    path.display()
                );
                count += 1;
            }
        }
    }
    assert!(
        count > 150,
        "only {count} tests are named after a paragraph"
    );
}
