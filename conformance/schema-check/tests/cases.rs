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

const VARIABLES: [&str; 16] = [
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
    "no_access_key_text",
    "options_type",
    "mcp_path",
    "tool",
    "ceiling",
    "ceiling_value",
];

/// The cases of the series `U`, `D` and `E` are in `conformance/cases/`.
fn cases_dir() -> PathBuf {
    repository_root().join("conformance/cases")
}

fn conformance_dir() -> PathBuf {
    repository_root().join("conformance")
}

/// True when a variable is known. A variable `token_<name>` gives the text of a token.
fn known_variable(name: &str) -> bool {
    VARIABLES.contains(&name) || name.strip_prefix("token_").is_some_and(|t| !t.is_empty())
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
        for path in json_files(&cases_dir().join(series.to_string())) {
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

/// The ids that the MCP binding gives to its cases (binding 9).
const MCP_IDS: [&str; 10] = [
    "U18", "U23", "U25", "U26", "U27", "U28", "U29", "U30", "U31", "E01",
];

#[test]
fn the_cases_of_the_mcp_binding_have_their_ids() {
    let all = cases();
    for id in MCP_IDS {
        let case = all
            .iter()
            .find(|c| c.stem == id)
            .unwrap_or_else(|| panic!("the case {id} of the MCP binding is missing"));
        let paragraphs = case.value["paragraphs"].as_array().unwrap();
        assert!(
            paragraphs
                .iter()
                .any(|p| p.as_str().unwrap().starts_with("mcp:")),
            "{id}: a case of the MCP binding cites a paragraph of the binding"
        );
        assert!(
            case.value["skip_if"]
                .as_array()
                .is_some_and(|a| a.iter().any(|c| c == "no_mcp_endpoint")),
            "{id}: a case of the MCP binding has the condition no_mcp_endpoint"
        );
    }
}

#[test]
fn the_ids_have_no_gap() {
    // Each series counts from 1 to its last number. The ids of the MCP binding fill their places.
    let all = cases();
    for series in ['U', 'D', 'E'] {
        let mut numbers: Vec<u32> = all
            .iter()
            .filter(|c| c.series == series)
            .map(|c| c.stem[1..].parse().unwrap())
            .collect();
        numbers.sort_unstable();
        let start = 1;
        for (index, number) in numbers.iter().enumerate() {
            let expected = start + u32::try_from(index).unwrap();
            assert_eq!(
                *number, expected,
                "series {series}: the numbers have a gap before {series}{number}"
            );
        }
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

/// Replace each variable of a text with the letter x.
fn replace_variables(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            break;
        };
        out.push_str(&rest[..start]);
        out.push('x');
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out
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
                        known_variable(&name),
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
            for key in ["regex", "not_regex"] {
                if let Some(Value::String(expression)) = value.as_object().and_then(|m| m.get(key))
                {
                    // The runner replaces a variable before it compiles the expression.
                    let expression = replace_variables(expression);
                    regex::Regex::new(&expression)
                        .unwrap_or_else(|e| panic!("{id}: bad regular expression at {path}: {e}"));
                }
            }
        };
        walk(&case.value, "", &mut check);
    }
}

#[test]
fn every_matcher_has_exactly_one_member() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap().to_owned();
        let known = [
            "equals",
            "absent",
            "present",
            "regex",
            "not_regex",
            "one_of",
        ];
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

/// The names of the tokens that a step uses: the member `token`, or a variable `token_<name>`.
fn tokens_used(case: &Value) -> BTreeSet<String> {
    let mut used = BTreeSet::new();
    for step in case["steps"].as_array().unwrap() {
        if let Some(name) = step["request"].get("token").and_then(Value::as_str) {
            used.insert(name.to_owned());
        }
        let mut check = |_: &str, value: &Value| {
            if let Value::String(text) = value {
                for name in variables_in(text) {
                    if let Some(token) = name.strip_prefix("token_") {
                        used.insert(token.to_owned());
                    }
                }
            }
        };
        walk(&step["request"], "", &mut check);
    }
    used
}

#[test]
fn every_token_that_a_step_uses_exists_and_every_token_is_used() {
    for case in cases() {
        let id = case.value["id"].as_str().unwrap();
        let defined: BTreeSet<String> = case.value["given"]
            .get("tokens")
            .and_then(Value::as_object)
            .map(|m| m.keys().cloned().collect())
            .unwrap_or_default();
        let used = tokens_used(&case.value);
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

fn skip_list(value: &Value) -> BTreeSet<String> {
    value
        .get("skip_if")
        .and_then(Value::as_array)
        .map(|a| a.iter().map(|c| c.as_str().unwrap().to_owned()).collect())
        .unwrap_or_default()
}

/// The conditions that a step needs: an operation or a variable that only some services have.
fn needed_conditions(step: &Value) -> Vec<&'static str> {
    let mut needed = Vec::new();
    let operation = step["request"]
        .get("operation")
        .and_then(Value::as_str)
        .unwrap_or("");
    match operation {
        "use_budget" => needed.push("no_budget_action"),
        "use_ceiling" => needed.push("no_ceiling_action"),
        "use_multi" => needed.extend(["no_budget_action", "no_multi_action"]),
        "list_options" => needed.push("no_options_route"),
        "mcp_call_budget" => needed.extend(["no_mcp_endpoint", "no_budget_action"]),
        "mcp_call_multi" => {
            needed.extend(["no_mcp_endpoint", "no_budget_action", "no_multi_action"])
        }
        "mcp_call_input" => needed.extend(["no_mcp_endpoint", "no_input_tool"]),
        "mcp_call_approval" | "mcp_approve" | "mcp_refuse" => {
            needed.extend(["no_mcp_endpoint", "no_approval_tool"]);
        }
        op if op.starts_with("mcp_") => needed.push("no_mcp_endpoint"),
        _ => {}
    }
    let text = step["request"].to_string();
    if text.contains("{{mcp_path}}") {
        needed.push("no_mcp_endpoint");
    }
    if text.contains("{{options_type}}") || text.contains("/.well-known/procurauth/resources") {
        needed.push("no_options_route");
    }
    needed
}

#[test]
fn a_case_that_needs_a_service_profile_says_so() {
    for case in cases() {
        let case_skip = skip_list(&case.value);
        for step in case.value["steps"].as_array().unwrap() {
            let mut have = case_skip.clone();
            have.extend(skip_list(step));
            for condition in needed_conditions(step) {
                assert!(
                    have.contains(condition),
                    "{}: a step needs the condition {condition}, and the case does not give it",
                    case.stem
                );
            }
        }
        let text = case.value["given"].to_string();
        if text.contains("{{ceiling") {
            assert!(
                case_skip.contains("no_ceiling_action"),
                "{}: the case uses a ceiling of the profile and has no condition",
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

// ---------------------------------------------------------------------------------------------
// The file conformance/COVERAGE.md
// ---------------------------------------------------------------------------------------------

/// The number of a paragraph, as a section and a paragraph in the section. A section has no second number.
fn split_number(text: &str) -> (u32, Option<u32>) {
    let mut parts = text.split('.');
    let section = parts.next().unwrap().parse().unwrap();
    let paragraph = parts.next().map(|p| {
        p.trim_end_matches(|c: char| c.is_ascii_lowercase())
            .parse()
            .unwrap()
    });
    (section, paragraph)
}

/// The paragraphs that a role must follow: protocol 1.3 and 15 (item 2), and binding 1.4.
fn required_paragraphs(role: &str) -> BTreeSet<String> {
    let root = repository_root();
    let protocol = paragraph_numbers(&root.join("protocol/procurauth-protocol.md"));
    let binding = paragraph_numbers(&root.join("bindings/mcp/procurauth-mcp-binding.md"));
    let mut out = BTreeSet::new();
    match role {
        "pdp" => {
            for p in &protocol {
                let keep = match split_number(p) {
                    (12, None) => true,
                    (_, None) => false,
                    (3 | 4 | 6 | 7 | 8 | 11, Some(_)) => true,
                    (5, Some(n)) => (1..=5).contains(&n),
                    (10, Some(n)) => n == 7,
                    _ => false,
                };
                if keep {
                    out.insert(p.clone());
                }
            }
        }
        "pep" => {
            let explicit = [
                "3.3", "3.4", "4.1", "4.4", "4.5", "5.1", "5.2", "5.3c", "5.4", "5.5", "5.5a",
                "5.6", "5.7", "5.8", "6.1", "6.2", "6.4", "6.11", "6.12", "7.1", "7.3", "7.4",
                "7.5", "7.6", "8.3", "9.3", "9.4", "9.5", "9.6", "9.7", "15",
            ];
            for p in &protocol {
                let (section, paragraph) = split_number(p);
                if explicit.contains(&p.as_str())
                    || (matches!(section, 10 | 11) && paragraph.is_some())
                {
                    out.insert(p.clone());
                }
            }
            for p in &binding {
                let (section, paragraph) = split_number(p);
                if paragraph.is_some()
                    && (matches!(section, 3..=5)
                        || ["1.3", "7.1", "7.2", "7.3", "7.4"].contains(&p.as_str()))
                {
                    out.insert(format!("mcp:{p}"));
                }
            }
        }
        _ => {
            for p in ["1.4", "8.3", "9.1", "9.2", "9.3", "9.4", "9.8", "9.9"] {
                out.insert(p.to_owned());
            }
            for p in ["6.1", "6.2", "6.3"] {
                out.insert(format!("mcp:{p}"));
            }
        }
    }
    out
}

/// The rows of the table of COVERAGE.md under the title `## <heading>`.
fn coverage_rows(heading: &str, columns: usize) -> Vec<Vec<String>> {
    let text = fs::read_to_string(conformance_dir().join("COVERAGE.md")).unwrap();
    let mut rows = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        if let Some(title) = line.strip_prefix("## ") {
            inside = title.trim() == heading;
            continue;
        }
        if !inside || !line.starts_with('|') {
            continue;
        }
        let cells: Vec<String> = line
            .trim()
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().to_owned())
            .collect();
        assert_eq!(cells.len(), columns, "COVERAGE.md: bad row {line}");
        if cells[0] == "Paragraph" || cells[0].starts_with("---") {
            continue;
        }
        rows.push(cells);
    }
    rows
}

fn role_of(series: char) -> &'static str {
    match series {
        'U' => "pep",
        'D' => "pdp",
        _ => "edge",
    }
}

#[test]
fn coverage_has_a_row_for_each_paragraph_that_a_role_must_follow() {
    let rows = coverage_rows("Cases for each paragraph", 3);
    let mut seen = BTreeSet::new();
    for row in &rows {
        assert!(
            seen.insert((row[0].clone(), row[1].clone())),
            "COVERAGE.md: the row {} {} occurs two times",
            row[0],
            row[1]
        );
    }
    for role in ["pdp", "pep", "edge"] {
        for paragraph in required_paragraphs(role) {
            assert!(
                seen.contains(&(paragraph.clone(), role.to_owned())),
                "COVERAGE.md: no row for the paragraph {paragraph} and the role {role}"
            );
        }
        let required = required_paragraphs(role);
        for (paragraph, row_role) in &seen {
            if row_role == role {
                assert!(
                    required.contains(paragraph),
                    "COVERAGE.md: the paragraph {paragraph} is not a paragraph that the role {role} must follow"
                );
            }
        }
    }
}

#[test]
fn coverage_and_the_cases_agree() {
    let rows = coverage_rows("Cases for each paragraph", 3);
    let all = cases();
    let mut listed: BTreeSet<(String, String)> = BTreeSet::new();
    for row in &rows {
        let (paragraph, role) = (&row[0], &row[1]);
        if row[2] == "none" {
            continue;
        }
        for id in row[2].split(',').map(str::trim) {
            let case = all
                .iter()
                .find(|c| c.stem == id)
                .unwrap_or_else(|| panic!("COVERAGE.md: the case {id} does not exist"));
            assert_eq!(
                case.value["role"], *role,
                "COVERAGE.md: the case {id} has another role than the row {paragraph}"
            );
            let cites = case.value["paragraphs"]
                .as_array()
                .unwrap()
                .iter()
                .any(|p| p == paragraph.as_str());
            assert!(
                cites,
                "COVERAGE.md: the case {id} does not cite the paragraph {paragraph}"
            );
            assert!(
                listed.insert((paragraph.clone(), id.to_owned())),
                "COVERAGE.md: the case {id} occurs two times in the row {paragraph}"
            );
        }
    }
    for case in &all {
        let role = role_of(case.series);
        let required = required_paragraphs(role);
        for paragraph in case.value["paragraphs"].as_array().unwrap() {
            let paragraph = paragraph.as_str().unwrap();
            assert!(
                required.contains(paragraph),
                "{}: the paragraph {paragraph} is not a paragraph that the role {role} must follow",
                case.stem
            );
            assert!(
                listed.contains(&(paragraph.to_owned(), case.stem.clone())),
                "{}: COVERAGE.md does not list the case in the row {paragraph}",
                case.stem
            );
        }
    }
}

#[test]
fn coverage_gives_a_reason_for_each_paragraph_with_no_case() {
    let rows = coverage_rows("Cases for each paragraph", 3);
    let reasons = coverage_rows("Not testable", 4);
    let main: BTreeSet<(String, String)> =
        rows.iter().map(|r| (r[0].clone(), r[1].clone())).collect();
    for row in &rows {
        if row[2] == "none" {
            assert!(
                reasons.iter().any(|r| r[0] == row[0] && r[1] == row[1]),
                "COVERAGE.md: the paragraph {} for {} has no case and no reason",
                row[0],
                row[1]
            );
        }
    }
    for reason in &reasons {
        assert!(
            main.contains(&(reason[0].clone(), reason[1].clone())),
            "COVERAGE.md: the table Not testable names the paragraph {} for {}, and the first table has no such row",
            reason[0],
            reason[1]
        );
        assert!(
            !reason[2].is_empty() && !reason[3].is_empty(),
            "COVERAGE.md: a row of the table Not testable has an empty cell"
        );
    }
}
