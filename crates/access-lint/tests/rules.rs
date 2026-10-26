//! One test for each rule of the table. Each rule has a bad fixture and a good fixture.
//!
//! The fixtures are in `tests/fixtures/<scope>/<rule>_<code>/`. A bad fixture gives a
//! finding with the rule and the code of the table. A good fixture gives no finding.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use access_lint::check::{LintFinding, check_document, check_grants, check_options};
use access_lint::rules::{RULES, Scope};
use procurauth_core::action_document::ActionDocument;

fn read(path: &str) -> String {
    let full = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(path);
    fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

fn context() -> ActionDocument {
    ActionDocument::parse_str(&read("context/document.json")).unwrap()
}

fn lint(scope: Scope, text: &str) -> Vec<LintFinding> {
    match scope {
        Scope::Document => check_document(text).1,
        Scope::Grants => check_grants(text, Some(&context())),
        Scope::Options => check_options(text, Some(&context())),
    }
}

fn describe(findings: &[LintFinding]) -> String {
    findings
        .iter()
        .map(|f| format!("{} {} {} {}", f.path, f.rule, f.code, f.message))
        .collect::<Vec<_>>()
        .join("\n")
}

fn check_rule(scope: Scope, rule: &str, code: &str) {
    let row = RULES
        .iter()
        .find(|r| r.scope == scope && r.rule == rule && r.code == code)
        .unwrap_or_else(|| panic!("no row for {rule} {code}"));
    let dir = format!("{}/{rule}_{code}", scope.as_str());
    let failing = lint(scope, &read(&format!("{dir}/fail.json")));
    let hit = failing
        .iter()
        .find(|f| f.rule == rule && f.code == code)
        .unwrap_or_else(|| {
            panic!(
                "{dir}/fail.json gives no {rule} {code}:\n{}",
                describe(&failing)
            )
        });
    assert_eq!(hit.severity, row.severity, "{dir}: severity");
    for finding in &failing {
        let known = RULES.iter().any(|r| {
            r.scope == scope
                && r.rule == finding.rule
                && r.code == finding.code
                && r.severity == finding.severity
        });
        assert!(
            known,
            "{dir}/fail.json: a finding is not in the table: {}",
            describe(std::slice::from_ref(finding))
        );
    }
    let passing = lint(scope, &read(&format!("{dir}/pass.json")));
    assert!(
        passing.is_empty(),
        "{dir}/pass.json gives findings:\n{}",
        describe(&passing)
    );
}

macro_rules! rule_tests {
    ($($name:ident: $scope:ident, $rule:literal, $code:literal;)*) => {
        $(
            #[test]
            fn $name() {
                check_rule(Scope::$scope, $rule, $code);
            }
        )*
        const TESTED: &[(Scope, &str, &str)] = &[$((Scope::$scope, $rule, $code)),*];
    };
}

rule_tests! {
    p_5_3_document_bad_json: Document, "5.3", "bad_json";
    p_5_2_document_wrong_type: Document, "5.2", "wrong_type";
    p_5_2_document_missing_member: Document, "5.2", "missing_member";
    p_5_2_document_unknown_member: Document, "5.2", "unknown_member";
    p_5_3_document_unknown_member: Document, "5.3", "unknown_member";
    p_6_1_document_wrong_type: Document, "6.1", "wrong_type";
    p_6_1_document_missing_member: Document, "6.1", "missing_member";
    p_5_2_document_bad_server: Document, "5.2", "bad_server";
    p_5_2_document_reserved_type_name: Document, "5.2", "reserved_type_name";
    p_5_2_document_bad_type_name: Document, "5.2", "bad_type_name";
    p_5_2_document_duplicate_type_name: Document, "5.2", "duplicate_type_name";
    p_5_2_document_undeclared_parent: Document, "5.2", "undeclared_parent";
    p_5_2_document_type_cycle: Document, "5.2", "type_cycle";
    p_4_1_document_type_too_deep: Document, "4.1", "type_too_deep";
    p_5_2_document_type_too_deep: Document, "5.2", "type_too_deep";
    p_5_2_document_access_in_list: Document, "5.2", "access_in_list";
    p_5_2_document_bad_action_name: Document, "5.2", "bad_action_name";
    p_5_2_document_duplicate_action_name: Document, "5.2", "duplicate_action_name";
    p_5_2_document_undeclared_type: Document, "5.2", "undeclared_type";
    p_5_2_document_duplicate_type: Document, "5.2", "duplicate_type";
    p_5_2_document_undeclared_limit: Document, "5.2", "undeclared_limit";
    p_5_2_document_duplicate_limit: Document, "5.2", "duplicate_limit";
    p_5_2_document_undeclared_action: Document, "5.2", "undeclared_action";
    p_5_2_document_duplicate_action: Document, "5.2", "duplicate_action";
    p_5_2_document_bad_path: Document, "5.2", "bad_path";
    p_5_2_document_wrong_parent: Document, "5.2", "wrong_parent";
    p_5_2_document_bad_limit_name: Document, "5.2", "bad_limit_name";
    p_6_1_document_bad_kind: Document, "6.1", "bad_kind";
    p_6_1_document_duplicate_limit_name: Document, "6.1", "duplicate_limit_name";
    p_6_1_document_budget_name_max: Document, "6.1", "budget_name_max";
    p_6_1_document_budget_with_min: Document, "6.1", "budget_with_min";
    p_6_1_document_budget_with_max: Document, "6.1", "budget_with_max";
    p_6_1_document_ceiling_without_bound: Document, "6.1", "ceiling_without_bound";
    p_6_1_document_bad_bound: Document, "6.1", "bad_bound";
    p_6_1_document_min_above_max: Document, "6.1", "min_above_max";
    p_6_1_document_budget_name_window: Document, "6.1", "budget_name_window";
    p_7_1_document_ceiling_name: Document, "7.1", "ceiling_name";
    p_5_3c_document_above_reader_minimum: Document, "5.3c", "above_reader_minimum";
    p_3_5_grants_bad_json: Grants, "3.5", "bad_json";
    p_3_5_grants_wrong_type: Grants, "3.5", "wrong_type";
    p_3_5_grants_missing_member: Grants, "3.5", "missing_member";
    p_3_5_grants_unknown_member: Grants, "3.5", "unknown_member";
    p_5_2_grants_bad_action_name: Grants, "5.2", "bad_action_name";
    p_5_2_grants_undeclared_action: Grants, "5.2", "undeclared_action";
    p_5_2_grants_action_not_valid_on_type: Grants, "5.2", "action_not_valid_on_type";
    p_5_2_grants_bad_limit_name: Grants, "5.2", "bad_limit_name";
    p_4_1_grants_bad_path: Grants, "4.1", "bad_path";
    p_4_1_grants_unknown_service: Grants, "4.1", "unknown_service";
    p_4_1_grants_invalid_node: Grants, "4.1", "invalid_node";
    p_6_1_grants_wrong_type: Grants, "6.1", "wrong_type";
    p_6_1_grants_missing_member: Grants, "6.1", "missing_member";
    p_6_1_grants_unknown_member: Grants, "6.1", "unknown_member";
    p_6_1_grants_bad_limit_value: Grants, "6.1", "bad_limit_value";
    p_6_1_grants_bad_ceiling_value: Grants, "6.1", "bad_ceiling_value";
    p_6_1_grants_ceiling_out_of_range: Grants, "6.1", "ceiling_out_of_range";
    p_6_1_grants_bad_budget_value: Grants, "6.1", "bad_budget_value";
    p_6_1_grants_bad_amount: Grants, "6.1", "bad_amount";
    p_6_1_grants_bad_window: Grants, "6.1", "bad_window";
    p_6_1_grants_duplicate_window: Grants, "6.1", "duplicate_window";
    p_6_10_grants_undeclared_limit: Grants, "6.10", "undeclared_limit";
    p_7_3_grants_ceiling_ignored: Grants, "7.3", "ceiling_ignored";
    p_8_3_grants_access_not_on_service: Grants, "8.3", "access_not_on_service";
    p_8_3_grants_budget_ignored: Grants, "8.3", "budget_ignored";
    p_8_3_grants_duplicate_budget_value: Grants, "8.3", "duplicate_budget_value";
    p_5_8_options_bad_json: Options, "5.8", "bad_json";
    p_5_8_options_wrong_type: Options, "5.8", "wrong_type";
    p_5_8_options_missing_member: Options, "5.8", "missing_member";
    p_5_8_options_unknown_member: Options, "5.8", "unknown_member";
    p_5_8_options_unknown_envelope_member: Options, "5.8", "unknown_envelope_member";
    p_4_1_options_bad_id: Options, "4.1", "bad_id";
    p_4_2_options_duplicate_id: Options, "4.2", "duplicate_id";
    p_5_8_options_above_caller_minimum: Options, "5.8", "above_caller_minimum";
    p_5_8_options_has_children_without_types: Options, "5.8", "has_children_without_types";
    p_5_7_options_duplicate_parameter: Options, "5.7", "duplicate_parameter";
    p_5_7_options_bad_parameter_value: Options, "5.7", "bad_parameter_value";
    p_5_7_options_missing_type: Options, "5.7", "missing_type";
    p_5_7_options_undeclared_type: Options, "5.7", "undeclared_type";
    p_5_7_options_wrong_parent_type: Options, "5.7", "wrong_parent_type";
    p_5_7_options_answer_above_limit: Options, "5.7", "answer_above_limit";
}

#[test]
fn every_rule_of_the_table_has_a_test() {
    let tested: BTreeSet<_> = TESTED
        .iter()
        .map(|(s, r, c)| (s.as_str(), *r, *c))
        .collect();
    let table: BTreeSet<_> = RULES
        .iter()
        .map(|r| (r.scope.as_str(), r.rule, r.code))
        .collect();
    assert_eq!(tested, table);
}

#[test]
fn every_fixture_directory_belongs_to_a_rule() {
    let table: BTreeSet<String> = RULES
        .iter()
        .map(|r| format!("{}/{}_{}", r.scope.as_str(), r.rule, r.code))
        .collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    for scope in ["document", "grants", "options"] {
        for entry in fs::read_dir(root.join(scope)).unwrap() {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            assert!(
                table.contains(&format!("{scope}/{name}")),
                "{scope}/{name} has no rule"
            );
        }
    }
}

#[test]
fn the_rules_file_lists_the_table() {
    let text = fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("RULES.md")).unwrap();
    let mut listed = BTreeSet::new();
    for line in text
        .lines()
        .filter(|l| l.starts_with("| ") && !l.starts_with("| Scope") && !l.starts_with("| ---"))
    {
        let cells: Vec<&str> = line.trim_matches('|').split('|').map(str::trim).collect();
        assert_eq!(cells.len(), 6, "{line}");
        let severity = cells[3];
        listed.insert((
            cells[0].to_owned(),
            cells[1].to_owned(),
            cells[2].trim_matches('`').to_owned(),
            severity.to_owned(),
        ));
    }
    let table: BTreeSet<_> = RULES
        .iter()
        .map(|r| {
            let severity = match r.severity {
                procurauth_core::finding::Severity::Error => "error",
                procurauth_core::finding::Severity::Warning => "warning",
            };
            (
                r.scope.as_str().to_owned(),
                r.rule.to_owned(),
                r.code.to_owned(),
                severity.to_owned(),
            )
        })
        .collect();
    assert_eq!(listed, table);
}
