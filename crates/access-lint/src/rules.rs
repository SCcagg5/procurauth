//! The table of the rules that the tool reports.
//!
//! Each row has the input, the paragraph of the protocol, a stable code,
//! the severity and a short text. The file `RULES.md`
//! shows the same table, and a test makes sure that the two agree.

use procurauth_core::finding::Severity;

/// The input that a rule applies to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Scope {
    /// The action document.
    Document,
    /// The file of grants (`--grants`).
    Grants,
    /// The file of the options route (`--options`).
    Options,
}

impl Scope {
    /// The word for the scope, as the JSON output and `RULES.md` show it.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Document => "document",
            Self::Grants => "grants",
            Self::Options => "options",
        }
    }
}

/// One rule of the table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rule {
    /// The input that the rule applies to.
    pub scope: Scope,
    /// The paragraph of the protocol, for example `5.2`.
    pub rule: &'static str,
    /// The stable code of the finding.
    pub code: &'static str,
    /// Error or warning.
    pub severity: Severity,
    /// The short text of the text output.
    pub summary: &'static str,
}

const fn row(
    scope: Scope,
    rule: &'static str,
    code: &'static str,
    severity: Severity,
    summary: &'static str,
) -> Rule {
    Rule {
        scope,
        rule,
        code,
        severity,
        summary,
    }
}

const E: Severity = Severity::Error;
const W: Severity = Severity::Warning;
const D: Scope = Scope::Document;
const G: Scope = Scope::Grants;
const O: Scope = Scope::Options;

/// All rules, in the order of `RULES.md`.
pub const RULES: &[Rule] = &[
    row(D, "5.3", "bad_json", E, "text is not valid JSON"),
    row(D, "5.2", "wrong_type", E, "value of a wrong type"),
    row(D, "5.2", "missing_member", E, "member is absent"),
    row(D, "5.2", "unknown_member", W, "unknown member"),
    row(
        D,
        "5.3",
        "unknown_member",
        E,
        "unknown member in a limit declaration",
    ),
    row(D, "6.1", "wrong_type", E, "value of a wrong type"),
    row(D, "6.1", "missing_member", E, "member is absent"),
    row(D, "5.2", "bad_server", E, "bad id of the service"),
    row(D, "5.2", "reserved_type_name", E, "type named service"),
    row(D, "5.2", "bad_type_name", E, "bad type name"),
    row(D, "5.2", "duplicate_type_name", E, "duplicate type name"),
    row(D, "5.2", "undeclared_parent", E, "parent is not declared"),
    row(D, "5.2", "type_cycle", E, "parents make a cycle"),
    row(D, "4.1", "type_too_deep", E, "type is deeper than 4"),
    row(D, "5.2", "type_too_deep", E, "path is deeper than 4"),
    row(
        D,
        "5.2",
        "access_in_list",
        E,
        "action access is in the list",
    ),
    row(D, "5.2", "bad_action_name", E, "bad action name"),
    row(
        D,
        "5.2",
        "duplicate_action_name",
        E,
        "duplicate action name",
    ),
    row(D, "5.2", "undeclared_type", E, "undeclared type"),
    row(D, "5.2", "duplicate_type", E, "duplicate type"),
    row(D, "5.2", "undeclared_limit", E, "undeclared limit"),
    row(D, "5.2", "duplicate_limit", E, "duplicate limit"),
    row(D, "5.2", "undeclared_action", E, "undeclared action"),
    row(D, "5.2", "duplicate_action", E, "duplicate action"),
    row(D, "5.2", "bad_path", E, "bad path"),
    row(
        D,
        "5.2",
        "wrong_parent",
        E,
        "segment does not follow the types",
    ),
    row(D, "5.2", "bad_limit_name", E, "bad limit name"),
    row(D, "6.1", "bad_kind", E, "kind is not ceiling or budget"),
    row(D, "6.1", "duplicate_limit_name", E, "duplicate limit name"),
    row(
        D,
        "6.1",
        "budget_name_max",
        E,
        "budget name starts with max_",
    ),
    row(D, "6.1", "budget_with_min", E, "budget with \"min\""),
    row(D, "6.1", "budget_with_max", E, "budget with \"max\""),
    row(
        D,
        "6.1",
        "ceiling_without_bound",
        E,
        "ceiling without a bound",
    ),
    row(D, "6.1", "bad_bound", E, "bound is not a whole number"),
    row(D, "6.1", "min_above_max", E, "min is above max"),
    row(
        D,
        "6.1",
        "budget_name_window",
        W,
        "budget name has a window or a unit",
    ),
    row(
        D,
        "7.1",
        "ceiling_name",
        W,
        "ceiling name is not max_ and a noun",
    ),
    row(
        D,
        "5.3c",
        "above_reader_minimum",
        W,
        "above the minimum of a reader",
    ),
    row(G, "3.5", "bad_json", E, "text is not valid JSON"),
    row(G, "3.5", "wrong_type", E, "value of a wrong type"),
    row(G, "3.5", "missing_member", E, "member is absent"),
    row(G, "3.5", "unknown_member", E, "unknown member"),
    row(G, "5.2", "bad_action_name", E, "bad action name"),
    row(G, "5.2", "undeclared_action", E, "undeclared action"),
    row(
        G,
        "5.2",
        "action_not_valid_on_type",
        E,
        "action is not valid on the type",
    ),
    row(G, "5.2", "bad_limit_name", E, "bad limit name"),
    row(G, "4.1", "bad_path", E, "bad resource path"),
    row(
        G,
        "4.1",
        "unknown_service",
        E,
        "service is not the service of the document",
    ),
    row(
        G,
        "4.1",
        "invalid_node",
        E,
        "node does not follow the types",
    ),
    row(G, "6.1", "wrong_type", E, "value of a wrong type"),
    row(G, "6.1", "missing_member", E, "member is absent"),
    row(G, "6.1", "unknown_member", E, "unknown member"),
    row(
        G,
        "6.1",
        "bad_limit_value",
        E,
        "value is not a number or an array",
    ),
    row(
        G,
        "6.1",
        "bad_ceiling_value",
        E,
        "value of a ceiling is not a whole number",
    ),
    row(
        G,
        "6.1",
        "ceiling_out_of_range",
        E,
        "value of a ceiling is out of range",
    ),
    row(
        G,
        "6.1",
        "bad_budget_value",
        E,
        "budget value is not 1 to 4 items",
    ),
    row(G, "6.1", "bad_amount", E, "amount is not 1 or more"),
    row(G, "6.1", "bad_window", E, "window does not exist"),
    row(G, "6.1", "duplicate_window", E, "duplicate window"),
    row(
        G,
        "6.10",
        "undeclared_limit",
        W,
        "limit is not declared, the value gives nothing",
    ),
    row(
        G,
        "7.3",
        "ceiling_ignored",
        W,
        "the PDP ignores this ceiling",
    ),
    row(
        G,
        "8.3",
        "access_not_on_service",
        E,
        "access is valid only on the service",
    ),
    row(G, "8.3", "budget_ignored", W, "the PDP ignores this budget"),
    row(
        G,
        "8.3",
        "duplicate_budget_value",
        W,
        "second value for one budget",
    ),
    row(O, "5.8", "bad_json", E, "text is not valid JSON"),
    row(O, "5.8", "wrong_type", E, "value of a wrong type"),
    row(O, "5.8", "missing_member", E, "member is absent"),
    row(O, "5.8", "unknown_member", W, "unknown member"),
    row(
        O,
        "5.8",
        "unknown_envelope_member",
        E,
        "unknown member of the options file",
    ),
    row(O, "4.1", "bad_id", E, "bad id"),
    row(O, "4.2", "duplicate_id", W, "duplicate id"),
    row(
        O,
        "5.8",
        "above_caller_minimum",
        W,
        "above the minimum of a caller",
    ),
    row(
        O,
        "5.8",
        "has_children_without_types",
        W,
        "has_children, but the type has no child type",
    ),
    row(
        O,
        "5.7",
        "duplicate_parameter",
        E,
        "parameter occurs more than one time",
    ),
    row(
        O,
        "5.7",
        "bad_parameter_value",
        E,
        "bad value of a parameter",
    ),
    row(O, "5.7", "missing_type", E, "parameter type is absent"),
    row(O, "5.7", "undeclared_type", E, "type is not declared"),
    row(
        O,
        "5.7",
        "wrong_parent_type",
        E,
        "type does not follow the parent",
    ),
    row(
        O,
        "5.7",
        "answer_above_limit",
        E,
        "more items than the limit",
    ),
];

/// The short text for a finding. The function gives `None` for an unknown pair.
pub fn summary(rule: &str, code: &str) -> Option<&'static str> {
    RULES
        .iter()
        .find(|r| r.rule == rule && r.code == code)
        .map(|r| r.summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn p_5_3_each_scope_rule_and_code_occurs_one_time() {
        let mut seen = HashSet::new();
        for rule in RULES {
            assert!(
                seen.insert((rule.scope, rule.rule, rule.code)),
                "{rule:?} occurs two times"
            );
        }
    }

    #[test]
    fn p_5_3_a_summary_has_no_end_mark_and_is_short() {
        for rule in RULES {
            assert!(!rule.summary.ends_with('.'), "{rule:?}");
            assert!(rule.summary.split_whitespace().count() <= 9, "{rule:?}");
        }
    }

    #[test]
    fn p_5_2_summary_finds_a_known_pair() {
        assert_eq!(summary("5.2", "undeclared_limit"), Some("undeclared limit"));
        assert_eq!(summary("9.9", "none"), None);
    }
}
