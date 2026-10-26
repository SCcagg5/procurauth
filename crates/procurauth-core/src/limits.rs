//! Limit values and the combination of values (protocol sections 6 to 8).
//!
//! A grant gives a value for a limit. A ceiling value is a whole number. A
//! budget value is a list of one to four items, one for each window.
//! This module reads the values and checks them against the declarations.
//! It also has the pure functions that a PDP needs: the windows (6.3), the
//! lowest value (8.1) and `retry_after` (11.1).

use std::collections::{BTreeMap, HashSet};

use serde_json::{Map, Value, json};

use crate::action_document::{ActionDocument, LimitKind};
use crate::finding::{JsonPath, Report, show, type_word};
use crate::names::is_type_or_limit_name;
use crate::read::{Obj, Unknown};

/// The length of a window of a budget (6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Window {
    /// One second.
    Second,
    /// One minute.
    Minute,
    /// One hour.
    Hour,
    /// One day.
    Day,
}

impl Window {
    /// The four windows, from the shortest.
    pub const ALL: [Window; 4] = [Self::Second, Self::Minute, Self::Hour, Self::Day];

    /// The word of the protocol.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Second => "second",
            Self::Minute => "minute",
            Self::Hour => "hour",
            Self::Day => "day",
        }
    }

    /// Read the word of the protocol.
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|w| w.as_str() == text)
    }

    /// The length of the window, in seconds.
    pub fn seconds(self) -> u64 {
        match self {
            Self::Second => 1,
            Self::Minute => 60,
            Self::Hour => 3600,
            Self::Day => 86_400,
        }
    }
}

/// One item of a budget value: an amount for one window (6.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BudgetItem {
    /// The units that the grant gives for one window. It is 1 or more.
    pub amount: u64,
    /// The window.
    pub window: Window,
}

/// The value that a grant gives for one limit (6.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LimitValue {
    /// A ceiling: a whole number.
    Ceiling(u64),
    /// A budget: one to four items.
    Budget(Vec<BudgetItem>),
}

impl LimitValue {
    /// The value as JSON, in the form of 6.1.
    pub fn to_value(&self) -> Value {
        match self {
            Self::Ceiling(number) => json!(number),
            Self::Budget(items) => Value::Array(
                items
                    .iter()
                    .map(|i| json!({"amount": i.amount, "window": i.window.as_str()}))
                    .collect(),
            ),
        }
    }
}

/// The limit values of one grant, by the name of the limit.
pub type LimitValues = BTreeMap<String, LimitValue>;

/// The values as a JSON object.
pub fn limit_values_to_value(values: &LimitValues) -> Value {
    Value::Object(
        values
            .iter()
            .map(|(name, value)| (name.clone(), value.to_value()))
            .collect::<Map<_, _>>(),
    )
}

/// Read the limit values of a grant.
/// When `document` is given, the function checks each value against the declaration of its limit (6.1).
/// It also warns about a limit that the document does not declare (6.10).
pub fn read_limit_values(
    value: &Value,
    path: &JsonPath,
    document: Option<&ActionDocument>,
    report: &mut Report,
) -> LimitValues {
    let mut out = LimitValues::new();
    let Value::Object(map) = value else {
        report.error(
            path,
            "6.1",
            "wrong_type",
            format!(
                "Expected an object, found {}: {}.",
                type_word(value),
                show(value)
            ),
        );
        return out;
    };
    for (name, item) in map {
        let item_path = path.key(name);
        if !is_type_or_limit_name(name) {
            report.error(
                &item_path,
                "5.2",
                "bad_limit_name",
                format!("Limit name {}: expected 1 to 32 characters, a to z first, then a to z, 0 to 9 or underscore.", show(&json!(name))),
            );
            continue;
        }
        let declaration = document.and_then(|d| d.limit(name));
        if document.is_some() && declaration.is_none() {
            report.warning(
                &item_path,
                "6.10",
                "undeclared_limit",
                format!("Limit `{name}` is not declared in the document. The value gives nothing."),
            );
        }
        let kind = match declaration {
            Some(d) => Some(d.kind),
            None if item.is_array() => Some(LimitKind::Budget),
            None if item.is_number() => Some(LimitKind::Ceiling),
            None => {
                report.error(
                    &item_path,
                    "6.1",
                    "bad_limit_value",
                    format!(
                        "Value of `{name}`: expected a whole number or an array, found {}: {}.",
                        type_word(item),
                        show(item)
                    ),
                );
                continue;
            }
        };
        let parsed = match kind {
            Some(LimitKind::Ceiling) => read_ceiling(name, item, &item_path, declaration, report),
            Some(LimitKind::Budget) => read_budget(name, item, &item_path, report),
            None => None,
        };
        if let Some(parsed) = parsed {
            out.insert(name.clone(), parsed);
        }
    }
    out
}

fn read_ceiling(
    name: &str,
    value: &Value,
    path: &JsonPath,
    declaration: Option<&crate::action_document::LimitDeclaration>,
    report: &mut Report,
) -> Option<LimitValue> {
    let Some(number) = value.as_u64() else {
        report.error(
            path,
            "6.1",
            "bad_ceiling_value",
            format!(
                "Value of ceiling `{name}`: expected a whole number, found {}: {}.",
                type_word(value),
                show(value)
            ),
        );
        return None;
    };
    if let Some(decl) = declaration {
        let low = decl.min.unwrap_or(0);
        let high = decl.max.unwrap_or(u64::MAX);
        if number < low || number > high {
            report.error(
                path,
                "6.1",
                "ceiling_out_of_range",
                format!("Value of ceiling `{name}`: expected a whole number from {low} to {high}, found {number}."),
            );
            return None;
        }
    }
    Some(LimitValue::Ceiling(number))
}

fn read_budget(
    name: &str,
    value: &Value,
    path: &JsonPath,
    report: &mut Report,
) -> Option<LimitValue> {
    let Some(items) = value.as_array() else {
        report.error(
            path,
            "6.1",
            "bad_budget_value",
            format!(
                "Value of budget `{name}`: expected an array of 1 to 4 items, found {}: {}.",
                type_word(value),
                show(value)
            ),
        );
        return None;
    };
    if items.is_empty() || items.len() > 4 {
        report.error(
            path,
            "6.1",
            "bad_budget_value",
            format!(
                "Value of budget `{name}`: expected an array of 1 to 4 items, found {} items.",
                items.len()
            ),
        );
        return None;
    }
    let start = report.error_count();
    let mut out = Vec::new();
    let mut windows = HashSet::new();
    for (index, item) in items.iter().enumerate() {
        let item_path = path.index(index);
        let Some(mut obj) = Obj::new(item, &item_path, "6.1", Unknown::Error, report) else {
            continue;
        };
        let amount = obj.whole("amount", report);
        let window_text = obj.string("window", report);
        obj.finish(report);
        if amount == Some(0) {
            report.error(
                &item_path.key("amount"),
                "6.1",
                "bad_amount",
                "Member `amount`: expected a whole number from 1, found 0.",
            );
        }
        let window = window_text.and_then(|text| {
            let window = Window::parse(text);
            if window.is_none() {
                report.error(
                    &item_path.key("window"),
                    "6.1",
                    "bad_window",
                    format!(
                        "Member `window`: expected `second`, `minute`, `hour` or `day`, found {}.",
                        show(&json!(text))
                    ),
                );
            }
            window
        });
        if let Some(window) = window
            && !windows.insert(window)
        {
            report.error(
                &item_path.key("window"),
                "6.1",
                "duplicate_window",
                format!("Window `{}` occurs more than one time.", window.as_str()),
            );
        }
        if let (Some(amount), Some(window)) = (amount, window) {
            out.push(BudgetItem { amount, window });
        }
    }
    (report.error_count() == start).then_some(LimitValue::Budget(out))
}

/// The start of the window that holds `now_seconds`, in seconds since the Unix
/// epoch. A window starts at a multiple of its length (6.3).
pub fn window_start(now_seconds: u64, window: Window) -> u64 {
    now_seconds - now_seconds % window.seconds()
}

/// The seconds from `now_millis` to the end of the current window, rounded up
/// to a whole number of 1 or more (11.1).
pub fn seconds_to_window_end(now_millis: u64, window: Window) -> u64 {
    let length = window.seconds() * 1000;
    let remaining = length - now_millis % length;
    remaining.div_ceil(1000).max(1)
}

/// The value of `retry_after` (11.1): the seconds to the latest end among the
/// windows of the counters that refuse. It is a whole number of 1 or more.
pub fn retry_after(now_millis: u64, refusing: impl IntoIterator<Item = Window>) -> u64 {
    refusing
        .into_iter()
        .map(|window| seconds_to_window_end(now_millis, window))
        .max()
        .unwrap_or(1)
}

/// The lowest of some ceiling values (8.1).
pub fn lowest(values: impl IntoIterator<Item = u64>) -> Option<u64> {
    values.into_iter().min()
}

/// Combine the ceilings of the two sides of a decision for a key (8.1, 8.2).
/// A name on both sides gets the lower value. A name on one side keeps its value.
pub fn combine_sides(
    key: &BTreeMap<String, u64>,
    owner: &BTreeMap<String, u64>,
) -> BTreeMap<String, u64> {
    let mut out = key.clone();
    for (name, value) in owner {
        out.entry(name.clone())
            .and_modify(|existing| *existing = (*existing).min(*value))
            .or_insert(*value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn document() -> ActionDocument {
        ActionDocument::from_value(&json!({
            "server": "datastore",
            "resource_types": [],
            "actions": [],
            "limits": [
                {"name": "requests", "label": "R", "description": "R.", "unit": "request", "kind": "budget"},
                {"name": "max_rows", "label": "R", "description": "R.", "unit": "row", "kind": "ceiling", "min": 1, "max": 1000}
            ]
        }))
        .unwrap()
    }

    fn read(value: &Value, doc: Option<&ActionDocument>) -> (LimitValues, Report) {
        let mut report = Report::new();
        let values = read_limit_values(value, &JsonPath::root(), doc, &mut report);
        (values, report)
    }

    fn codes(report: &Report) -> Vec<(&str, &'static str)> {
        report
            .findings()
            .iter()
            .map(|f| (f.path.as_str(), f.code))
            .collect()
    }

    #[test]
    fn p_6_1_good_values() {
        let value = json!({"requests": [{"amount": 10, "window": "second"}, {"amount": 300, "window": "minute"}], "max_rows": 1000});
        let (values, report) = read(&value, Some(&document()));
        assert!(report.findings().is_empty());
        assert_eq!(values["max_rows"], LimitValue::Ceiling(1000));
        assert_eq!(
            values["requests"],
            LimitValue::Budget(vec![
                BudgetItem {
                    amount: 10,
                    window: Window::Second
                },
                BudgetItem {
                    amount: 300,
                    window: Window::Minute
                },
            ])
        );
        assert_eq!(limit_values_to_value(&values), value);
    }

    #[test]
    fn p_6_1_ceiling_must_be_in_the_declared_range() {
        for bad in [
            json!(0),
            json!(1001),
            json!(-1),
            json!(1.5),
            json!("5"),
            json!([1]),
        ] {
            let (values, report) = read(&json!({"max_rows": bad}), Some(&document()));
            assert!(report.has_errors(), "{bad}");
            assert!(values.is_empty());
        }
        for good in [1, 1000] {
            let (_, report) = read(&json!({"max_rows": good}), Some(&document()));
            assert!(!report.has_errors());
        }
    }

    #[test]
    fn p_6_1_budget_has_one_to_four_items() {
        let (_, report) = read(&json!({"requests": []}), Some(&document()));
        assert_eq!(codes(&report), vec![("$.requests", "bad_budget_value")]);
        let five: Vec<Value> = (0..5)
            .map(|_| json!({"amount": 1, "window": "day"}))
            .collect();
        let (_, report) = read(&json!({"requests": five}), Some(&document()));
        assert_eq!(codes(&report), vec![("$.requests", "bad_budget_value")]);
        let four: Vec<Value> = Window::ALL
            .iter()
            .map(|w| json!({"amount": 1, "window": w.as_str()}))
            .collect();
        let (values, report) = read(&json!({"requests": four}), Some(&document()));
        assert!(report.findings().is_empty());
        assert!(matches!(&values["requests"], LimitValue::Budget(items) if items.len() == 4));
    }

    #[test]
    fn p_6_1_budget_item_rules() {
        let value = json!({"requests": [
            {"amount": 0, "window": "minute"},
            {"amount": 1, "window": "week"},
            {"amount": 1.5, "window": "hour"},
            {"amount": 1, "window": "day", "extra": 1},
        ]});
        let (_, report) = read(&value, Some(&document()));
        assert_eq!(
            codes(&report),
            vec![
                ("$.requests[0].amount", "bad_amount"),
                ("$.requests[1].window", "bad_window"),
                ("$.requests[2].amount", "wrong_type"),
                ("$.requests[3].extra", "unknown_member"),
            ]
        );
        let (_, report) = read(&json!({"requests": [{"amount": 1}]}), Some(&document()));
        assert_eq!(codes(&report), vec![("$.requests[0]", "missing_member")]);
    }

    #[test]
    fn p_6_1_two_items_never_have_the_same_window() {
        let value = json!({"requests": [{"amount": 1, "window": "minute"}, {"amount": 2, "window": "minute"}]});
        let (_, report) = read(&value, Some(&document()));
        assert_eq!(
            codes(&report),
            vec![("$.requests[1].window", "duplicate_window")]
        );
    }

    #[test]
    fn p_6_1_a_value_must_fit_the_kind_of_its_limit() {
        let (_, report) = read(
            &json!({"requests": 5, "max_rows": [{"amount": 1, "window": "day"}]}),
            Some(&document()),
        );
        assert_eq!(
            codes(&report),
            vec![
                ("$.max_rows", "bad_ceiling_value"),
                ("$.requests", "bad_budget_value")
            ]
        );
    }

    #[test]
    fn p_6_10_a_value_for_an_undeclared_limit_gives_nothing() {
        let (values, report) = read(&json!({"ghost": 5}), Some(&document()));
        assert_eq!(codes(&report), vec![("$.ghost", "undeclared_limit")]);
        assert!(!report.has_errors());
        assert_eq!(values["ghost"], LimitValue::Ceiling(5));
    }

    #[test]
    fn p_6_1_without_a_document_the_json_type_gives_the_kind() {
        let (values, report) = read(
            &json!({"a": 5, "b": [{"amount": 2, "window": "hour"}]}),
            None,
        );
        assert!(report.findings().is_empty());
        assert!(matches!(values["a"], LimitValue::Ceiling(5)));
        assert!(matches!(values["b"], LimitValue::Budget(_)));
        let (_, report) = read(&json!({"a": "x", "Bad": 1}), None);
        assert_eq!(
            codes(&report),
            vec![("$.Bad", "bad_limit_name"), ("$.a", "bad_limit_value")]
        );
    }

    #[test]
    fn p_6_3_window_starts_at_a_multiple_of_its_length() {
        assert_eq!(window_start(1_792_569_637, Window::Second), 1_792_569_637);
        assert_eq!(window_start(1_792_569_637, Window::Minute), 1_792_569_600);
        assert_eq!(window_start(1_792_569_637, Window::Hour), 1_792_569_600);
        assert_eq!(window_start(1_792_569_637, Window::Day), 1_792_540_800);
    }

    #[test]
    fn p_11_1_retry_after_rounds_up() {
        // 48.8 seconds into a minute: 11.2 seconds remain, and the answer is 12.
        let now = 1_792_569_600_000 + 48_800;
        assert_eq!(seconds_to_window_end(now, Window::Minute), 12);
        assert_eq!(retry_after(now, [Window::Minute]), 12);
    }

    #[test]
    fn p_11_1_retry_after_takes_the_latest_end() {
        let now = 1_792_569_600_000 + 48_800;
        assert_eq!(retry_after(now, [Window::Second, Window::Minute]), 12);
        assert_eq!(retry_after(now, [Window::Second]), 1);
        assert_eq!(retry_after(now, [Window::Hour, Window::Minute]), 3600 - 48);
    }

    #[test]
    fn p_11_1_retry_after_is_at_least_one() {
        let now = 1_792_569_600_000 + 999;
        assert_eq!(seconds_to_window_end(now, Window::Second), 1);
        assert_eq!(retry_after(now, []), 1);
        assert_eq!(seconds_to_window_end(1_792_569_600_000, Window::Minute), 60);
    }

    #[test]
    fn p_8_1_lowest_value() {
        assert_eq!(lowest([5000, 100]), Some(100));
        assert_eq!(lowest([]), None);
    }

    #[test]
    fn p_8_1_two_sides_take_the_lower_value() {
        let key = BTreeMap::from([
            ("max_rows".to_owned(), 10_000),
            ("max_duration".to_owned(), 10),
        ]);
        let owner = BTreeMap::from([("max_rows".to_owned(), 5000), ("other".to_owned(), 3)]);
        let combined = combine_sides(&key, &owner);
        assert_eq!(combined["max_rows"], 5000);
        assert_eq!(combined["max_duration"], 10);
        assert_eq!(combined["other"], 3);
    }

    #[test]
    fn p_8_4_a_value_of_a_key_above_its_owner_has_no_effect() {
        let key = BTreeMap::from([("max_rows".to_owned(), 10_000)]);
        let owner = BTreeMap::from([("max_rows".to_owned(), 5000)]);
        assert_eq!(combine_sides(&key, &owner)["max_rows"], 5000);
        assert_eq!(combine_sides(&owner, &key)["max_rows"], 5000);
    }

    #[test]
    fn p_8_2_a_value_that_one_side_gives_stays() {
        let key = BTreeMap::from([("max_rows".to_owned(), 7)]);
        assert_eq!(combine_sides(&key, &BTreeMap::new())["max_rows"], 7);
        assert_eq!(combine_sides(&BTreeMap::new(), &key)["max_rows"], 7);
    }
}
