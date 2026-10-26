//! The answer of the route that lists the options (protocol 5.6 to 5.8).
//!
//! [`analyze_value`] checks an answer and returns every finding. The caller
//! of the route (a form for grants) and `access-lint` use it.

use serde_json::{Value, json};

use crate::finding::{Finding, JsonPath, Report, show};
use crate::json::parse_str;
use crate::names::validate_id;
use crate::read::{Obj, Unknown};

/// The size of an answer that a caller must accept, in bytes (5.8).
pub const CALLER_MIN_BYTES: usize = 64 * 1024;
/// The number of items that a caller must accept (5.8).
pub const CALLER_MIN_ITEMS: usize = 50;
/// The length of a label that a caller must accept, in characters (5.8).
pub const CALLER_MIN_LABEL: usize = 60;

/// One child of a node (5.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionItem {
    /// The id of the child. Nobody encodes it (4.1).
    pub id: String,
    /// A short text for the form.
    pub label: String,
    /// True when the route can list children below this child.
    pub has_children: bool,
}

/// An answer of the route (5.8).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OptionsAnswer {
    /// The children, in the order of the service.
    pub items: Vec<OptionItem>,
    /// The cursor of the next page, or `None` on the last page. The caller treats it as opaque text.
    pub next: Option<String>,
}

impl OptionsAnswer {
    /// The answer as JSON.
    pub fn to_value(&self) -> Value {
        json!({
            "items": self.items.iter()
                .map(|i| json!({"id": i.id, "label": i.label, "has_children": i.has_children}))
                .collect::<Vec<_>>(),
            "next": self.next,
        })
    }

    /// Read an answer from JSON text.
    ///
    /// # Errors
    /// Returns every finding when the answer is bad.
    pub fn parse_str(text: &str) -> Result<Self, Vec<Finding>> {
        let (answer, report) = analyze_str(text);
        answer.ok_or_else(|| report.into_findings())
    }
}

/// Check an answer in JSON text. A text above 64 KiB gets a warning (5.8).
pub fn analyze_str(text: &str) -> (Option<OptionsAnswer>, Report) {
    match parse_str(text) {
        Ok(value) => {
            let (answer, mut report) = analyze_value(&value);
            if text.len() > CALLER_MIN_BYTES {
                report.warning(
                    &JsonPath::root(),
                    "5.8",
                    "above_caller_minimum",
                    format!(
                        "The answer has {} bytes. A caller must accept {CALLER_MIN_BYTES} bytes.",
                        text.len()
                    ),
                );
            }
            (answer, report)
        }
        Err(error) => {
            let mut report = Report::new();
            report.error(
                &error.path,
                "5.8",
                "bad_json",
                format!("The text is not valid JSON: {error}."),
            );
            (None, report)
        }
    }
}

/// Check an answer in a JSON value. The answer is `None` when a finding is an error.
pub fn analyze_value(value: &Value) -> (Option<OptionsAnswer>, Report) {
    let mut report = Report::new();
    let root = JsonPath::root();
    let mut items = Vec::new();
    let mut next = None;
    if let Some(mut obj) = Obj::new(value, &root, "5.8", Unknown::Warn, &mut report) {
        let list = obj.array("items", &mut report);
        let next_value = obj.required("next", &mut report);
        obj.finish(&mut report);
        if let Some(list) = list {
            if list.len() > CALLER_MIN_ITEMS {
                report.warning(
                    &root.key("items"),
                    "5.8",
                    "above_caller_minimum",
                    format!(
                        "The answer has {} items. A caller must accept {CALLER_MIN_ITEMS}.",
                        list.len()
                    ),
                );
            }
            for (index, item) in list.iter().enumerate() {
                items.extend(read_item(
                    item,
                    &root.key("items").index(index),
                    &mut report,
                ));
            }
        }
        match next_value {
            Some(Value::Null) => {}
            Some(Value::String(cursor)) => next = Some(cursor.clone()),
            Some(other) => report.error(
                &root.key("next"),
                "5.8",
                "wrong_type",
                format!(
                    "Member `next`: expected a string or null, found {}.",
                    show(other)
                ),
            ),
            None => {}
        }
    }
    let answer = (!report.has_errors()).then_some(OptionsAnswer { items, next });
    (answer, report)
}

fn read_item(value: &Value, path: &JsonPath, report: &mut Report) -> Option<OptionItem> {
    let start = report.error_count();
    let mut obj = Obj::new(value, path, "5.8", Unknown::Warn, report)?;
    let id = obj.string("id", report);
    let label = obj.string("label", report);
    let has_children = obj.boolean("has_children", report);
    obj.finish(report);
    if let Some(id) = id
        && let Err(error) = validate_id(id)
    {
        report.error(
            &path.key("id"),
            "4.1",
            "bad_id",
            format!("Member `id` {}: {error}.", show(&json!(id))),
        );
    }
    if let Some(label) = label
        && label.chars().count() > CALLER_MIN_LABEL
    {
        report.warning(
            &path.key("label"),
            "5.8",
            "above_caller_minimum",
            format!(
                "The label has {} characters. A caller must accept {CALLER_MIN_LABEL}.",
                label.chars().count()
            ),
        );
    }
    (report.error_count() == start).then(|| OptionItem {
        id: id.unwrap_or_default().to_owned(),
        label: label.unwrap_or_default().to_owned(),
        has_children: has_children.unwrap_or_default(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finding::Severity;

    fn codes(value: &Value) -> Vec<(String, &'static str, Severity)> {
        analyze_value(value)
            .1
            .findings()
            .iter()
            .map(|f| (f.path.as_str().to_owned(), f.code, f.severity))
            .collect()
    }

    #[test]
    fn p_5_8_the_example_of_the_protocol_is_good() {
        let value = json!({"items": [{"id": "test1", "label": "test1", "has_children": true},
                                     {"id": "test2", "label": "test2", "has_children": true}], "next": null});
        let (answer, report) = analyze_value(&value);
        assert!(report.findings().is_empty());
        let answer = answer.unwrap();
        assert_eq!(answer.items.len(), 2);
        assert_eq!(answer.next, None);
        assert_eq!(answer.to_value(), value);
    }

    #[test]
    fn p_5_8_next_is_a_cursor_or_null() {
        let value = json!({"items": [], "next": "c2"});
        assert_eq!(analyze_value(&value).0.unwrap().next.as_deref(), Some("c2"));
        assert_eq!(
            codes(&json!({"items": [], "next": 5})),
            vec![("$.next".to_owned(), "wrong_type", Severity::Error)]
        );
        assert_eq!(
            codes(&json!({"items": []})),
            vec![("$".to_owned(), "missing_member", Severity::Error)]
        );
    }

    #[test]
    fn p_5_8_an_item_has_id_label_and_has_children() {
        let value = json!({"items": [{"id": "a"}, {"id": "b", "label": "B", "has_children": "yes"}, 5], "next": null});
        assert_eq!(
            codes(&value),
            vec![
                ("$.items[0]".to_owned(), "missing_member", Severity::Error),
                ("$.items[0]".to_owned(), "missing_member", Severity::Error),
                (
                    "$.items[1].has_children".to_owned(),
                    "wrong_type",
                    Severity::Error
                ),
                ("$.items[2]".to_owned(), "wrong_type", Severity::Error),
            ]
        );
    }

    #[test]
    fn p_5_8_an_id_follows_4_1() {
        let long = "a".repeat(257);
        let value = json!({"items": [{"id": "", "label": "x", "has_children": false},
                                     {"id": long, "label": "x", "has_children": false},
                                     {"id": "a/b c%", "label": "x", "has_children": false}], "next": null});
        let found = codes(&value);
        assert_eq!(found.len(), 2);
        assert!(found.iter().all(|f| f.1 == "bad_id"));
    }

    #[test]
    fn p_5_8_a_caller_accepts_50_items_and_a_label_of_60_characters() {
        let items: Vec<Value> = (0..50)
            .map(|i| json!({"id": format!("i{i}"), "label": "l".repeat(60), "has_children": false}))
            .collect();
        assert!(codes(&json!({"items": items, "next": null})).is_empty());
        let items: Vec<Value> = (0..51)
            .map(|i| json!({"id": format!("i{i}"), "label": "l".repeat(61), "has_children": false}))
            .collect();
        let found = codes(&json!({"items": items, "next": null}));
        assert_eq!(found.len(), 52);
        assert!(
            found
                .iter()
                .all(|f| f.1 == "above_caller_minimum" && f.2 == Severity::Warning)
        );
    }

    #[test]
    fn p_5_8_an_unknown_member_is_a_warning() {
        let value = json!({"items": [], "next": null, "total": 5});
        assert_eq!(
            codes(&value),
            vec![("$.total".to_owned(), "unknown_member", Severity::Warning)]
        );
        assert!(analyze_value(&value).0.is_some());
    }

    #[test]
    fn p_5_8_a_duplicate_member_in_the_text_is_bad() {
        let (answer, report) = analyze_str(r#"{"items": [], "items": [], "next": null}"#);
        assert!(answer.is_none());
        assert_eq!(report.findings()[0].code, "bad_json");
    }

    #[test]
    fn p_5_8_a_text_above_64_kib_gets_a_warning() {
        let text = format!(
            r#"{{"items": [], "next": "{}"}}"#,
            "x".repeat(CALLER_MIN_BYTES)
        );
        let (answer, report) = analyze_str(&text);
        assert!(answer.is_some());
        assert_eq!(report.findings()[0].code, "above_caller_minimum");
    }
}
