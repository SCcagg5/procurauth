//! A reader for typed members of a JSON object.
//!
//! The parsers of this crate use [`Obj`] to read an object member by member.
//! A wrong type or an absent member becomes a finding, and the parser
//! continues. At the end, [`Obj::finish`] reports each member that the parser
//! did not read. Thus each parser can return every error with its path.

use std::collections::BTreeSet;

use serde_json::{Map, Value};

use crate::finding::{JsonPath, Report, show, type_word};

/// What a reader does with a member that the schema does not name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unknown {
    /// An unknown member is an error. This is the closed schema.
    Error,
    /// An unknown member is a warning.
    Warn,
    /// An unknown member is ignored without a finding.
    Ignore,
}

/// An object that a parser reads member by member.
pub struct Obj<'a> {
    map: &'a Map<String, Value>,
    path: JsonPath,
    rule: &'static str,
    unknown_rule: &'static str,
    unknown: Unknown,
    used: BTreeSet<&'a str>,
}

impl<'a> Obj<'a> {
    /// Start to read `value` as an object. When it is not an object, add an
    /// error to `report` and return `None`.
    pub fn new(
        value: &'a Value,
        path: &JsonPath,
        rule: &'static str,
        unknown: Unknown,
        report: &mut Report,
    ) -> Option<Self> {
        match value {
            Value::Object(map) => Some(Self {
                map,
                path: path.clone(),
                rule,
                unknown_rule: rule,
                unknown,
                used: BTreeSet::new(),
            }),
            other => {
                report.error(
                    path,
                    rule,
                    "wrong_type",
                    format!(
                        "Expected an object, found {}: {}.",
                        type_word(other),
                        show(other)
                    ),
                );
                None
            }
        }
    }

    /// Use another rule number for the findings about unknown members.
    #[must_use]
    pub fn with_unknown_rule(mut self, rule: &'static str) -> Self {
        self.unknown_rule = rule;
        self
    }

    /// The path of this object.
    pub fn path(&self) -> &JsonPath {
        &self.path
    }

    /// The path of one member.
    pub fn member_path(&self, key: &str) -> JsonPath {
        self.path.key(key)
    }

    /// True when the member exists and is a string. The member does not count as read.
    pub fn has_string(&self, key: &str) -> bool {
        self.map.get(key).is_some_and(Value::is_string)
    }

    /// The items of an array member that are objects. The member does not count as read.
    pub fn peek_items(&self, key: &str) -> Vec<&'a Map<String, Value>> {
        match self.map.get(key) {
            Some(Value::Array(items)) => items.iter().filter_map(Value::as_object).collect(),
            _ => Vec::new(),
        }
    }

    /// True when the object has the member. The member counts as read.
    pub fn has(&mut self, key: &'static str) -> bool {
        self.optional(key).is_some()
    }

    /// An optional member. The member counts as read.
    pub fn optional(&mut self, key: &'static str) -> Option<&'a Value> {
        let (name, value) = self.map.get_key_value(key)?;
        self.used.insert(name.as_str());
        Some(value)
    }

    /// A mandatory member. When it is absent, add an error.
    pub fn required(&mut self, key: &'static str, report: &mut Report) -> Option<&'a Value> {
        let found = self.optional(key);
        if found.is_none() {
            report.error(
                &self.path,
                self.rule,
                "missing_member",
                format!("Member `{key}` is absent."),
            );
        }
        found
    }

    fn wrong(&self, key: &str, expected: &str, found: &Value, report: &mut Report) {
        report.error(
            &self.path.key(key),
            self.rule,
            "wrong_type",
            format!(
                "Member `{key}`: expected {expected}, found {}: {}.",
                type_word(found),
                show(found)
            ),
        );
    }

    /// A mandatory string member.
    pub fn string(&mut self, key: &'static str, report: &mut Report) -> Option<&'a str> {
        let value = self.required(key, report)?;
        self.as_string(key, value, report)
    }

    /// An optional string member.
    pub fn string_opt(&mut self, key: &'static str, report: &mut Report) -> Option<&'a str> {
        let value = self.optional(key)?;
        self.as_string(key, value, report)
    }

    fn as_string(&self, key: &str, value: &'a Value, report: &mut Report) -> Option<&'a str> {
        match value.as_str() {
            Some(text) => Some(text),
            None => {
                self.wrong(key, "a string", value, report);
                None
            }
        }
    }

    /// A mandatory member that is a whole number of 0 or more.
    pub fn whole(&mut self, key: &'static str, report: &mut Report) -> Option<u64> {
        let value = self.required(key, report)?;
        self.as_whole(key, value, report)
    }

    /// An optional member that is a whole number of 0 or more.
    pub fn whole_opt(&mut self, key: &'static str, report: &mut Report) -> Option<u64> {
        let value = self.optional(key)?;
        self.as_whole(key, value, report)
    }

    fn as_whole(&self, key: &str, value: &Value, report: &mut Report) -> Option<u64> {
        match value.as_u64() {
            Some(number) => Some(number),
            None => {
                self.wrong(key, "a whole number of 0 or more", value, report);
                None
            }
        }
    }

    /// A mandatory boolean member.
    pub fn boolean(&mut self, key: &'static str, report: &mut Report) -> Option<bool> {
        let value = self.required(key, report)?;
        self.as_boolean(key, value, report)
    }

    /// An optional boolean member.
    pub fn boolean_opt(&mut self, key: &'static str, report: &mut Report) -> Option<bool> {
        let value = self.optional(key)?;
        self.as_boolean(key, value, report)
    }

    fn as_boolean(&self, key: &str, value: &Value, report: &mut Report) -> Option<bool> {
        match value.as_bool() {
            Some(flag) => Some(flag),
            None => {
                self.wrong(key, "a boolean", value, report);
                None
            }
        }
    }

    /// A mandatory array member.
    pub fn array(&mut self, key: &'static str, report: &mut Report) -> Option<&'a [Value]> {
        let value = self.required(key, report)?;
        self.as_array(key, value, report)
    }

    /// An optional array member.
    pub fn array_opt(&mut self, key: &'static str, report: &mut Report) -> Option<&'a [Value]> {
        let value = self.optional(key)?;
        self.as_array(key, value, report)
    }

    fn as_array(&self, key: &str, value: &'a Value, report: &mut Report) -> Option<&'a [Value]> {
        match value.as_array() {
            Some(items) => Some(items.as_slice()),
            None => {
                self.wrong(key, "an array", value, report);
                None
            }
        }
    }

    /// A mandatory array member whose items are all strings.
    pub fn strings(&mut self, key: &'static str, report: &mut Report) -> Option<Vec<&'a str>> {
        let items = self.array(key, report)?;
        self.item_strings(key, items, report)
    }

    /// An optional array member whose items are all strings.
    pub fn strings_opt(&mut self, key: &'static str, report: &mut Report) -> Option<Vec<&'a str>> {
        let items = self.array_opt(key, report)?;
        self.item_strings(key, items, report)
    }

    fn item_strings(
        &self,
        key: &str,
        items: &'a [Value],
        report: &mut Report,
    ) -> Option<Vec<&'a str>> {
        let mut out = Vec::with_capacity(items.len());
        let mut good = true;
        for (index, item) in items.iter().enumerate() {
            if let Some(text) = item.as_str() {
                out.push(text);
            } else {
                good = false;
                report.error(
                    &self.path.key(key).index(index),
                    self.rule,
                    "wrong_type",
                    format!(
                        "Expected a string, found {}: {}.",
                        type_word(item),
                        show(item)
                    ),
                );
            }
        }
        good.then_some(out)
    }

    /// A mandatory object member, ready to read.
    pub fn object(
        &mut self,
        key: &'static str,
        rule: &'static str,
        unknown: Unknown,
        report: &mut Report,
    ) -> Option<Obj<'a>> {
        let value = self.required(key, report)?;
        Obj::new(value, &self.path.key(key), rule, unknown, report)
    }

    /// An optional object member, ready to read.
    pub fn object_opt(
        &mut self,
        key: &'static str,
        rule: &'static str,
        unknown: Unknown,
        report: &mut Report,
    ) -> Option<Obj<'a>> {
        let value = self.optional(key)?;
        Obj::new(value, &self.path.key(key), rule, unknown, report)
    }

    /// Report each member that nobody read, as the closed schema says.
    pub fn finish(&self, report: &mut Report) {
        if self.unknown == Unknown::Ignore {
            return;
        }
        for key in self.map.keys() {
            if self.used.contains(key.as_str()) {
                continue;
            }
            let path = self.path.key(key);
            let message = format!("Member `{key}` is not known here.");
            if self.unknown == Unknown::Error {
                report.error(&path, self.unknown_rule, "unknown_member", message);
            } else {
                report.warning(&path, self.unknown_rule, "unknown_member", message);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn obj_reports_every_problem_with_its_path() {
        let value = json!({"name": 5, "size": -1, "extra": 1});
        let mut report = Report::new();
        let mut obj = Obj::new(
            &value,
            &JsonPath::root(),
            "5.2",
            Unknown::Error,
            &mut report,
        )
        .unwrap();
        assert!(obj.string("name", &mut report).is_none());
        assert!(obj.whole("size", &mut report).is_none());
        assert!(obj.string("missing", &mut report).is_none());
        obj.finish(&mut report);
        let codes: Vec<_> = report
            .findings()
            .iter()
            .map(|f| (f.path.as_str().to_owned(), f.code))
            .collect();
        assert_eq!(
            codes,
            vec![
                ("$.name".to_owned(), "wrong_type"),
                ("$.size".to_owned(), "wrong_type"),
                ("$".to_owned(), "missing_member"),
                ("$.extra".to_owned(), "unknown_member"),
            ]
        );
    }

    #[test]
    fn obj_float_is_not_a_whole_number() {
        let value = json!({"n": 1.0});
        let mut report = Report::new();
        let mut obj = Obj::new(
            &value,
            &JsonPath::root(),
            "6.1",
            Unknown::Ignore,
            &mut report,
        )
        .unwrap();
        assert!(obj.whole("n", &mut report).is_none());
        assert!(report.has_errors());
    }

    #[test]
    fn obj_rejects_a_value_that_is_not_an_object() {
        let value = json!([1]);
        let mut report = Report::new();
        assert!(
            Obj::new(
                &value,
                &JsonPath::root(),
                "5.2",
                Unknown::Error,
                &mut report
            )
            .is_none()
        );
        assert_eq!(report.findings()[0].code, "wrong_type");
    }
}
