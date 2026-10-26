//! Variables and matchers.
//!
//! A case writes a variable as `{{name}}`. The runner replaces it before it
//! uses the value. A string that is exactly one variable gets the JSON value
//! of the variable. In a regular expression, the runner escapes the text of
//! a variable. A matcher then checks one value (`conformance/README.md`).

use std::collections::BTreeMap;

use procurauth_core::finding::show;
use regex::Regex;
use serde_json::{Map, Value};

use crate::model::Matcher;

/// The values of the variables for one step.
#[derive(Clone, Debug, Default)]
pub(crate) struct Vars {
    map: BTreeMap<String, Value>,
}

/// The name that a variable can have: lower-case letters, digits and the underscore.
fn is_name_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'
}

/// The text of a JSON value, as a regular expression reads it.
pub(crate) fn text_of(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

/// Find the next variable in a text. Return its start, its end and its name.
fn next_variable(text: &str, from: usize) -> Option<(usize, usize, &str)> {
    let mut search = from;
    while let Some(offset) = text[search..].find("{{") {
        let start = search + offset;
        let rest = &text[start + 2..];
        if let Some(close) = rest.find("}}") {
            let name = &rest[..close];
            if !name.is_empty() && name.chars().all(is_name_char) {
                return Some((start, start + 2 + close + 2, name));
            }
        }
        search = start + 2;
    }
    None
}

impl Vars {
    /// An empty set of variables.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Give a variable a value. A later call replaces the value.
    pub(crate) fn set(&mut self, name: &str, value: Value) {
        self.map.insert(name.to_owned(), value);
    }

    /// Give a variable a value only when it has none.
    pub(crate) fn set_default(&mut self, name: &str, value: Value) {
        self.map.entry(name.to_owned()).or_insert(value);
    }

    /// The value of a variable.
    pub(crate) fn get(&self, name: &str) -> Option<&Value> {
        self.map.get(name)
    }

    /// Add the variables of another set that this set does not have.
    pub(crate) fn extend_missing(&mut self, other: &Self) {
        for (name, value) in &other.map {
            self.map
                .entry(name.clone())
                .or_insert_with(|| value.clone());
        }
    }

    /// Add the variables of another set. Its values replace the values of this set.
    pub(crate) fn extend(&mut self, other: &Self) {
        for (name, value) in &other.map {
            self.map.insert(name.clone(), value.clone());
        }
    }

    /// Replace the variables of a text. The result is always a text.
    ///
    /// # Errors
    /// Returns the name of a variable that has no value.
    pub(crate) fn text(&self, text: &str, escape: bool) -> Result<String, String> {
        let mut out = String::with_capacity(text.len());
        let mut at = 0;
        while let Some((start, end, name)) = next_variable(text, at) {
            out.push_str(&text[at..start]);
            let value = self.map.get(name).ok_or_else(|| name.to_owned())?;
            let piece = text_of(value);
            if escape {
                out.push_str(&regex::escape(&piece));
            } else {
                out.push_str(&piece);
            }
            at = end;
        }
        out.push_str(&text[at..]);
        Ok(out)
    }

    /// Replace the variables of a string. A string that is exactly one variable gets its JSON value.
    ///
    /// # Errors
    /// Returns the name of a variable that has no value.
    pub(crate) fn string(&self, text: &str) -> Result<Value, String> {
        if let Some((0, end, name)) = next_variable(text, 0)
            && end == text.len()
        {
            return self.map.get(name).cloned().ok_or_else(|| name.to_owned());
        }
        self.text(text, false).map(Value::String)
    }

    /// Replace the variables in a JSON value, in the strings and in the member names.
    ///
    /// # Errors
    /// Returns the name of a variable that has no value.
    pub(crate) fn value(&self, value: &Value) -> Result<Value, String> {
        match value {
            Value::String(text) => self.string(text),
            Value::Array(items) => items
                .iter()
                .map(|item| self.value(item))
                .collect::<Result<Vec<_>, _>>()
                .map(Value::Array),
            Value::Object(map) => {
                let mut out = Map::new();
                for (key, item) in map {
                    out.insert(self.text(key, false)?, self.value(item)?);
                }
                Ok(Value::Object(out))
            }
            other => Ok(other.clone()),
        }
    }

    /// Replace the variables in a matcher. A regular expression gets escaped text.
    ///
    /// # Errors
    /// Returns a message when a variable has no value or when an expression does not compile.
    pub(crate) fn matcher(&self, matcher: &Matcher) -> Result<Matcher, String> {
        let unknown = |name: String| format!("the variable `{name}` has no value");
        let expression = |text: &str| -> Result<String, String> {
            let replaced = self.text(text, true).map_err(unknown)?;
            Regex::new(&replaced)
                .map_err(|e| format!("the regular expression `{replaced}` is not valid: {e}"))?;
            Ok(replaced)
        };
        Ok(match matcher {
            Matcher::Equals(value) => Matcher::Equals(self.value(value).map_err(unknown)?),
            Matcher::Absent => Matcher::Absent,
            Matcher::Present => Matcher::Present,
            Matcher::Regex(text) => Matcher::Regex(expression(text)?),
            Matcher::NotRegex(text) => Matcher::NotRegex(expression(text)?),
            Matcher::OneOf(items) => Matcher::OneOf(
                items
                    .iter()
                    .map(|item| self.value(item))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(unknown)?,
            ),
        })
    }
}

impl Matcher {
    /// Check one value. `None` means that the value does not exist.
    pub(crate) fn check(&self, actual: Option<&Value>) -> bool {
        match self {
            Self::Equals(expected) => actual == Some(expected),
            Self::Absent => actual.is_none(),
            Self::Present => actual.is_some(),
            Self::Regex(expression) => match (actual, Regex::new(expression)) {
                (Some(value), Ok(regex)) => regex.is_match(&text_of(value)),
                _ => false,
            },
            Self::NotRegex(expression) => match (actual, Regex::new(expression)) {
                (Some(value), Ok(regex)) => !regex.is_match(&text_of(value)),
                (None, Ok(_)) => true,
                _ => false,
            },
            Self::OneOf(items) => actual.is_some_and(|value| items.contains(value)),
        }
    }

    /// What the matcher expects, as words for a message.
    pub(crate) fn expected(&self) -> String {
        match self {
            Self::Equals(value) => show(value),
            Self::Absent => "no value".to_owned(),
            Self::Present => "a value".to_owned(),
            Self::Regex(text) => format!("a text that matches `{text}`"),
            Self::NotRegex(text) => format!("no match for `{text}`"),
            Self::OneOf(items) => format!(
                "one of [{}]",
                items.iter().map(show).collect::<Vec<_>>().join(", ")
            ),
        }
    }

    /// Check a value, and return a message with the name of the value when the check fails.
    pub(crate) fn verdict(&self, what: &str, actual: Option<&Value>) -> Option<String> {
        if self.check(actual) {
            return None;
        }
        let found = actual.map_or_else(|| "no value".to_owned(), show);
        Some(format!(
            "{what}: expected {}, found {found}",
            self.expected()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vars() -> Vars {
        let mut vars = Vars::new();
        vars.set("service", json!("data.store"));
        vars.set(
            "ancestors",
            json!([{"type": "service", "id": "data.store"}]),
        );
        vars.set("ceiling_value", json!(100));
        vars.set("ceiling", json!("max_rows"));
        vars
    }

    #[test]
    fn a_string_that_is_one_variable_gets_the_json_value() {
        assert_eq!(
            vars().string("{{ancestors}}"),
            Ok(json!([{"type": "service", "id": "data.store"}]))
        );
        assert_eq!(vars().string("{{ceiling_value}}"), Ok(json!(100)));
    }

    #[test]
    fn a_variable_in_a_longer_string_gives_text() {
        assert_eq!(
            vars().string("a {{ceiling_value}} b {{service}}"),
            Ok(json!("a 100 b data.store"))
        );
    }

    #[test]
    fn a_variable_can_name_a_member() {
        let out = vars()
            .value(&json!({"{{ceiling}}": "{{ceiling_value}}"}))
            .unwrap();
        assert_eq!(out, json!({"max_rows": 100}));
    }

    #[test]
    fn an_unknown_variable_is_an_error_that_names_it() {
        assert_eq!(vars().string("{{nothing}}"), Err("nothing".to_owned()));
        assert_eq!(
            vars().text("x {{nothing}}", false),
            Err("nothing".to_owned())
        );
    }

    #[test]
    fn text_with_braces_that_is_not_a_variable_stays() {
        assert_eq!(
            vars().string("{{ not a name }} {{Service}} {{}}"),
            Ok(json!("{{ not a name }} {{Service}} {{}}"))
        );
    }

    #[test]
    fn a_regular_expression_gets_the_escaped_text_of_a_variable() {
        let matcher = Matcher::Regex("^{{service}}$".into());
        let out = vars().matcher(&matcher).unwrap();
        assert_eq!(out, Matcher::Regex("^data\\.store$".into()));
        assert!(out.check(Some(&json!("data.store"))));
        assert!(!out.check(Some(&json!("dataXstore"))));
    }

    #[test]
    fn a_regular_expression_that_does_not_compile_is_an_error() {
        let matcher = Matcher::Regex("(".into());
        assert!(vars().matcher(&matcher).is_err());
    }

    #[test]
    fn the_matchers_follow_the_data_model() {
        assert!(Matcher::Equals(json!(1)).check(Some(&json!(1))));
        assert!(!Matcher::Equals(json!(1)).check(None));
        assert!(!Matcher::Equals(json!(1)).check(Some(&json!(1.5))));
        assert!(Matcher::Absent.check(None));
        assert!(!Matcher::Absent.check(Some(&json!(null))));
        assert!(Matcher::Present.check(Some(&json!(null))));
        assert!(!Matcher::Present.check(None));
        assert!(Matcher::OneOf(vec![json!(1), json!("a")]).check(Some(&json!("a"))));
        assert!(!Matcher::OneOf(vec![json!(1)]).check(None));
    }

    #[test]
    fn a_regular_expression_reads_the_text_of_a_value() {
        let r = |text: &str| Matcher::Regex(text.to_owned());
        assert!(r("^2[0-9]{2}$").check(Some(&json!(204))));
        assert!(r("^true$").check(Some(&json!(true))));
        assert!(r("^null$").check(Some(&json!(null))));
        assert!(r(r#"^\{"a":1\}$"#).check(Some(&json!({"a": 1}))));
        assert!(r("^\\[1,2\\]$").check(Some(&json!([1, 2]))));
        assert!(!r("a").check(None));
        // The match is not anchored.
        assert!(r("ell").check(Some(&json!("hello"))));
    }

    #[test]
    fn not_regex_is_true_for_an_absent_value() {
        let m = Matcher::NotRegex("a".into());
        assert!(m.check(None));
        assert!(m.check(Some(&json!("b"))));
        assert!(!m.check(Some(&json!("cat"))));
    }

    #[test]
    fn a_verdict_names_the_value_and_what_was_found() {
        let m = Matcher::Equals(json!(401));
        assert_eq!(m.verdict("status", Some(&json!(401))), None);
        assert_eq!(
            m.verdict("status", Some(&json!(200))),
            Some("status: expected 401, found 200".to_owned())
        );
        assert_eq!(
            Matcher::Present.verdict("header X", None),
            Some("header X: expected a value, found no value".to_owned())
        );
    }
}
