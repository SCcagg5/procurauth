//! The effect of an operation (protocol 17.3, 17.9).
//!
//! The effect is a hash. It binds the service, the action, the resource and the
//! operation `op`. The hash input is a JSON object with the members `v`, `service`,
//! `action`, `resource` and `op`. The module writes it as JSON text with JCS
//! (RFC 8785) and computes SHA-256 over the UTF-8 bytes.
//!
//! `op` has only objects, arrays, strings, booleans, `null` and integers from
//! -(2^53-1) to 2^53-1. Any other number makes `op` invalid. A duplicate member
//! name and an unpaired surrogate also make `op` invalid. The strict reader of
//! [`crate::json`] refuses both before a [`Value`] exists, so a [`Value`] cannot hold them.
//! The file `conformance/vectors/effect.json` has the test vectors.
//!
//! The module also checks a `view` (17.9): a template of JSON Pointers [RFC 6901] over `op`.
//!
//! ```
//! use procurauth_core::effect::effect_hash;
//! use serde_json::json;
//!
//! let effect = effect_hash("datastore", "data.write", "host:prod", &json!({"a": 2, "b": 1})).unwrap();
//! assert!(effect.starts_with("sha256:"));
//! assert!(effect_hash("datastore", "data.write", "host:prod", &json!({"a": 1.5})).is_err());
//! ```

use std::cmp::Ordering;
use std::fmt::Write as _;

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::path::{NodePath, format_below_service};

/// The version of the hash input (17.3). It is the number 1.
pub const EFFECT_VERSION: u64 = 1;

/// The largest integer that `op` can hold: 2^53 - 1 (17.3).
pub const MAX_INTEGER: i64 = (1_i64 << 53) - 1;

/// Why an `op` is not valid (17.3). A PEP never computes the effect of such an `op`.
/// A PDP refuses it with the error `invalid_op`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum OpError {
    /// `op` is not a JSON object.
    #[error("`op` is not a JSON object")]
    NotObject,
    /// A number is not an integer from -(2^53-1) to 2^53-1.
    /// The JSON pointer of the value and its text are in the error.
    #[error(
        "the number {text} at `{pointer}` is not an integer from -9007199254740991 to 9007199254740991"
    )]
    Number {
        /// The JSON Pointer of the number inside `op`.
        pointer: String,
        /// The number as text.
        text: String,
    },
}

/// Why a `view` is not valid (17.9). A PDP refuses it with the error `invalid_view`.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
pub enum ViewError {
    /// The `view` is not a JSON object.
    #[error("the view is not a JSON object")]
    NotObject,
    /// The `view` has a member that 17.9 does not define.
    #[error("the view has the unknown member `{0}`")]
    UnknownMember(String),
    /// A member has a value of the wrong type or form.
    #[error("the member `{member}` of the view {why}")]
    BadMember {
        /// The name of the member.
        member: &'static str,
        /// What is wrong.
        why: &'static str,
    },
    /// A text is not a JSON Pointer [RFC 6901].
    #[error("`{0}` is not a JSON Pointer")]
    BadPointer(String),
    /// A pointer names no value in `op`.
    #[error("the pointer `{0}` names no value in `op`")]
    NoValue(String),
}

/// True when the text is an effect: `sha256:` and 64 lower-case hexadecimal digits (17.3).
pub fn is_effect(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|digits| {
        digits.len() == 64
            && digits
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// The text of a node path as the effect writes it: the path below the service in the form of 5.2.
/// The service itself gives the empty text.
pub fn resource_text(node: &NodePath) -> String {
    format_below_service(&node.nodes()[1..])
}

/// Check an `op` (17.3).
///
/// # Errors
/// Returns the first problem: `op` is not an object, or it holds a number that is not an integer
/// within the bound.
pub fn check_op(op: &Value) -> Result<(), OpError> {
    if !op.is_object() {
        return Err(OpError::NotObject);
    }
    check_numbers(op, &mut String::new())
}

fn check_numbers(value: &Value, pointer: &mut String) -> Result<(), OpError> {
    match value {
        Value::Number(n) => {
            // `as_i64` is `None` for a float, for `-0`, for `1.0`, for `1e2` and for a big integer.
            if n.as_i64()
                .is_some_and(|i| (-MAX_INTEGER..=MAX_INTEGER).contains(&i))
            {
                Ok(())
            } else {
                Err(OpError::Number {
                    pointer: pointer.clone(),
                    text: n.to_string(),
                })
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                let mark = pointer.len();
                let _ = write!(pointer, "/{index}");
                check_numbers(item, pointer)?;
                pointer.truncate(mark);
            }
            Ok(())
        }
        Value::Object(map) => {
            for (name, item) in map {
                let mark = pointer.len();
                pointer.push('/');
                pointer.push_str(&escape_token(name));
                check_numbers(item, pointer)?;
                pointer.truncate(mark);
            }
            Ok(())
        }
        Value::Null | Value::Bool(_) | Value::String(_) => Ok(()),
    }
}

/// Write a string as JCS does: short escapes, `\u00xx` below U+0020, all else as it is.
fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two member names by their UTF-16 code units (RFC 8785, 3.2.3).
fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Write a value as JCS. The caller checked the numbers.
fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut members: Vec<(&String, &Value)> = map.iter().collect();
            members.sort_by(|a, b| utf16_order(a.0, b.0));
            out.push('{');
            for (index, (name, item)) in members.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(out, name);
                out.push(':');
                write_value(out, item);
            }
            out.push('}');
        }
    }
}

/// The canonical JSON text of the hash input (17.3).
/// `resource` is the path below the service in the form of 5.2, as [`resource_text`] gives it.
///
/// # Errors
/// Returns the problem of an `op` that is not valid.
pub fn canonical_text(
    service: &str,
    action: &str,
    resource: &str,
    op: &Value,
) -> Result<String, OpError> {
    check_op(op)?;
    // The members of the hash input in the order of the UTF-16 code units of their names.
    let mut out = String::from("{\"action\":");
    write_string(&mut out, action);
    out.push_str(",\"op\":");
    write_value(&mut out, op);
    out.push_str(",\"resource\":");
    write_string(&mut out, resource);
    out.push_str(",\"service\":");
    write_string(&mut out, service);
    let _ = write!(out, ",\"v\":{EFFECT_VERSION}}}");
    Ok(out)
}

/// The effect of an operation: `sha256:` and the 64 lower-case hexadecimal digits of the hash (17.3).
///
/// # Errors
/// Returns the problem of an `op` that is not valid.
pub fn effect_hash(
    service: &str,
    action: &str,
    resource: &str,
    op: &Value,
) -> Result<String, OpError> {
    let text = canonical_text(service, action, resource, op)?;
    Ok(format!("sha256:{}", hex::encode(Sha256::digest(text))))
}

/// Escape a name for a JSON Pointer (RFC 6901, 3): `~` is `~0` and `/` is `~1`.
fn escape_token(name: &str) -> String {
    name.replace('~', "~0").replace('/', "~1")
}

/// True when the text is a JSON Pointer [RFC 6901]: empty, or `/`-led tokens where `~` is followed by 0 or 1.
pub fn is_json_pointer(text: &str) -> bool {
    if text.is_empty() {
        return true;
    }
    if !text.starts_with('/') {
        return false;
    }
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    true
}

/// The value that a JSON Pointer names in `value`. `None` when the pointer is not valid,
/// or when it names no value. An array index has no sign and no zero at the start.
pub fn resolve_pointer<'a>(value: &'a Value, pointer: &str) -> Option<&'a Value> {
    if !is_json_pointer(pointer) {
        return None;
    }
    let mut current = value;
    if pointer.is_empty() {
        return Some(current);
    }
    for raw in pointer[1..].split('/') {
        let token = raw.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Object(map) => map.get(&token)?,
            Value::Array(items) => {
                let digits_only = !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit());
                if !digits_only || (token.len() > 1 && token.starts_with('0')) {
                    return None;
                }
                items.get(token.parse::<usize>().ok()?)?
            }
            _ => return None,
        };
    }
    Some(current)
}

fn pointer_names_value(op: &Value, pointer: &str) -> Result<(), ViewError> {
    if !is_json_pointer(pointer) {
        return Err(ViewError::BadPointer(pointer.to_owned()));
    }
    resolve_pointer(op, pointer)
        .map(|_| ())
        .ok_or_else(|| ViewError::NoValue(pointer.to_owned()))
}

/// Check a `view` against an `op` (17.9).
///
/// The `view` is a JSON object. It has no member other than these four.
/// `title` is a text. `fields` is an array of pairs of a text and a pointer.
/// `body` is a pointer to a text of `op`. `body_label` is a text.
///
/// Each pointer must name a value in `op`.
///
/// # Errors
/// Returns the first problem of the `view`.
pub fn check_view(view: &Value, op: &Value) -> Result<(), ViewError> {
    let Some(map) = view.as_object() else {
        return Err(ViewError::NotObject);
    };
    for (name, value) in map {
        match name.as_str() {
            "title" if value.is_string() => {}
            "title" => {
                return Err(ViewError::BadMember {
                    member: "title",
                    why: "is not a text",
                });
            }
            "body_label" if value.is_string() => {}
            "body_label" => {
                return Err(ViewError::BadMember {
                    member: "body_label",
                    why: "is not a text",
                });
            }
            "fields" => {
                let Some(items) = value.as_array() else {
                    return Err(ViewError::BadMember {
                        member: "fields",
                        why: "is not an array",
                    });
                };
                for item in items {
                    match item.as_array().map(Vec::as_slice) {
                        Some([Value::String(_), Value::String(pointer)]) => {
                            pointer_names_value(op, pointer)?;
                        }
                        _ => {
                            return Err(ViewError::BadMember {
                                member: "fields",
                                why: "has an item that is not a pair of a text and a pointer",
                            });
                        }
                    }
                }
            }
            "body" => {
                let Some(pointer) = value.as_str() else {
                    return Err(ViewError::BadMember {
                        member: "body",
                        why: "is not a text",
                    });
                };
                pointer_names_value(op, pointer)?;
                if !resolve_pointer(op, pointer).is_some_and(Value::is_string) {
                    return Err(ViewError::BadMember {
                        member: "body",
                        why: "names a value of `op` that is not a text",
                    });
                }
            }
            other => return Err(ViewError::UnknownMember(other.to_owned())),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json::parse_str;
    use serde_json::json;

    const VECTORS: &str = include_str!("../../../conformance/vectors/effect.json");

    fn vectors() -> Vec<Value> {
        let file = parse_str(VECTORS).unwrap();
        file["vectors"].as_array().unwrap().clone()
    }

    fn compute(input: &Value) -> Result<(String, String), OpError> {
        let (service, action, resource) = (
            input["service"].as_str().unwrap(),
            input["action"].as_str().unwrap(),
            input["resource"].as_str().unwrap(),
        );
        Ok((
            canonical_text(service, action, resource, &input["op"])?,
            effect_hash(service, action, resource, &input["op"])?,
        ))
    }

    #[test]
    fn p_17_3_each_vector_of_v01_gives_its_canonical_text_and_effect() {
        let mut count = 0;
        for v in vectors().iter().filter(|v| v["group"] == "V01") {
            let id = v["id"].as_str().unwrap();
            let (text, effect) = compute(&v["input"]).unwrap_or_else(|e| panic!("{id}: {e}"));
            assert_eq!(text, v["canonical"].as_str().unwrap(), "{id}: canonical");
            assert_eq!(effect, v["effect"].as_str().unwrap(), "{id}: effect");
            count += 1;
        }
        assert!(count >= 10, "{count}");
    }

    #[test]
    fn p_17_3_each_vector_of_v02_is_refused() {
        let mut count = 0;
        for v in vectors().iter().filter(|v| v["group"] == "V02") {
            let id = v["id"].as_str().unwrap();
            assert!(compute(&v["input"]).is_err(), "{id}: not refused");
            assert!(check_op(&v["input"]["op"]).is_err(), "{id}: check_op");
            assert_eq!(v["error"], "invalid_op", "{id}");
            count += 1;
        }
        assert!(count >= 5, "{count}");
    }

    #[test]
    fn p_17_3_the_resource_has_no_service_and_the_service_itself_has_the_empty_text() {
        let path = NodePath::parse("service:datastore/host:prod/database:analytics").unwrap();
        assert_eq!(resource_text(&path), "host:prod/database:analytics");
        assert_eq!(resource_text(&NodePath::service("datastore")), "");
        let encoded = NodePath::parse("service:datastore/host:prod/database:a%2Fb").unwrap();
        assert_eq!(resource_text(&encoded), "host:prod/database:a%2Fb");
    }

    #[test]
    fn p_17_3_the_effect_is_sha256_and_64_lower_case_digits() {
        let effect = effect_hash("s", "a.b", "", &json!({})).unwrap();
        assert!(is_effect(&effect), "{effect}");
        assert!(!is_effect("sha256:ABC"));
        assert!(!is_effect(&effect.to_uppercase()));
        assert!(!is_effect(&effect[1..]));
        assert!(!is_effect(&format!("{effect}0")));
    }

    #[test]
    fn p_17_3_an_error_names_the_pointer_and_the_text_of_the_number() {
        let error = check_op(&json!({"a": [1, {"b/c": 1.5}]})).unwrap_err();
        assert_eq!(
            error,
            OpError::Number {
                pointer: "/a/1/b~1c".into(),
                text: "1.5".into()
            }
        );
        assert_eq!(check_op(&json!([1])).unwrap_err(), OpError::NotObject);
        assert_eq!(check_op(&json!("x")).unwrap_err(), OpError::NotObject);
    }

    #[test]
    fn p_17_3_the_strict_reader_refuses_a_duplicate_name_and_a_lone_surrogate_before_op_exists() {
        assert!(parse_str(r#"{"op": {"a": 1, "a": 2}}"#).is_err());
        assert!(parse_str(r#"{"op": {"a": "\ud800"}}"#).is_err());
    }

    #[test]
    fn p_17_3_a_literal_minus_zero_and_a_big_integer_are_invalid_in_text() {
        for text in [
            r#"{"x":-0}"#,
            r#"{"x":1e2}"#,
            r#"{"x":18446744073709551616}"#,
        ] {
            let op = parse_str(text).unwrap();
            assert!(check_op(&op).is_err(), "{text}");
        }
    }

    #[test]
    fn p_17_3_a_pointer_has_a_clear_syntax() {
        for good in ["", "/", "/a", "/a/0", "/a~0b", "/a~1b", "//"] {
            assert!(is_json_pointer(good), "{good}");
        }
        for bad in ["a", "/a~", "/a~2", "~0"] {
            assert!(!is_json_pointer(bad), "{bad}");
        }
    }

    #[test]
    fn p_17_9_a_pointer_resolves_in_objects_and_arrays() {
        let op = json!({"a": {"b/c": [10, 20]}, "~": "t", "": "empty"});
        assert_eq!(resolve_pointer(&op, ""), Some(&op));
        assert_eq!(resolve_pointer(&op, "/a/b~1c/1"), Some(&json!(20)));
        assert_eq!(resolve_pointer(&op, "/~0"), Some(&json!("t")));
        assert_eq!(resolve_pointer(&op, "/"), Some(&json!("empty")));
        assert_eq!(resolve_pointer(&op, "/a/b~1c/2"), None);
        assert_eq!(resolve_pointer(&op, "/a/b~1c/01"), None);
        assert_eq!(resolve_pointer(&op, "/a/b~1c/-"), None);
        assert_eq!(resolve_pointer(&op, "/a/b~1c/+1"), None);
        assert_eq!(resolve_pointer(&op, "/x"), None);
        assert_eq!(resolve_pointer(&op, "/~0/x"), None);
    }

    #[test]
    fn p_17_9_a_good_view_names_values_of_op() {
        let op = json!({"host": "prod", "database": "analytics", "sql": "DELETE 1", "n": 3});
        let view = json!({
            "title": "Write",
            "fields": [["Host", "/host"], ["Rows", "/n"]],
            "body": "/sql",
            "body_label": "SQL"
        });
        assert_eq!(check_view(&view, &op), Ok(()));
        assert_eq!(check_view(&json!({}), &op), Ok(()));
    }

    #[test]
    fn p_17_9_a_bad_view_is_refused() {
        let op = json!({"host": "prod", "n": 3});
        let bad = |view: Value| check_view(&view, &op).unwrap_err();
        assert_eq!(bad(json!([])), ViewError::NotObject);
        assert_eq!(
            bad(json!({"extra": 1})),
            ViewError::UnknownMember("extra".into())
        );
        assert_eq!(
            bad(json!({"fields": [["Host", "/nothing"]]})),
            ViewError::NoValue("/nothing".into())
        );
        assert_eq!(
            bad(json!({"fields": [["Host", "host"]]})),
            ViewError::BadPointer("host".into())
        );
        assert!(matches!(
            bad(json!({"fields": [["Host"]]})),
            ViewError::BadMember {
                member: "fields",
                ..
            }
        ));
        assert!(matches!(
            bad(json!({"fields": "x"})),
            ViewError::BadMember {
                member: "fields",
                ..
            }
        ));
        assert!(matches!(
            bad(json!({"body": "/n"})),
            ViewError::BadMember { member: "body", .. }
        ));
        assert_eq!(
            bad(json!({"body": "/missing"})),
            ViewError::NoValue("/missing".into())
        );
        assert!(matches!(
            bad(json!({"title": 1})),
            ViewError::BadMember {
                member: "title",
                ..
            }
        ));
        assert!(matches!(
            bad(json!({"body_label": null})),
            ViewError::BadMember {
                member: "body_label",
                ..
            }
        ));
    }
}
