//! The vectors of the effect (protocol 17.3).
//!
//! The file `conformance/vectors/effect.json` holds the vectors. This test
//! computes each vector again with its own small code for JCS (RFC 8785) and
//! SHA-256. It does not use the code of a tool, because the core has no
//! `effect` module yet. A one-off Python program computed the same vectors
//! first, so the file and this test agree through two separate computations.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cmp::Ordering;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;
use sha2::{Digest, Sha256};

/// The largest integer that `op` can hold: 2^53 - 1.
const MAX_INTEGER: i64 = (1_i64 << 53) - 1;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn vectors() -> Vec<Value> {
    let text = fs::read_to_string(root().join("conformance/vectors/effect.json")).unwrap();
    let file: Value = serde_json::from_str(&text).unwrap();
    file["vectors"].as_array().unwrap().clone()
}

fn group(name: &str) -> Vec<Value> {
    vectors()
        .into_iter()
        .filter(|v| v["group"] == name)
        .collect()
}

fn vector(id: &str) -> Value {
    vectors().into_iter().find(|v| v["id"] == id).unwrap()
}

/// The reason why a value cannot be part of an `op`.
#[derive(Debug, PartialEq)]
enum Invalid {
    Number(String),
    NotObject,
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
            c if u32::from(c) < 0x20 => write!(out, "\\u{:04x}", u32::from(c)).unwrap(),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// Compare two member names by their UTF-16 code units (RFC 8785, 3.2.3).
fn utf16_order(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// The JCS text of a value, with the number subset of protocol 17.3.
fn jcs(value: &Value, out: &mut String) -> Result<(), Invalid> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => {
            // A float, a number that serde_json reads as a float, and a big integer are invalid.
            let integer = n
                .as_i64()
                .filter(|i| (-MAX_INTEGER..=MAX_INTEGER).contains(i))
                .ok_or_else(|| Invalid::Number(n.to_string()))?;
            write!(out, "{integer}").unwrap();
        }
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                jcs(item, out)?;
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
                jcs(item, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The canonical text and the effect of an input.
fn effect_of(input: &Value) -> Result<(String, String), Invalid> {
    let op = &input["op"];
    if !op.is_object() {
        return Err(Invalid::NotObject);
    }
    let hash_input = serde_json::json!({
        "v": 1,
        "service": input["service"],
        "action": input["action"],
        "resource": input["resource"],
        "op": op,
    });
    let mut text = String::new();
    jcs(&hash_input, &mut text)?;
    let digest = Sha256::digest(text.as_bytes());
    let effect = format!("sha256:{}", hex::encode(digest));
    Ok((text, effect))
}

#[test]
fn p_17_3_the_file_has_at_least_twelve_vectors_in_two_groups() {
    assert!(vectors().len() >= 12);
    assert!(!group("V01").is_empty());
    assert!(!group("V02").is_empty());
    assert_eq!(group("V01").len() + group("V02").len(), vectors().len());
}

#[test]
fn p_17_3_each_vector_of_v01_gives_its_canonical_text_and_effect() {
    for v in group("V01") {
        let id = v["id"].as_str().unwrap();
        let (text, effect) = effect_of(&v["input"]).unwrap_or_else(|e| panic!("{id}: {e:?}"));
        assert_eq!(text, v["canonical"].as_str().unwrap(), "{id}: canonical");
        assert_eq!(effect, v["effect"].as_str().unwrap(), "{id}: effect");
    }
}

#[test]
fn p_17_3_each_vector_of_v02_is_refused() {
    for v in group("V02") {
        let id = v["id"].as_str().unwrap();
        assert!(effect_of(&v["input"]).is_err(), "{id}: not refused");
        assert_eq!(v["error"], "invalid_op", "{id}");
    }
}

#[test]
fn p_17_3_the_order_of_the_members_does_not_change_the_effect() {
    let a = vector("member-order-sorted");
    let b = vector("member-order-reversed");
    assert_eq!(a["effect"], b["effect"]);
    assert_eq!(a["canonical"], b["canonical"]);
}

#[test]
fn p_17_3_names_sort_by_utf16_and_not_by_code_point() {
    let v = vector("utf16-key-order");
    let (text, _) = effect_of(&v["input"]).unwrap();
    // U+10000 and U+1F600 are surrogate pairs that start with D800 and D83D: before U+E000.
    let order: Vec<usize> = ["\u{10000}", "\u{1F600}", "\u{E000}", "\u{FFFD}"]
        .iter()
        .map(|name| text.find(name).unwrap())
        .collect();
    assert!(order.windows(2).all(|w| w[0] < w[1]), "{text}");
    // The order of code points is another order, so the vector can tell the two apart.
    assert_eq!(utf16_order("\u{1F600}", "\u{E000}"), Ordering::Less);
    assert_eq!("\u{1F600}".cmp("\u{E000}"), Ordering::Greater);
}

#[test]
fn p_17_3_no_unicode_normalisation_applies() {
    let composed = vector("normalisation-composed");
    let decomposed = vector("normalisation-decomposed");
    assert_ne!(composed["effect"], decomposed["effect"]);
    assert_eq!(composed["input"]["op"]["s"], "\u{e9}");
    assert_eq!(decomposed["input"]["op"]["s"], "e\u{301}");
}

#[test]
fn p_17_3_the_limits_of_the_integers_are_valid_and_the_next_integers_are_not() {
    let limits = vector("integers-at-limits");
    assert_eq!(limits["input"]["op"]["max"], 9_007_199_254_740_991_i64);
    assert_eq!(limits["input"]["op"]["min"], -9_007_199_254_740_991_i64);
    for id in ["integer-2-53", "integer-minus-2-53"] {
        let v = vector(id);
        let n = v["input"]["op"]["x"].as_i64().unwrap();
        assert_eq!(n.abs(), MAX_INTEGER + 1, "{id}");
        assert!(matches!(effect_of(&v["input"]), Err(Invalid::Number(_))));
    }
}

#[test]
fn p_17_3_an_op_that_is_not_an_object_is_refused() {
    let v = vector("op-not-object");
    assert_eq!(effect_of(&v["input"]), Err(Invalid::NotObject));
}

#[test]
fn p_17_3_the_four_values_and_the_version_change_the_effect() {
    let base = vector("member-order-sorted");
    let (_, reference) = effect_of(&base["input"]).unwrap();
    for member in ["service", "action", "resource"] {
        let mut input = base["input"].clone();
        input[member] = Value::String(format!("{}x", input[member].as_str().unwrap()));
        assert_ne!(effect_of(&input).unwrap().1, reference, "{member}");
    }
    let mut input = base["input"].clone();
    input["op"]["a"] = Value::from(3);
    assert_ne!(effect_of(&input).unwrap().1, reference, "op");
    // The version is part of the text that the hash covers.
    assert!(base["canonical"].as_str().unwrap().ends_with(",\"v\":1}"));
}

#[test]
fn p_17_3_the_ids_of_the_vectors_are_unique() {
    let mut ids: Vec<String> = vectors()
        .iter()
        .map(|v| v["id"].as_str().unwrap().to_owned())
        .collect();
    ids.sort();
    let count = ids.len();
    ids.dedup();
    assert_eq!(ids.len(), count);
}
