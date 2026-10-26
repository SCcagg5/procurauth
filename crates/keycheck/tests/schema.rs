//! The example format and the JSON output against their schemas.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::fs;

use common::{GOLDEN_KEY, GOLDEN_RANDOM, check, go};
use procurauth_schema_check::Schemas;
use serde_json::{Value, json};

fn valid(name: &str, value: &Value) -> bool {
    Schemas::load().unwrap().is_valid(name, value).unwrap()
}

#[test]
fn p_3_8_the_example_format_is_valid_against_the_schema() {
    let text = fs::read_to_string(common::FORMAT_PATH).unwrap();
    let value: Value = serde_json::from_str(&text).unwrap();
    let errors = Schemas::load()
        .unwrap()
        .validate("key-format", &value)
        .unwrap();
    assert!(errors.is_empty(), "{errors:?}");
    // The strict reader of the core also accepts it, and it is the format of the site.
    assert_eq!(common::format().length, 53);
    assert_eq!(
        value,
        json!({
            "prefix": "mcp_", "length": 53, "alphabet": "A-Za-z0-9",
            "checksum": {"algorithm": "crc32", "encoding": "base62", "characters": 6}
        })
    );
}

fn json_output(stdin: &[u8]) -> Value {
    let run = go(&["--format", "json", common::FORMAT_PATH], stdin);
    assert_eq!(run.stdout.matches('\n').count(), 1, "one line");
    assert!(run.stdout.ends_with('\n'));
    serde_json::from_str(&run.stdout).unwrap()
}

#[test]
fn p_3_8_the_json_of_each_verdict_is_valid_against_the_schema() {
    let mut alphabet = GOLDEN_KEY.to_owned();
    alphabet.replace_range(10..11, "-");
    let inputs = [
        GOLDEN_KEY.to_owned(),
        GOLDEN_KEY.replacen("mcp_", "dlg_", 1),
        format!("mcp_{GOLDEN_RANDOM}"),
        alphabet,
        format!("{}aaaaaa", &GOLDEN_KEY[..47]),
    ];
    let causes = ["good", "prefix", "length", "alphabet", "checksum"];
    for (input, cause) in inputs.iter().zip(causes) {
        let value = json_output(input.as_bytes());
        assert!(valid("keycheck-output", &value), "{cause}: {value}");
        let label = if cause == "good" {
            &value["verdict"]
        } else {
            &value["cause"]
        };
        assert_eq!(label, cause);
    }
}

#[test]
fn p_3_8_each_example_of_the_schema_is_what_the_tool_prints() {
    let schemas = Schemas::load().unwrap();
    let examples = schemas.examples("keycheck-output");
    assert_eq!(examples.len(), 5);
    let mut alphabet = GOLDEN_KEY.to_owned();
    alphabet.replace_range(10..11, "-");
    let inputs = [
        GOLDEN_KEY.to_owned(),
        GOLDEN_KEY.replacen("mcp_", "dlg_", 1),
        format!("mcp_{GOLDEN_RANDOM}"),
        alphabet,
        format!("{}aaaaaa", &GOLDEN_KEY[..47]),
    ];
    for (example, input) in examples.iter().zip(inputs) {
        assert_eq!(&json_output(input.as_bytes()), example);
    }
}

#[test]
fn p_3_8_the_json_text_and_the_text_form_agree() {
    let key = format!("mcp_{GOLDEN_RANDOM}");
    let value = json_output(key.as_bytes());
    let text = check(key.as_bytes()).stdout;
    assert_eq!(
        text,
        format!("bad: {}\n", value["message"].as_str().unwrap())
    );
}

#[test]
fn the_schema_rejects_a_wrong_output() {
    let good = json!({"verdict": "good", "sha256": "a".repeat(64), "hint": "abcd"});
    assert!(valid("keycheck-output", &good));
    let mut v = good.clone();
    v["hint"] = json!("abcde");
    assert!(!valid("keycheck-output", &v));
    let mut v = good.clone();
    v["sha256"] = json!("ABC");
    assert!(!valid("keycheck-output", &v));
    let mut v = good.clone();
    v["key"] = json!("mcp_");
    assert!(!valid("keycheck-output", &v));
    let bad = json!({"verdict": "bad", "cause": "length", "message": "m", "detail": {"expected": 53, "found": 47}});
    assert!(valid("keycheck-output", &bad));
    let mut v = bad.clone();
    v["cause"] = json!("other");
    assert!(!valid("keycheck-output", &v));
    let mut v = bad.clone();
    v["detail"] = json!({"expected": 53});
    assert!(!valid("keycheck-output", &v));
    let mut v = bad;
    v["detail"]["text"] = json!("mcp_");
    assert!(!valid("keycheck-output", &v));
}
