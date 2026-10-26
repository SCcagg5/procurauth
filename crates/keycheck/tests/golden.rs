//! Golden tests: the exact text and the exact JSON of each verdict.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::{GOLDEN_DIGEST, GOLDEN_KEY, GOLDEN_RANDOM, check, go};
use keycheck::Exit;

fn line(key: &str) -> Vec<u8> {
    format!("{key}\n").into_bytes()
}

#[test]
fn p_3_8_golden_key_has_the_expected_digest_and_length() {
    assert_eq!(GOLDEN_KEY.len(), 53);
    assert!(GOLDEN_KEY.contains(GOLDEN_RANDOM));
    assert_eq!(
        common::format().check(GOLDEN_KEY).unwrap().digest_hex,
        GOLDEN_DIGEST
    );
}

#[test]
fn p_3_8_text_good() {
    let run = check(&line(GOLDEN_KEY));
    assert_eq!(run.exit, Exit::Clean);
    assert_eq!(
        run.stdout,
        format!("good\nsha256: {GOLDEN_DIGEST}\nhint: aB3d\n")
    );
    assert_eq!(run.stderr, "");
}

#[test]
fn p_3_8_json_good() {
    let run = go(
        &["--format", "json", common::FORMAT_PATH],
        &line(GOLDEN_KEY),
    );
    assert_eq!(run.exit, Exit::Clean);
    assert_eq!(
        run.stdout,
        format!("{{\"verdict\":\"good\",\"sha256\":\"{GOLDEN_DIGEST}\",\"hint\":\"aB3d\"}}\n")
    );
    assert_eq!(run.stderr, "");
}

#[test]
fn p_3_8_text_bad_prefix() {
    let key = GOLDEN_KEY.replacen("mcp_", "dlg_", 1);
    let run = check(&line(&key));
    assert_eq!(run.exit, Exit::Findings);
    assert_eq!(run.stdout, "bad: prefix (expected the prefix mcp_)\n");
    assert_eq!(run.stderr, "");
}

#[test]
fn p_3_8_text_bad_length_as_the_site_shows() {
    let key = format!("mcp_{GOLDEN_RANDOM}");
    let run = check(&line(&key));
    assert_eq!(run.exit, Exit::Findings);
    assert_eq!(
        run.stdout,
        "bad: length (expected 53 characters, found 47)\n"
    );
}

#[test]
fn p_3_8_text_bad_alphabet() {
    let mut key = GOLDEN_KEY.to_owned();
    key.replace_range(10..11, "-");
    let run = check(&line(&key));
    assert_eq!(run.exit, Exit::Findings);
    assert_eq!(
        run.stdout,
        "bad: alphabet (the character at position 11 is not in the alphabet A-Za-z0-9)\n"
    );
}

#[test]
fn p_3_8_text_bad_checksum() {
    let key = format!("{}aaaaaa", &GOLDEN_KEY[..47]);
    let run = check(&line(&key));
    assert_eq!(run.exit, Exit::Findings);
    assert_eq!(
        run.stdout,
        "bad: checksum (the checksum characters do not match the text)\n"
    );
}

fn json(key: &str) -> String {
    let run = go(&["--format", "json", common::FORMAT_PATH], &line(key));
    assert_eq!(run.exit, Exit::Findings);
    assert_eq!(run.stderr, "");
    run.stdout
}

#[test]
fn p_3_8_json_bad_causes() {
    assert_eq!(
        json(&GOLDEN_KEY.replacen("mcp_", "dlg_", 1)),
        "{\"verdict\":\"bad\",\"cause\":\"prefix\",\"message\":\"prefix (expected the prefix mcp_)\",\"detail\":{\"expected\":\"mcp_\"}}\n"
    );
    assert_eq!(
        json(&format!("mcp_{GOLDEN_RANDOM}")),
        "{\"verdict\":\"bad\",\"cause\":\"length\",\"message\":\"length (expected 53 characters, found 47)\",\"detail\":{\"expected\":53,\"found\":47}}\n"
    );
    let mut key = GOLDEN_KEY.to_owned();
    key.replace_range(10..11, "-");
    assert_eq!(
        json(&key),
        "{\"verdict\":\"bad\",\"cause\":\"alphabet\",\"message\":\"alphabet (the character at position 11 is not in the alphabet A-Za-z0-9)\",\"detail\":{\"position\":11,\"alphabet\":\"A-Za-z0-9\"}}\n"
    );
    assert_eq!(
        json(&format!("{}aaaaaa", &GOLDEN_KEY[..47])),
        "{\"verdict\":\"bad\",\"cause\":\"checksum\",\"message\":\"checksum (the checksum characters do not match the text)\",\"detail\":{}}\n"
    );
}

#[test]
fn p_3_8_the_json_form_escapes_the_members_of_the_format() {
    // A format with a prefix and an alphabet that need a JSON escape.
    let path = common::scratch_file(
        "escape.json",
        br#"{"prefix": "\"\\", "length": 5, "alphabet": "a-c"}"#,
    );
    let run = go(&["--format", "json", &path], b"zzzzz\n");
    assert_eq!(run.exit, Exit::Findings);
    let value: serde_json::Value = serde_json::from_str(&run.stdout).unwrap();
    assert_eq!(value["detail"]["expected"], "\"\\");
}

#[test]
fn p_3_8_the_order_of_the_checks_is_prefix_length_alphabet_checksum() {
    // A text with a bad prefix, a bad length and a bad character: the cause is the prefix.
    assert!(check(b"zz-\n").stdout.starts_with("bad: prefix"));
    // A good prefix, a bad length and a bad character: the cause is the length.
    assert!(check(b"mcp_-\n").stdout.starts_with("bad: length"));
}
