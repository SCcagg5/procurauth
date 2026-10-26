//! Golden tests: the exact text and JSON output of the tool.
//!
//! A golden file is in `tests/golden/`. When the output changes on purpose,
//! write the new output to the file by hand and read the difference.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::json;

fn golden(name: &str, actual: &str) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("golden")
        .join(name);
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read the golden file {}: {e}", path.display()));
    assert_eq!(actual, expected, "the output differs from {name}");
}

const ED: &str = "test-edge-ed25519.pem";
const ES: &str = "test-edge-es256.pem";

#[test]
fn p_9_2_golden_token_ed25519() {
    let out = make_out(ED, &person_claims(), &["--alg", "Ed25519"]);
    golden("make_ed25519.txt", &out.stdout);
}

#[test]
fn p_9_2_golden_token_es256() {
    let out = make_out(
        ES,
        &key_claims(),
        &["--alg", "ES256", "--kid", "edge-es256"],
    );
    golden("make_es256.txt", &out.stdout);
}

#[test]
fn p_9_2_golden_make_json() {
    let out = make_out(
        ED,
        &key_claims(),
        &["--format", "json", "--kid", "edge-ed25519"],
    );
    golden("make_ed25519.json", &out.stdout);
}

#[test]
fn p_9_3_golden_make_refused_in_text_and_json() {
    let mut claims = key_claims();
    claims.as_object_mut().unwrap().remove("owner");
    let out = make_out(ED, &claims, &[]);
    golden("make_refused.stderr.txt", &out.stderr);
    let out = make_out(ED, &claims, &["--format", "json"]);
    golden("make_refused.json", &out.stdout);
}

#[test]
fn p_9_4_golden_check_of_a_good_token_in_text() {
    let token = make(ED, &person_claims(), &[]);
    golden("check_good.txt", &check("service.json", &token, &[]).stdout);
}

#[test]
fn p_9_4_golden_check_of_a_good_token_in_json() {
    let token = make(ES, &key_claims(), &["--kid", "edge-es256"]);
    golden(
        "check_good.json",
        &check("service-two-keys.json", &token, &["--format", "json"]).stdout,
    );
}

#[test]
fn p_9_4_golden_check_of_an_expired_token() {
    let mut claims = person_claims();
    claims["iat"] = json!(1_792_569_400_u64);
    claims["exp"] = json!(1_792_569_600_u64);
    let token = make(ED, &claims, &[]);
    golden(
        "check_expired.txt",
        &check("service.json", &token, &[]).stdout,
    );
}

#[test]
fn p_9_4_golden_check_of_a_bad_signature_in_json() {
    let token = make(ED, &person_claims(), &["--bad-signature"]);
    golden(
        "check_bad_signature.json",
        &check("service.json", &token, &["--format", "json"]).stdout,
    );
}

#[test]
fn p_9_2_golden_check_of_alg_none() {
    let token = make(ED, &person_claims(), &["--alg", "none"]);
    golden(
        "check_alg_none.txt",
        &check("service.json", &token, &[]).stdout,
    );
}

#[test]
fn p_9_4_golden_check_of_a_wrong_typ_and_a_long_life() {
    let mut claims = person_claims();
    claims["exp"] = json!(1_792_570_000_u64);
    let token = make(ED, &claims, &["--typ", "at+jwt"]);
    golden(
        "check_typ_life.txt",
        &check("service.json", &token, &[]).stdout,
    );
}

#[test]
fn p_9_4_golden_effective_configuration() {
    let config = example("service-two-keys.json");
    let out = run_cli(&["check", "--config", &config, "--print-config"], "");
    golden("print_config.txt", &out.stdout);
    let out = run_cli(
        &[
            "check",
            "--config",
            &config,
            "--print-config",
            "--format",
            "json",
        ],
        "",
    );
    golden("print_config.json", &out.stdout);
}

#[test]
fn p_9_4_golden_configuration_errors() {
    let bad = temp_file(
        "golden_bad_config.json",
        "{\"token_header\": \"Cookie\", \"iss\": 5, \"service_id\": \"datastore\", \"max_age_seconds\": 0, \"extra\": true}",
    );
    let out = run_cli(&["check", "--config", &bad, "--now", "1", "-"], "");
    let text = out.stderr.replace(&bad, "CONFIG");
    golden("config_errors.stderr.txt", &text);
}
