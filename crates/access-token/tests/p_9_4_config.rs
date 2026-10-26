//! The strict reader of the configuration of a service (protocol 9.4).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use access_token::config::Config;
use common::*;
use procurauth_schema_check::Schemas;
use serde_json::{Value, json};

const NAME: &str = "access-token-config";

fn good() -> Value {
    serde_json::from_str(&example_text("service.json")).unwrap()
}

fn errors_of(value: &Value) -> Vec<String> {
    match Config::from_value(value) {
        Ok(_) => Vec::new(),
        Err(errors) => errors.iter().map(ToString::to_string).collect(),
    }
}

fn with(name: &str, value: Value) -> Value {
    let mut config = good();
    config[name] = value;
    config
}

fn without(name: &str) -> Value {
    let mut config = good();
    config.as_object_mut().unwrap().remove(name);
    config
}

/// Assert that the configuration has an error that holds each fragment.
fn assert_error(config: &Value, fragments: &[&str]) {
    let errors = errors_of(config);
    assert!(
        errors
            .iter()
            .any(|error| fragments.iter().all(|f| error.contains(f))),
        "no error with {fragments:?} in {errors:#?}"
    );
}

#[test]
fn p_9_4_the_example_files_are_good() {
    for name in ["service.json", "service-two-keys.json"] {
        let config = Config::parse(&example_text(name)).unwrap();
        assert!(!config.key_info.is_empty(), "{name}");
    }
    let config = Config::parse(&example_text("service-two-keys.json")).unwrap();
    assert_eq!(config.key_info.len(), 2);
    assert_eq!(config.policy.max_age_seconds, 300);
    assert_eq!(config.policy.skew_seconds, 30);
    assert_eq!(config.policy.issuer, "https://edge.example");
    assert_eq!(config.policy.service_id, "datastore");
    assert_eq!(config.token_header, "X-Identity-Token");
}

#[test]
fn p_9_4_a_text_that_is_not_json_is_refused() {
    let errors = Config::parse("{").unwrap_err();
    assert!(errors[0].message.contains("not valid JSON"));
}

#[test]
fn p_9_4_a_duplicate_member_is_refused() {
    let text = example_text("service.json").replace(
        "\"skew_seconds\": 30,",
        "\"skew_seconds\": 30,\n  \"skew_seconds\": 31,",
    );
    let errors = Config::parse(&text).unwrap_err();
    assert!(
        errors[0]
            .message
            .contains("duplicate member `skew_seconds`"),
        "{errors:?}"
    );
}

#[test]
fn p_9_4_an_unknown_member_is_refused() {
    let config = with("clock", json!(1));
    assert_error(&config, &["$.clock", "Member `clock` is not known here."]);
    let mut config = good();
    config["jwks"]["keys"][0]["extra"] = json!(1);
    assert_error(&config, &["$.jwks.keys[0].extra", "not known"]);
    let config = with("pem_keys", json!([{"pem": "x", "color": "red"}]));
    assert_error(&config, &["$.pem_keys[0].color", "not known"]);
}

#[test]
fn p_9_4_each_member_is_mandatory() {
    for name in [
        "token_header",
        "iss",
        "service_id",
        "max_age_seconds",
        "skew_seconds",
    ] {
        assert_error(
            &without(name),
            &["$", &format!("Member `{name}` is absent.")],
        );
    }
}

#[test]
fn p_9_4_a_member_of_the_wrong_type_names_the_key_the_type_and_the_value() {
    assert_error(
        &with("max_age_seconds", json!("300")),
        &[
            "$.max_age_seconds",
            "expected a whole number of 0 or more",
            "found a string",
            "\"300\"",
        ],
    );
    assert_error(
        &with("skew_seconds", json!(1.5)),
        &["$.skew_seconds", "found a number", "1.5"],
    );
    assert_error(
        &with("skew_seconds", json!(-1)),
        &["$.skew_seconds", "found a number", "-1"],
    );
    assert_error(
        &with("iss", json!(5)),
        &["$.iss", "expected a string", "found a number", "5"],
    );
}

#[test]
fn p_9_4_the_maximum_age_is_one_second_or_more() {
    assert_error(
        &with("max_age_seconds", json!(0)),
        &[
            "$.max_age_seconds",
            "expected a whole number of 1 or more, found 0",
        ],
    );
    assert!(errors_of(&with("max_age_seconds", json!(1))).is_empty());
}

#[test]
fn p_9_4_the_skew_can_be_zero_and_a_value_is_never_changed() {
    let config = Config::from_value(&with("skew_seconds", json!(0))).unwrap();
    assert_eq!(config.policy.skew_seconds, 0);
    let config = Config::from_value(&with("max_age_seconds", json!(99_999_999_u64))).unwrap();
    assert_eq!(config.policy.max_age_seconds, 99_999_999);
}

#[test]
fn p_9_4_the_issuer_is_not_empty() {
    assert_error(&with("iss", json!("")), &["$.iss", "not empty"]);
}

#[test]
fn p_9_4_the_service_id_follows_the_rules_of_an_id() {
    assert_error(
        &with("service_id", json!("")),
        &["$.service_id", "rule 4.1", "the id is empty"],
    );
    assert_error(
        &with("service_id", json!("a\u{7}b")),
        &["$.service_id", "control character"],
    );
    assert_error(
        &with("service_id", json!("x".repeat(257))),
        &["$.service_id", "257 bytes"],
    );
}

#[test]
fn p_9_4_the_token_header_is_a_field_name_and_not_a_forbidden_header() {
    for name in [
        "Authorization",
        "authorization",
        "Proxy-Authorization",
        "COOKIE",
        "Cookie",
    ] {
        assert_error(
            &with("token_header", json!(name)),
            &["$.token_header", "other than `Authorization`", name],
        );
    }
    for name in ["", "X Identity", "X:Identity", "X-Ident\u{e9}"] {
        assert_error(
            &with("token_header", json!(name)),
            &["$.token_header", "expected an HTTP field name"],
        );
    }
    assert!(errors_of(&with("token_header", json!("X-Identity-Token"))).is_empty());
}

#[test]
fn p_9_4_the_file_needs_a_public_key() {
    let mut config = without("jwks");
    assert_error(&config, &["$", "at least one public key"]);
    config["pem_keys"] = json!([]);
    assert_error(&config, &["$.pem_keys", "at least one key"]);
    assert_error(
        &with("jwks", json!({"keys": []})),
        &["$.jwks.keys", "The set has no key."],
    );
}

#[test]
fn p_9_4_the_set_holds_public_keys_only() {
    let mut config = good();
    config["jwks"]["keys"][0]["d"] = json!("AAAA");
    assert_error(&config, &["$.jwks.keys[0].d", "public keys only"]);
    let mut config = good();
    config["jwks"]["keys"][0]["x"] = json!("AAAA");
    assert_error(&config, &["$.jwks.keys[0].x", "32 bytes"]);
    assert_error(&with("jwks", json!([])), &["$.jwks", "Expected an object"]);
}

#[test]
fn p_9_4_a_pem_key_needs_a_public_key_in_pem_form() {
    let pem = example_text("test-edge-ed25519.pub.pem");
    let mut good_pem = without("jwks");
    good_pem["pem_keys"] = json!([{"pem": pem}]);
    assert!(errors_of(&good_pem).is_empty());
    for bad in [
        "",
        "hello",
        "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n",
    ] {
        let config = without("jwks");
        let mut config = config;
        config["pem_keys"] = json!([{"pem": bad}]);
        let expected = if bad.is_empty() {
            "a text that is not a PEM text"
        } else {
            "found"
        };
        assert_error(
            &config,
            &["$.pem_keys[0].pem", "expected a PEM public key", expected],
        );
    }
}

#[test]
fn p_9_4_a_private_key_in_the_pem_member_is_refused_and_never_shown() {
    for key in ["test-edge-ed25519.pem", "test-edge-es256.pem"] {
        let mut config = without("jwks");
        config["pem_keys"] = json!([{"pem": example_text(key)}]);
        let errors = errors_of(&config);
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("-----BEGIN PRIVATE KEY-----"));
        for line in example_text(key)
            .lines()
            .filter(|l| !l.starts_with("-----"))
        {
            assert!(!errors[0].contains(line), "the error shows the key");
        }
        assert_no_secret(&errors.join("\n"), key);
    }
}

#[test]
fn p_9_4_a_pem_key_can_have_a_kid_and_the_kid_is_not_empty() {
    let pem = example_text("test-edge-ed25519.pub.pem");
    let mut config = without("jwks");
    config["pem_keys"] = json!([{"pem": pem, "kid": ""}]);
    assert_error(&config, &["$.pem_keys[0].kid", "not empty"]);
    config["pem_keys"] = json!([{"pem": pem, "kid": "k1"}]);
    let read = Config::from_value(&config).unwrap();
    assert_eq!(read.key_info[0].kid.as_deref(), Some("k1"));
    assert_eq!(read.key_info[0].source, "pem_keys[0]");
}

#[test]
fn p_9_4_a_set_with_two_keys_needs_a_kid_for_each_key() {
    let pem = example_text("test-edge-ed25519.pub.pem");
    let mut config = good();
    config["pem_keys"] = json!([{"pem": pem, "kid": "k1"}]);
    assert_error(
        &config,
        &["The set holds 2 keys", "`jwks.keys[0]` has no `kid`"],
    );
    let mut config = good();
    config["pem_keys"] = json!([{"pem": pem}]);
    let errors = errors_of(&config);
    assert_eq!(errors.len(), 2, "{errors:?}");
}

#[test]
fn p_9_4_two_keys_with_the_same_kid_are_refused() {
    let pem = example_text("test-edge-ed25519.pub.pem");
    let mut config = good();
    config["jwks"]["keys"][0]["kid"] = json!("same");
    config["pem_keys"] = json!([{"pem": pem, "kid": "same"}]);
    assert_error(
        &config,
        &[
            "The `kid` \"same\" occurs more than one time",
            "pem_keys[0]",
        ],
    );
}

#[test]
fn p_9_4_the_reader_gives_every_error_in_one_run() {
    let config = json!({"token_header": "Cookie", "iss": "", "service_id": 5, "max_age_seconds": 0, "skew_seconds": "x", "z": 1});
    let errors = errors_of(&config);
    assert!(errors.len() >= 6, "{errors:#?}");
}

#[test]
fn p_9_4_the_effective_configuration_shows_each_value_and_its_source() {
    let config = Config::parse(&example_text("service-two-keys.json")).unwrap();
    let effective = config.effective();
    assert_eq!(effective["max_age_seconds"], 300);
    assert_eq!(effective["keys"][0]["source"], "file:jwks.keys[0]");
    assert_eq!(effective["keys"][1]["source"], "file:pem_keys[0]");
    assert_eq!(effective["keys"][1]["alg"], "Ed25519");
    assert_eq!(effective["keys"][0]["kid"], "edge-es256");
    // The effective configuration shows no key material.
    let text = effective.to_string();
    assert!(!text.contains("AHgxA-H8"));
    assert!(!text.contains("BEGIN"));
}

// The table of the agreement between the schema and the reader. A row where they differ
// names a rule that a schema cannot state.
#[test]
fn p_9_4_the_schema_and_the_reader_agree() {
    let schemas = Schemas::load().unwrap();
    let pem = example_text("test-edge-ed25519.pub.pem");
    let mut private_in_pem = without("jwks");
    private_in_pem["pem_keys"] = json!([{"pem": example_text("test-edge-ed25519.pem")}]);
    let mut jwk_with_d = good();
    jwk_with_d["jwks"]["keys"][0]["d"] = json!("AAAA");
    let mut two_without_kid = good();
    two_without_kid["pem_keys"] = json!([{"pem": pem}]);
    // (name, document, reader says good, schema says good)
    let rows: Vec<(&str, Value, bool, bool)> = vec![
        ("the example", good(), true, true),
        ("an unknown member", with("clock", json!(1)), false, false),
        ("no token_header", without("token_header"), false, false),
        ("no iss", without("iss"), false, false),
        ("no service_id", without("service_id"), false, false),
        (
            "no max_age_seconds",
            without("max_age_seconds"),
            false,
            false,
        ),
        ("no skew_seconds", without("skew_seconds"), false, false),
        ("no key", without("jwks"), false, false),
        (
            "max_age_seconds is 0",
            with("max_age_seconds", json!(0)),
            false,
            false,
        ),
        (
            "skew_seconds is 0",
            with("skew_seconds", json!(0)),
            true,
            true,
        ),
        (
            "skew_seconds is a string",
            with("skew_seconds", json!("1")),
            false,
            false,
        ),
        (
            "skew_seconds is 1.5",
            with("skew_seconds", json!(1.5)),
            false,
            false,
        ),
        ("an empty iss", with("iss", json!("")), false, false),
        (
            "an empty service_id",
            with("service_id", json!("")),
            false,
            false,
        ),
        (
            "a header with a space",
            with("token_header", json!("X A")),
            false,
            false,
        ),
        (
            "the header Authorization",
            with("token_header", json!("Authorization")),
            false,
            true,
        ),
        ("a private key in pem", private_in_pem, false, true),
        ("a JWK with d", jwk_with_d, false, true),
        ("two keys, one without kid", two_without_kid, false, true),
        (
            "an empty jwks",
            with("jwks", json!({"keys": []})),
            false,
            false,
        ),
    ];
    for (name, document, reader_good, schema_good) in rows {
        assert_eq!(
            errors_of(&document).is_empty(),
            reader_good,
            "reader: {name}"
        );
        assert_eq!(
            schemas.is_valid(NAME, &document).unwrap(),
            schema_good,
            "schema: {name}"
        );
    }
    for example in schemas.examples(NAME) {
        assert!(errors_of(&example).is_empty(), "example: {example}");
    }
    for file in ["service.json", "service-two-keys.json"] {
        let document: Value = serde_json::from_str(&example_text(file)).unwrap();
        assert!(schemas.is_valid(NAME, &document).unwrap(), "{file}");
    }
}

#[test]
fn p_9_4_the_check_stops_before_it_reads_the_token_when_the_configuration_is_bad() {
    let bad = temp_file("p_9_4_bad_config.json", "{\"iss\": 5, \"zzz\": 1}");
    let out = run_cli(&["check", "--config", &bad, "--now", "1", "-"], "a.b.c");
    assert_eq!(out.code, 2);
    assert_eq!(out.stdout, "");
    assert!(out.stderr.contains("$.iss"));
    assert!(out.stderr.contains("$.zzz"));
    assert!(out.stderr.contains("Member `token_header` is absent."));
    assert!(
        out.stderr
            .lines()
            .all(|l| l.starts_with("error: Configuration `"))
    );
}
