//! Round trips and bad tokens. Each test is named after the paragraph that it tests.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use serde_json::{Value, json};

const ED: &str = "test-edge-ed25519.pem";
const ES: &str = "test-edge-es256.pem";
const SINGLE: &str = "service.json";
const TWO: &str = "service-two-keys.json";

fn json_check(config: &str, token: &str) -> Out {
    check(config, token, &["--format", "json"])
}

/// The one check that fails, with its rule.
fn only_failure(out: &Out) -> (String, String) {
    assert_eq!(out.code, 1, "{}", out.stdout);
    let names = failing(out);
    assert_eq!(names.len(), 1, "failing checks: {names:?}");
    let rule = check_entry(out, &names[0])["rule"]
        .as_str()
        .unwrap()
        .to_owned();
    (names[0].clone(), rule)
}

#[test]
fn p_9_2_a_good_token_for_a_person_passes_with_ed25519() {
    let token = make(ED, &person_claims(), &["--alg", "Ed25519"]);
    let out = check(SINGLE, &token, &[]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    assert!(out.stdout.contains("signature  ok"));
    assert!(out.stdout.contains("life       ok   life 300 s, max 300 s"));
    assert_eq!(out.stderr, "");
}

#[test]
fn p_9_2_a_good_token_for_a_key_passes_with_es256() {
    let token = make(ES, &key_claims(), &["--kid", "edge-es256"]);
    let out = json_check(TWO, &token);
    assert_eq!(out.code, 0, "{}", out.stdout);
    let document: Value = serde_json::from_str(&out.stdout).unwrap();
    assert_eq!(document["result"], "pass");
    assert_eq!(document["claims"]["owner"], "alice");
    assert_eq!(check_entry(&out, "alg")["detail"], "ES256");
}

#[test]
fn p_9_2_the_default_algorithm_is_the_algorithm_of_the_key() {
    for (key, name) in [(ED, "Ed25519"), (ES, "ES256")] {
        let out = make_out(key, &person_claims(), &["--format", "json"]);
        let document: Value = serde_json::from_str(&out.stdout).unwrap();
        assert_eq!(document["header"], json!({"alg": name, "typ": "JWT"}));
    }
}

#[test]
fn p_9_2_a_good_token_from_a_pem_public_key_passes() {
    let token = make(ED, &person_claims(), &["--kid", "edge-ed25519"]);
    assert_eq!(check(TWO, &token, &[]).code, 0);
}

#[test]
fn p_9_2_the_token_comes_from_a_file_or_from_the_standard_input() {
    let token = make(ED, &person_claims(), &[]);
    let file = temp_file("p_9_2_token_file.jwt", &format!("{token}\n"));
    let config = example(SINGLE);
    let now = NOW.to_string();
    let out = run_cli(&["check", "--config", &config, "--now", &now, &file], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    let crlf = temp_file("p_9_2_token_crlf.jwt", &format!("{token}\r\n"));
    let out = run_cli(&["check", "--config", &config, "--now", &now, &crlf], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
}

#[test]
fn p_9_2_the_claims_come_from_a_file() {
    let file = temp_file("p_9_2_claims.json", &person_claims().to_string());
    let key = example(ED);
    let out = run_cli(&["make", "--key", &key, &file], "");
    assert_eq!(out.code, 0, "{}", out.stderr);
    assert_eq!(check(SINGLE, out.stdout.trim_end(), &[]).code, 0);
}

#[test]
fn p_9_4_an_old_exp_fails_the_check_exp() {
    let mut claims = person_claims();
    claims["iat"] = json!(1_792_569_400_u64);
    claims["exp"] = json!(1_792_569_600_u64);
    let token = make(ED, &claims, &[]);
    let out = json_check(SINGLE, &token);
    assert_eq!(only_failure(&out), ("exp".to_owned(), "9.4".to_owned()));
    assert!(
        check_entry(&out, "exp")["detail"]
            .as_str()
            .unwrap()
            .contains("later than `exp` 1792569600 plus the skew 30 s")
    );
}

#[test]
fn p_9_4_the_skew_applies_to_exp_and_to_iat() {
    let mut claims = person_claims();
    claims["iat"] = json!(1_792_569_500_u64);
    claims["exp"] = json!(NOW - 30);
    assert_eq!(check(SINGLE, &make(ED, &claims, &[]), &[]).code, 0);
    claims["exp"] = json!(NOW - 31);
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out).0, "exp");
    let mut claims = person_claims();
    claims["iat"] = json!(NOW + 30);
    claims["exp"] = json!(NOW + 130);
    assert_eq!(check(SINGLE, &make(ED, &claims, &[]), &[]).code, 0);
    claims["iat"] = json!(NOW + 31);
    claims["exp"] = json!(NOW + 131);
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out), ("iat".to_owned(), "9.4".to_owned()));
}

#[test]
fn p_9_4_a_future_iat_fails_the_check_iat() {
    let mut claims = person_claims();
    claims["iat"] = json!(1_792_570_000_u64);
    claims["exp"] = json!(1_792_570_200_u64);
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out), ("iat".to_owned(), "9.4".to_owned()));
}

#[test]
fn p_9_2_a_life_longer_than_the_maximum_age_fails_the_check_life() {
    let mut claims = person_claims();
    claims["exp"] = json!(1_792_570_000_u64);
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out), ("life".to_owned(), "9.4".to_owned()));
    assert!(
        check_entry(&out, "life")["detail"]
            .as_str()
            .unwrap()
            .contains("The life of the token is 400 s, and the maximum age is 300 s.")
    );
}

#[test]
fn p_9_2_a_life_of_exactly_the_maximum_age_passes() {
    let out = json_check(SINGLE, &make(ED, &person_claims(), &[]));
    assert_eq!(check_entry(&out, "life")["detail"], "life 300 s, max 300 s");
}

#[test]
fn p_9_4_exp_before_iat_fails_the_check_life() {
    let mut claims = person_claims();
    claims["iat"] = json!(NOW - 10);
    claims["exp"] = json!(NOW - 20);
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out).0, "life");
}

#[test]
fn p_9_2_another_typ_fails_the_check_typ() {
    for typ in ["at+jwt", "jwt", "JWS"] {
        let token = make(ED, &person_claims(), &["--typ", typ]);
        let out = json_check(SINGLE, &token);
        assert_eq!(
            only_failure(&out),
            ("typ".to_owned(), "9.2".to_owned()),
            "{typ}"
        );
        assert!(
            check_entry(&out, "typ")["detail"]
                .as_str()
                .unwrap()
                .contains(&format!("expected `JWT`, found \"{typ}\""))
        );
    }
}

#[test]
fn p_9_2_a_good_typ_is_jwt() {
    let token = make(ED, &person_claims(), &["--typ", "JWT"]);
    assert_eq!(check(SINGLE, &token, &[]).code, 0);
}

#[test]
fn p_9_2_a_name_that_the_protocol_does_not_give_fails_the_check_alg() {
    for alg in ["EdDSA", "HS256", "RS256", "none"] {
        let token = make(ED, &person_claims(), &["--alg", alg]);
        let out = json_check(SINGLE, &token);
        let (name, rule) = only_failure(&out);
        assert_eq!((name.as_str(), rule.as_str()), ("alg", "9.2"), "{alg}");
        assert!(
            check_entry(&out, "alg")["detail"]
                .as_str()
                .unwrap()
                .contains(&format!("found \"{alg}\"")),
            "{alg}"
        );
    }
}

#[test]
fn p_9_2_the_algorithm_none_makes_a_token_with_no_signature() {
    let token = make(ED, &person_claims(), &["--alg", "none"]);
    assert!(token.ends_with('.'));
    assert_eq!(token.matches('.').count(), 2);
}

#[test]
fn p_9_2_a_header_that_names_another_algorithm_than_the_key_fails_the_signature() {
    // Alg confusion: the header says ES256 and the edge key is Ed25519.
    let token = make(ED, &person_claims(), &["--alg", "ES256"]);
    let out = json_check(SINGLE, &token);
    assert_eq!(
        only_failure(&out),
        ("signature".to_owned(), "9.4".to_owned())
    );
    assert!(
        check_entry(&out, "signature")["detail"]
            .as_str()
            .unwrap()
            .contains("The header says `ES256`, and the key is for `Ed25519`.")
    );
    // The same in the other direction: the key is ES256 and the header says Ed25519.
    let token = make(
        ES,
        &person_claims(),
        &["--alg", "Ed25519", "--kid", "edge-es256"],
    );
    let out = json_check(TWO, &token);
    assert_eq!(only_failure(&out).0, "signature");
}

#[test]
fn p_9_4_a_bad_signature_fails_the_check_signature() {
    for key in [ED, ES] {
        let kid = if key == ED {
            "edge-ed25519"
        } else {
            "edge-es256"
        };
        let token = make(key, &person_claims(), &["--bad-signature", "--kid", kid]);
        let out = json_check(TWO, &token);
        assert_eq!(
            only_failure(&out),
            ("signature".to_owned(), "9.4".to_owned()),
            "{key}"
        );
    }
}

#[test]
fn p_9_4_a_token_that_another_key_signed_fails_the_signature() {
    // The token has the kid of the Ed25519 key, but the ES256 key signed it.
    let token = make(
        ES,
        &person_claims(),
        &["--alg", "Ed25519", "--kid", "edge-ed25519"],
    );
    let out = json_check(TWO, &token);
    assert_eq!(only_failure(&out).0, "signature");
}

#[test]
fn p_9_3_each_claim_is_mandatory() {
    for claim in ["iss", "sub", "aud", "iat", "exp"] {
        let mut claims = person_claims();
        claims.as_object_mut().unwrap().remove(claim);
        // `make` refuses the claims, and it gives no token.
        let refused = make_out(ED, &claims, &[]);
        assert_eq!(refused.code, 1, "{claim}");
        assert_eq!(refused.stdout, "", "{claim}");
        assert!(
            refused.stderr.contains("rule 9.3"),
            "{claim}: {}",
            refused.stderr
        );
        assert!(
            refused.stderr.contains(&format!("`{claim}`")),
            "{claim}: {}",
            refused.stderr
        );
        // With the option, `make` makes the token, and `check` refuses it.
        let token = make(ED, &claims, &["--allow-bad-claims"]);
        let out = json_check(SINGLE, &token);
        assert_eq!(out.code, 1, "{claim}");
        let failed = failing(&out);
        assert!(failed.contains(&"claims".to_owned()), "{claim}: {failed:?}");
        assert_eq!(check_entry(&out, "claims")["rule"], "9.3");
        assert!(failed.contains(&claim.to_owned()), "{claim}: {failed:?}");
    }
}

#[test]
fn p_9_4_a_wrong_issuer_fails_the_check_iss() {
    let mut claims = person_claims();
    claims["iss"] = json!("https://other.example");
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out), ("iss".to_owned(), "9.4".to_owned()));
}

#[test]
fn p_9_4_a_wrong_audience_fails_the_check_aud() {
    let mut claims = person_claims();
    claims["aud"] = json!("reports");
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out), ("aud".to_owned(), "9.4".to_owned()));
}

#[test]
fn p_9_4_an_audience_array_that_holds_the_service_passes() {
    let mut claims = person_claims();
    claims["aud"] = json!(["reports", "datastore"]);
    let out = check(SINGLE, &make(ED, &claims, &[]), &[]);
    assert_eq!(out.code, 0, "{}", out.stdout);
    claims["aud"] = json!(["reports"]);
    let out = json_check(SINGLE, &make(ED, &claims, &[]));
    assert_eq!(only_failure(&out).0, "aud");
}

#[test]
fn p_9_4_an_unknown_claim_is_ignored() {
    let mut claims = person_claims();
    claims["scope"] = json!("read");
    claims["nbf"] = json!(1);
    let out = check(SINGLE, &make(ED, &claims, &[]), &[]);
    assert_eq!(out.code, 0, "{}", out.stdout);
}

#[test]
fn p_9_3_a_token_for_a_key_needs_the_claim_owner() {
    let mut claims = key_claims();
    claims.as_object_mut().unwrap().remove("owner");
    let refused = make_out(ED, &claims, &[]);
    assert_eq!(refused.code, 1);
    assert!(refused.stderr.contains("rule 9.3"));
    assert!(refused.stderr.contains("`owner`"));
    // The service does not use `owner` (9.5), so the token still passes `check`.
    let token = make(ED, &claims, &["--allow-bad-claims"]);
    assert_eq!(check(SINGLE, &token, &[]).code, 0);
}

#[test]
fn p_9_3_the_claim_act_is_refused_by_make() {
    let mut claims = key_claims();
    claims["act"] = json!({"sub": "alice"});
    let refused = make_out(ED, &claims, &[]);
    assert_eq!(refused.code, 1);
    assert!(refused.stderr.contains("`act`"));
}

#[test]
fn p_9_3_a_warning_does_not_stop_make() {
    let mut claims = person_claims();
    claims["owner"] = json!("alice");
    let out = make_out(ED, &claims, &[]);
    assert_eq!(out.code, 0);
    assert!(out.stderr.starts_with("warning: $.owner: rule 9.3"));
    assert!(out.stdout.starts_with("eyJ"));
}

#[test]
fn p_9_4_a_header_with_crit_fails_the_check_header() {
    let token = make(ED, &person_claims(), &["--crit", "exp"]);
    let out = json_check(SINGLE, &token);
    assert_eq!(only_failure(&out), ("header".to_owned(), "9.4".to_owned()));
}

#[test]
fn p_9_4_a_token_with_a_wrong_form_fails_the_check_structure() {
    for token in ["", "a.b", "a.b.c.d", "!!!.!!!.!!!", "eyJ.eyJ.eyJ"] {
        let out = json_check(SINGLE, token);
        assert_eq!(out.code, 1, "{token}");
        assert_eq!(failing(&out), vec!["structure".to_owned()], "{token}");
    }
}

#[test]
fn p_9_4_a_token_above_the_largest_size_fails_the_check_structure() {
    let token = format!("{}.b.c", "a".repeat(20_000));
    let out = json_check(SINGLE, &token);
    assert_eq!(failing(&out), vec!["structure".to_owned()]);
}

#[test]
fn p_9_4_a_check_that_does_not_run_is_shown_as_skip() {
    let out = check(SINGLE, "a.b", &[]);
    assert_eq!(out.code, 1);
    assert!(out.stdout.starts_with("structure  fail"));
    assert!(out.stdout.contains("\nsignature  skip\n"));
}

#[test]
fn p_9_4_a_service_with_one_key_accepts_a_token_without_kid() {
    let token = make(ED, &person_claims(), &[]);
    assert_eq!(check(SINGLE, &token, &[]).code, 0);
}

#[test]
fn p_9_4_a_service_with_one_key_refuses_a_kid_that_the_set_does_not_hold() {
    let token = make(ED, &person_claims(), &["--kid", "other"]);
    let out = json_check(SINGLE, &token);
    assert_eq!(only_failure(&out).0, "kid");
}

#[test]
fn p_9_4_a_service_with_two_keys_needs_a_kid() {
    let token = make(ED, &person_claims(), &[]);
    let out = json_check(TWO, &token);
    assert_eq!(only_failure(&out), ("kid".to_owned(), "9.4".to_owned()));
    assert!(
        check_entry(&out, "kid")["detail"]
            .as_str()
            .unwrap()
            .contains("more than one key")
    );
}

#[test]
fn p_9_4_a_service_refuses_a_kid_that_the_set_does_not_hold() {
    let token = make(ED, &person_claims(), &["--kid", "unknown"]);
    let out = json_check(TWO, &token);
    assert_eq!(only_failure(&out).0, "kid");
}

#[test]
fn p_9_4_the_kid_chooses_the_key() {
    for (key, kid) in [(ED, "edge-ed25519"), (ES, "edge-es256")] {
        let token = make(key, &person_claims(), &["--kid", kid]);
        let out = json_check(TWO, &token);
        assert_eq!(out.code, 0, "{kid}: {}", out.stdout);
        assert_eq!(check_entry(&out, "kid")["detail"], kid);
    }
}

#[test]
fn p_9_4_the_json_result_lists_the_13_checks_in_a_fixed_order() {
    let out = json_check(SINGLE, &make(ED, &person_claims(), &[]));
    let document: Value = serde_json::from_str(&out.stdout).unwrap();
    let names: Vec<&str> = document["checks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        [
            "structure",
            "header",
            "alg",
            "typ",
            "kid",
            "signature",
            "claims",
            "iss",
            "sub",
            "aud",
            "iat",
            "exp",
            "life"
        ]
    );
    assert_eq!(document["now"], NOW);
}

#[test]
fn p_9_4_the_clock_is_read_only_without_the_flag_now() {
    let token = make(ED, &person_claims(), &[]);
    let config = example(SINGLE);
    let out = run_with_clock(&["check", "--config", &config, "-"], &token, &|| Ok(NOW));
    assert_eq!(out.code, 0, "{}", out.stderr);
    let out = run_with_clock(&["check", "--config", &config, "-"], &token, &|| {
        Ok(NOW + 10_000)
    });
    assert_eq!(out.code, 1);
    let out = run_with_clock(&["check", "--config", &config, "-"], &token, &|| {
        Err("The clock is broken.".to_owned())
    });
    assert_eq!(out.code, 2);
    assert!(out.stderr.contains("The clock is broken."));
    // With the flag, the program does not call the clock.
    let now = NOW.to_string();
    let out = run_with_clock(
        &["check", "--config", &config, "--now", &now, "-"],
        &token,
        &|| panic!("the clock must not be read"),
    );
    assert_eq!(out.code, 0);
}

#[test]
fn p_9_2_a_bad_token_never_depends_on_the_clock_of_make() {
    // `make` has no clock: the same input gives the same token.
    let first = make(ED, &person_claims(), &[]);
    let second = make(ED, &person_claims(), &[]);
    assert_eq!(first, second);
    let first = make(ES, &person_claims(), &[]);
    let second = make(ES, &person_claims(), &[]);
    assert_eq!(first, second);
}
