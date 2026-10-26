//! The check of the identity token (9.3 to 9.7). These tests are the cases U01, U03, U07,
//! U09, U10, U14 and U41 to U55 of the conformance series, at the level of the library.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use access_token::cli::AlgName;
use common::*;
use procurauth_pep::refusal::AuthFailure;
use procurauth_pep::{Pep, Refusal};
use serde_json::{Value, json};

fn setup() -> (Pep, Edge) {
    let edge = Edge::new();
    let (pep, _clock) = pep(yes_to_all(), &edge, "http://pdp.test", |_| {});
    (pep, edge)
}

fn check(pep: &Pep, token: &str) -> Result<procurauth_pep::Identity, Refusal> {
    pep.authenticate([(HEADER, token)])
}

fn failed_check(result: Result<procurauth_pep::Identity, Refusal>) -> String {
    match result {
        Err(Refusal::Unauthenticated(AuthFailure::Token { check, .. })) => check,
        other => panic!("expected a refused token, found {other:?}"),
    }
}

fn claims_without(edge: &Edge, member: &str) -> Value {
    let mut claims = edge.claims("alice", None);
    claims.as_object_mut().unwrap().remove(member);
    claims
}

#[test]
fn p_9_4_a_good_token_gives_the_identity_of_a_person() {
    let (pep, edge) = setup();
    let who = check(&pep, &edge.token("alice")).unwrap();
    assert_eq!(who.sub(), "alice");
    assert_eq!(who.owner(), None);
    assert_eq!(who.subject().subject_type, "user");
    assert_eq!(who.expires_at(), NOW + 290);
}

#[test]
fn p_9_3_a_good_token_of_a_key_gives_the_owner_for_the_logs() {
    let (pep, edge) = setup();
    let who = check(&pep, &edge.token_for_key(KEY_ALICE, "alice")).unwrap();
    assert_eq!(who.sub(), KEY_ALICE);
    assert_eq!(who.owner(), Some("alice"));
}

#[test]
fn p_9_4_a_request_with_no_token_is_refused_with_401() {
    let (pep, _) = setup();
    let refusal = pep.authenticate([("Accept", "text/plain")]).unwrap_err();
    assert_eq!(refusal, Refusal::Unauthenticated(AuthFailure::NoToken));
    assert_eq!(refusal.status(), 401);
    assert_eq!(
        pep.authenticate(std::iter::empty::<(&str, &str)>())
            .unwrap_err()
            .status(),
        401
    );
}

#[test]
fn p_9_4_the_header_name_has_no_case_and_a_duplicate_is_refused() {
    let (pep, edge) = setup();
    let token = edge.token("alice");
    assert!(
        pep.authenticate([("x-identity-token", token.as_str())])
            .is_ok()
    );
    assert!(
        pep.authenticate([("X-IDENTITY-TOKEN", token.as_str())])
            .is_ok()
    );
    let refusal = pep
        .authenticate([
            (HEADER, token.as_str()),
            ("x-identity-token", token.as_str()),
        ])
        .unwrap_err();
    assert_eq!(
        refusal,
        Refusal::Unauthenticated(AuthFailure::DuplicateHeader)
    );
}

#[test]
fn p_9_4_the_token_is_never_read_from_authorization_or_a_cookie() {
    let (pep, edge) = setup();
    let token = edge.token("alice");
    let bearer = format!("Bearer {token}");
    let cookie = format!("token={token}");
    let refusal = pep
        .authenticate([
            ("Authorization", bearer.as_str()),
            ("Cookie", cookie.as_str()),
        ])
        .unwrap_err();
    assert_eq!(refusal, Refusal::Unauthenticated(AuthFailure::NoToken));
}

#[test]
fn p_9_4_a_bad_signature_is_refused() {
    let (pep, edge) = setup();
    let mut shape = shape();
    shape.bad_signature = true;
    let token = edge.sign_with(&shape, &edge.claims("alice", None));
    assert_eq!(failed_check(check(&pep, &token)), "signature");
}

#[test]
fn p_9_4_a_token_signed_by_another_key_is_refused() {
    let (pep, _) = setup();
    let other = Edge::es256();
    assert!(check(&pep, &other.token("alice")).is_err());
}

#[test]
fn p_9_2_the_algorithms_none_hs256_and_eddsa_are_refused() {
    let (pep, edge) = setup();
    for alg in [
        AlgName::None,
        AlgName::Hs256,
        AlgName::EdDsa,
        AlgName::Rs256,
    ] {
        let mut shape = shape();
        shape.alg = Some(alg);
        let token = edge.sign_with(&shape, &edge.claims("alice", None));
        let failed = failed_check(check(&pep, &token));
        // The core reports a token with an empty third part as `structure`
        // (`notes/core-requests-access-token.md`, item 3). The token is refused in each case.
        let expected = if alg == AlgName::None {
            "structure"
        } else {
            "alg"
        };
        assert_eq!(failed, expected, "{alg:?}");
    }
}

#[test]
fn p_9_2_a_token_with_another_typ_is_refused() {
    let (pep, edge) = setup();
    for typ in ["at+jwt", "JOSE", "jwt"] {
        let mut shape = shape();
        shape.typ = Some(typ.into());
        let token = edge.sign_with(&shape, &edge.claims("alice", None));
        assert_eq!(failed_check(check(&pep, &token)), "typ", "{typ}");
    }
}

#[test]
fn p_9_4_the_issuer_must_be_the_configured_one() {
    let (pep, edge) = setup();
    let mut claims = edge.claims("alice", None);
    claims["iss"] = json!("https://other.example");
    assert_eq!(failed_check(check(&pep, &edge.sign(&claims))), "iss");
    assert!(check(&pep, &edge.sign(&claims_without(&edge, "iss"))).is_err());
}

#[test]
fn p_9_4_the_audience_is_the_service_or_an_array_that_holds_it() {
    let (pep, edge) = setup();
    let mut claims = edge.claims("alice", None);
    claims["aud"] = json!("other-service");
    assert_eq!(failed_check(check(&pep, &edge.sign(&claims))), "aud");
    claims["aud"] = json!(["a", "b"]);
    assert_eq!(failed_check(check(&pep, &edge.sign(&claims))), "aud");
    claims["aud"] = json!(["a", SERVICE]);
    assert!(check(&pep, &edge.sign(&claims)).is_ok());
    assert!(check(&pep, &edge.sign(&claims_without(&edge, "aud"))).is_err());
}

#[test]
fn p_9_4_each_claim_is_mandatory() {
    let (pep, edge) = setup();
    for member in ["iss", "sub", "aud", "iat", "exp"] {
        let token = edge.sign(&claims_without(&edge, member));
        assert!(check(&pep, &token).is_err(), "{member}");
    }
}

#[test]
fn p_9_4_exp_has_a_skew_and_iat_has_a_skew() {
    let (pep, edge) = setup();
    let mut claims = edge.claims("alice", None);
    // The skew is 30 s. A token that ended 30 s ago is good. A token that ended 31 s ago is not.
    claims["iat"] = json!(NOW - 300);
    claims["exp"] = json!(NOW - 30);
    assert!(check(&pep, &edge.sign(&claims)).is_ok());
    claims["exp"] = json!(NOW - 31);
    assert_eq!(failed_check(check(&pep, &edge.sign(&claims))), "exp");
    let mut claims = edge.claims("alice", None);
    claims["iat"] = json!(NOW + 30);
    assert!(check(&pep, &edge.sign(&claims)).is_ok());
    claims["iat"] = json!(NOW + 31);
    assert_eq!(failed_check(check(&pep, &edge.sign(&claims))), "iat");
}

#[test]
fn p_9_4_a_token_with_a_life_above_the_maximum_age_is_refused() {
    let (pep, edge) = setup();
    let mut claims = edge.claims("alice", None);
    claims["iat"] = json!(NOW - 10);
    claims["exp"] = json!(NOW - 10 + 301);
    assert_eq!(failed_check(check(&pep, &edge.sign(&claims))), "life");
    claims["exp"] = json!(NOW - 10 + 300);
    assert!(check(&pep, &edge.sign(&claims)).is_ok());
}

#[test]
fn p_9_4_a_kid_that_the_set_does_not_hold_is_refused() {
    let (pep, edge) = setup();
    let mut shape = shape();
    shape.kid = Some("unknown".into());
    let token = edge.sign_with(&shape, &edge.claims("alice", None));
    assert_eq!(failed_check(check(&pep, &token)), "kid");
}

#[test]
fn p_9_4_an_unknown_claim_is_ignored_and_sent_nowhere() {
    let edge = Edge::new();
    let transport = yes_to_all();
    let (pep, _) = pep(transport.clone(), &edge, "http://pdp.test", |_| {});
    let mut claims = edge.claims("alice", None);
    claims["x_unknown"] = json!(1);
    claims["email"] = json!("alice@example.org");
    claims["groups"] = json!(["staff"]);
    let who = check(&pep, &edge.sign(&claims)).unwrap();
    assert_eq!(who.sub(), "alice");
    assert!(transport.seen().is_empty());
}

#[test]
fn p_9_5_a_token_with_no_owner_or_an_odd_owner_is_good() {
    let (pep, edge) = setup();
    for owner in [json!(null), json!(42), json!(""), json!(["a"])] {
        let mut claims = edge.claims(KEY_ALICE, None);
        claims["owner"] = owner;
        let who = check(&pep, &edge.sign(&claims)).unwrap();
        assert_eq!(who.sub(), KEY_ALICE);
        assert_eq!(who.owner(), None);
    }
    let who = check(&pep, &edge.sign(&edge.claims("alice", Some("bob")))).unwrap();
    assert_eq!(who.owner(), Some("bob"));
}

#[test]
fn p_3_3_the_sub_stays_as_it_is_for_any_characters() {
    let (pep, edge) = setup();
    for sub in [
        "Mixed:Case-Id",
        "two words",
        "key:UPPER-CASE",
        "caf\u{e9}",
        "a%2Fb+c",
        "robot:7",
    ] {
        let who = check(&pep, &edge.token(sub)).unwrap();
        assert_eq!(who.sub(), sub);
        assert_eq!(who.subject().id, sub);
    }
}

#[test]
fn p_9_2_a_token_signed_with_es256_is_good_when_the_set_holds_the_key() {
    let edge = Edge::es256();
    let (pep, _) = pep(yes_to_all(), &edge, "http://pdp.test", |_| {});
    assert!(check(&pep, &edge.token("alice")).is_ok());
}

#[test]
fn p_9_4_a_token_that_is_not_a_jws_is_refused() {
    let (pep, _) = setup();
    for text in ["", "abc", "a.b", "a.b.c", "a.b.c.d", "   "] {
        assert!(check(&pep, text).is_err(), "{text:?}");
    }
}

#[test]
fn p_9_7_the_check_gives_no_grant_and_asks_no_question() {
    let edge = Edge::new();
    let transport = yes_to_all();
    let (pep, _) = pep(transport.clone(), &edge, "http://pdp.test", |_| {});
    let mut claims = edge.claims("alice", None);
    claims["decision"] = json!(true);
    claims["grants"] = json!([{"action": "data.read"}]);
    claims["limits"] = json!({"max_rows": 1_000_000});
    assert!(check(&pep, &edge.sign(&claims)).is_ok());
    assert!(transport.seen().is_empty());
}
