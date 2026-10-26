//! The edge, with real HTTP on the loopback address. The tests use a test PDP (`fake-pdp`),
//! a tiny service behind the edge, and the edge in the same process. The names of the
//! tests follow the paragraphs of the protocol (`p_9_8_...`) and of the MCP binding (`mcp_6_2_...`).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, Instant};

use common::*;
use procurauth_core::identity::{TokenPolicy, verify};
use procurauth_core::jws::KeySet;
use serde_json::json;

fn policy() -> TokenPolicy {
    TokenPolicy {
        issuer: ISSUER.to_owned(),
        service_id: SERVICE.to_owned(),
        max_age_seconds: 300,
        skew_seconds: 30,
    }
}

fn auth(text: &str) -> String {
    format!("Bearer {text}")
}

const INVALID: &str = "Bearer error=\"invalid_token\"";

// ---- 9.8: the refusals ---------------------------------------------------------------------------------------

#[test]
fn p_9_8_a_request_with_no_key_gets_401_bearer_and_an_empty_body() {
    let rig = rig();
    let reply = rig.get("/probe", &[]);
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
    assert!(reply.body.is_empty());
    assert_eq!(rig.service.count(), 0);
    assert!(
        rig.questions().is_empty(),
        "no question for a request with no key"
    );
}

#[test]
fn p_9_8_an_unknown_key_gets_401_with_invalid_token_and_an_empty_body() {
    let rig = rig();
    let reply = rig.get("/probe", &[("Authorization", &auth(KEY_UNKNOWN))]);
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("www-authenticate"), Some(INVALID));
    assert!(reply.body.is_empty());
    assert_eq!(reply.header("location"), None);
    assert_eq!(rig.service.count(), 0);
    assert!(
        rig.questions().is_empty(),
        "the edge does not ask the PDP about an unknown key"
    );
}

#[test]
fn p_9_8_a_text_with_a_bad_form_gets_the_same_answer_as_an_unknown_key() {
    let rig = rig();
    let unknown = rig.get("/probe", &[("Authorization", &auth(KEY_UNKNOWN))]);
    for text in [
        "",
        "x",
        "pk_live_",
        "mcp_0000000000000000000000000000000000000000001",
        "pk_live_000000000000000000000000000000000000000000a",
    ] {
        let header = auth(text);
        let reply = rig.get("/probe", &[("Authorization", &header)]);
        assert_eq!(reply.status, unknown.status, "{text:?}");
        if text.is_empty() {
            // "Bearer " has no text: it is a request with no key.
            assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
        } else {
            assert_eq!(reply.header("www-authenticate"), Some(INVALID), "{text:?}");
        }
        assert!(reply.body.is_empty());
    }
    assert_eq!(rig.service.count(), 0);
}

#[test]
fn p_9_8_another_scheme_is_a_request_with_no_key_text() {
    let rig = rig();
    for value in ["Basic dXNlcjpwYXNz", "Token abc", "Bearer"] {
        let reply = rig.get("/probe", &[("Authorization", value)]);
        assert_eq!(reply.status, 401, "{value}");
        assert_eq!(reply.header("www-authenticate"), Some("Bearer"), "{value}");
    }
    // The scheme has no case.
    let header = auth(KEY_OK).replace("Bearer", "bEaReR");
    assert_eq!(rig.get("/probe", &[("Authorization", &header)]).status, 200);
}

#[test]
fn p_9_8_two_authorization_headers_are_refused() {
    let rig = rig();
    let one = auth(KEY_OK);
    let two = auth(KEY_UNKNOWN);
    let reply = rig.get(
        "/probe",
        &[("Authorization", &one), ("Authorization", &two)],
    );
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("www-authenticate"), Some(INVALID));
    assert_eq!(rig.service.count(), 0);
}

#[test]
fn p_9_8_the_edge_never_redirects_a_request_that_has_a_key() {
    let rig = rig();
    let reply = rig.get(
        "/probe",
        &[
            ("Authorization", &auth(KEY_UNKNOWN)),
            ("Accept", "text/html"),
        ],
    );
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("location"), None);
}

#[test]
fn p_9_8_a_refusal_needs_no_part_of_the_body() {
    let rig = rig();
    for body in [b"{not json".to_vec(), vec![b'x'; 5_000_000]] {
        let reply = send(
            rig.addr(),
            "POST",
            "/probe",
            &[
                ("Authorization", &auth(KEY_UNKNOWN)),
                ("Content-Type", "application/json"),
            ],
            Some(&body),
        );
        assert_eq!(reply.status, 401, "{} bytes", body.len());
        assert!(reply.body.is_empty());
    }
    assert_eq!(rig.service.count(), 0);
}

#[test]
fn p_9_8_a_refusal_closes_the_connection_and_it_has_no_other_header_than_the_challenge() {
    let rig = rig();
    let reply = rig.get("/probe", &[]);
    let names: Vec<String> = reply
        .headers
        .iter()
        .map(|(n, _)| n.to_ascii_lowercase())
        .collect();
    assert_eq!(names, ["www-authenticate", "content-length", "connection"]);
    assert_eq!(reply.header("content-length"), Some("0"));
    assert_eq!(reply.header("connection"), Some("close"));
}

// ---- 8.3: the decision for access ----------------------------------------------------------------------------

#[test]
fn p_8_3_the_edge_asks_for_access_on_the_service_for_the_subject_of_the_key() {
    let rig = rig();
    assert_eq!(rig.with_key("/probe").status, 200);
    assert_eq!(
        rig.questions(),
        [(
            "key:ann-k1".to_owned(),
            "access".to_owned(),
            "service:datastore".to_owned()
        )]
    );
    let entries = rig.pdp.log();
    let question = entries.iter().find(|e| e.endpoint != "metadata").unwrap();
    assert!(!question.usage, "the question has no context.usage");
}

#[test]
fn p_8_3_a_key_with_a_good_text_and_no_access_gets_401_and_the_service_sees_nothing() {
    let rig = rig();
    let reply = rig.get("/probe", &[("Authorization", &auth(KEY_NO_ACCESS))]);
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("www-authenticate"), Some(INVALID));
    assert!(reply.body.is_empty());
    assert_eq!(rig.service.count(), 0);
    assert_eq!(rig.questions().len(), 1, "the edge asked the PDP one time");
}

#[test]
fn p_8_3_the_edge_asks_the_pdp_for_each_request_also_with_kept_tokens() {
    let rig = rig_with(
        Service::echo(),
        |c| c["token_cache_max_entries"] = json!(10),
        ED25519_PEM,
    );
    for _ in 0..3 {
        assert_eq!(rig.with_key("/probe").status, 200);
    }
    assert_eq!(rig.questions().len(), 3);
}

#[test]
fn p_8_3_a_pdp_that_does_not_answer_gives_503_and_no_request_for_the_service() {
    let rig = rig();
    rig.pdp.set_faults(
        fake_pdp::faults::read_faults_str(r#"{"failures": [{"kind": "error_503"}]}"#).unwrap(),
    );
    let reply = rig.with_key("/probe");
    assert_eq!(reply.status, 503);
    assert!(reply.body.is_empty());
    assert_eq!(rig.service.count(), 0);
    assert!(
        rig.log.text().contains("pdp_unavailable"),
        "{}",
        rig.log.text()
    );
}

#[test]
fn p_10_0_the_edge_sends_its_credential_to_the_pdp() {
    // A PDP that wants another credential refuses the edge: the answer is not valid, so 503.
    let rig = rig();
    drop(rig);
    let pdp = {
        let credential =
            fake_pdp::config::Credential::from_file_text("another-credential", "test").unwrap();
        fake_pdp::Server::from_value(
            &pdp_data(),
            fake_pdp::Options {
                credential: Some(credential),
                ..fake_pdp::Options::default()
            },
        )
        .unwrap()
        .start("127.0.0.1:0")
        .unwrap()
    };
    let rig = rig_on(pdp, Service::echo(), |_| {}, ED25519_PEM);
    assert_eq!(rig.with_key("/probe").status, 503);
    assert_eq!(rig.service.count(), 0);
}

#[test]
fn p_3_1_a_person_has_a_text_with_no_owner() {
    let rig = rig();
    let reply = rig.get("/probe", &[("Authorization", &auth(PERSON_TEXT))]);
    assert_eq!(reply.status, 200);
    let seen = rig.service.requests();
    let (_, claims) = decode_token(seen[0].header(HEADER).unwrap());
    assert_eq!(claims["sub"], "ann");
    assert!(claims.get("owner").is_none());
    // A person without `access` is refused as a key is.
    let reply = rig.get("/probe", &[("Authorization", &auth(PERSON_NO_ACCESS))]);
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("www-authenticate"), Some(INVALID));
}

// ---- 9.1: the request for the service ------------------------------------------------------------------------

#[test]
fn p_9_1_the_key_text_and_the_copies_of_the_token_header_never_reach_the_service() {
    let rig = rig();
    let reply = rig.get(
        "/probe?x=1",
        &[
            ("Authorization", &auth(KEY_OK)),
            (HEADER, "forged.forged.forged"),
            ("x-identity-token", "forged-two"),
            ("Accept", "application/json"),
        ],
    );
    assert_eq!(reply.status, 200);
    let seen = &rig.service.requests()[0];
    assert!(seen.header("authorization").is_none());
    for (name, value) in &seen.headers {
        assert!(!value.contains(KEY_OK), "{name}");
        assert!(!value.contains("forged"), "{name}");
    }
    let tokens = seen.headers_named(HEADER);
    assert_eq!(tokens.len(), 1, "one token header: {tokens:?}");
    assert_eq!(tokens[0].split('.').count(), 3);
    assert_eq!(seen.header("accept"), Some("application/json"));
    assert!(String::from_utf8_lossy(&seen.body).is_empty());
}

#[test]
fn p_9_1_a_request_with_the_token_header_and_no_good_key_never_reaches_the_service() {
    let rig = rig();
    assert_eq!(
        rig.get("/probe", &[(HEADER, "forged.forged.forged")])
            .status,
        401
    );
    let unknown = auth(KEY_UNKNOWN);
    assert_eq!(
        rig.get(
            "/probe",
            &[
                ("Authorization", &unknown),
                (HEADER, "forged.forged.forged")
            ]
        )
        .status,
        401
    );
    assert_eq!(rig.service.count(), 0);
}

#[test]
fn p_9_1_the_method_the_target_and_the_body_go_through_as_they_are() {
    let rig = rig();
    let body = b"{\"rows\": [1, 2, 3]}";
    let reply = send(
        rig.addr(),
        "POST",
        "/hosts/prod/databases/a%2Fb/tables/t?limit=5&x=%20",
        &[
            ("Authorization", &auth(KEY_OK)),
            ("Content-Type", "application/json"),
        ],
        Some(body),
    );
    assert_eq!(reply.status, 200);
    assert_eq!(
        reply.json(),
        json!({"method": "POST", "target": "/hosts/prod/databases/a%2Fb/tables/t?limit=5&x=%20"})
    );
    let seen = &rig.service.requests()[0];
    assert_eq!(seen.body, body);
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(seen.header("content-length"), Some("19"));
}

#[test]
fn p_9_1_a_chunked_body_reaches_the_service_with_a_length() {
    let rig = rig();
    let mut stream = TcpStream::connect(rig.addr()).unwrap();
    let head = format!(
        "POST /w HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n3\r\nabc\r\n4\r\ndefg\r\n0\r\n\r\n",
        auth(KEY_OK)
    );
    stream.write_all(head.as_bytes()).unwrap();
    let reply = read_reply(&mut stream, false);
    assert_eq!(reply.status, 200);
    let seen = &rig.service.requests()[0];
    assert_eq!(seen.body, b"abcdefg");
    assert!(seen.header("transfer-encoding").is_none());
    assert_eq!(seen.header("content-length"), Some("7"));
}

#[test]
fn p_9_1_the_edge_answers_100_continue_after_it_accepted_the_request() {
    let rig = rig();
    let mut stream = TcpStream::connect(rig.addr()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let head = format!(
        "POST /w HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nContent-Length: 3\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n",
        auth(KEY_OK)
    );
    stream.write_all(head.as_bytes()).unwrap();
    let mut got = [0_u8; 64];
    let n = stream.read(&mut got).unwrap();
    assert!(String::from_utf8_lossy(&got[..n]).starts_with("HTTP/1.1 100 Continue\r\n\r\n"));
    stream.write_all(b"abc").unwrap();
    let reply = read_reply(&mut stream, false);
    assert_eq!(reply.status, 200);
    assert_eq!(rig.service.requests()[0].body, b"abc");
    // A refused request gets no 100 Continue.
    let mut stream = TcpStream::connect(rig.addr()).unwrap();
    let head = format!(
        "POST /w HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\n",
        auth(KEY_UNKNOWN)
    );
    stream.write_all(head.as_bytes()).unwrap();
    let reply = read_reply(&mut stream, false);
    assert_eq!(reply.status, 401);
}

#[test]
fn p_9_1_a_body_above_the_bound_gets_413_after_the_key_is_good_and_never_before() {
    let rig = rig_with(
        Service::echo(),
        |c| c["max_body_bytes"] = json!(100),
        ED25519_PEM,
    );
    let body = vec![b'x'; 101];
    let good = send(
        rig.addr(),
        "POST",
        "/w",
        &[("Authorization", &auth(KEY_OK))],
        Some(&body),
    );
    assert_eq!(good.status, 413);
    let bad = send(
        rig.addr(),
        "POST",
        "/w",
        &[("Authorization", &auth(KEY_UNKNOWN))],
        Some(&body),
    );
    assert_eq!(bad.status, 401);
    assert_eq!(rig.service.count(), 0);
}

// ---- 9.2, 9.3, 9.4: the identity token -------------------------------------------------------------------------

#[test]
fn p_9_3_the_token_of_a_key_has_the_claims_and_a_service_accepts_it() {
    let rig = rig();
    assert_eq!(rig.with_key("/probe").status, 200);
    let token = rig.service.requests()[0].header(HEADER).unwrap().to_owned();
    let (header, claims) = decode_token(&token);
    assert_eq!(header["alg"], "Ed25519");
    assert_eq!(header["typ"], "JWT");
    assert_eq!(header["kid"], "edge-ed25519");
    assert_eq!(claims["iss"], ISSUER);
    assert_eq!(claims["sub"], "key:ann-k1");
    assert_eq!(claims["aud"], SERVICE);
    assert_eq!(claims["owner"], "ann");
    assert_eq!(claims["iat"], NOW);
    assert_eq!(claims["exp"], NOW + 60);
    assert!(claims.get("act").is_none());
    assert!(!token.contains(KEY_OK));
    assert!(!claims.to_string().contains(KEY_OK));
    // The core checks the token with the public key, as a service does.
    let verified = verify(&token, &rig.settings_keys, &policy(), NOW + 1).unwrap();
    assert_eq!(verified.claims.sub, "key:ann-k1");
}

#[test]
fn p_9_2_an_es256_key_gives_a_token_with_the_header_es256() {
    let rig = rig_with(
        Service::echo(),
        |c| c["signing"]["kid"] = json!("edge-es256"),
        ES256_PEM,
    );
    assert_eq!(rig.with_key("/probe").status, 200);
    let token = rig.service.requests()[0].header(HEADER).unwrap().to_owned();
    let (header, _) = decode_token(&token);
    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "JWT");
    assert!(verify(&token, &rig.settings_keys, &policy(), NOW + 1).is_ok());
}

#[test]
fn p_9_4_the_header_has_no_kid_when_the_configuration_has_none() {
    let rig = rig_with(
        Service::echo(),
        |c| {
            c["signing"].as_object_mut().unwrap().remove("kid");
        },
        ED25519_PEM,
    );
    assert_eq!(rig.with_key("/probe").status, 200);
    let (header, _) = decode_token(rig.service.requests()[0].header(HEADER).unwrap());
    assert!(header.get("kid").is_none());
}

#[test]
fn p_9_2_the_life_of_the_token_is_the_configured_life() {
    let rig = rig_with(
        Service::echo(),
        |c| c["token_life_seconds"] = json!(300),
        ED25519_PEM,
    );
    assert_eq!(rig.with_key("/probe").status, 200);
    let (_, claims) = decode_token(rig.service.requests()[0].header(HEADER).unwrap());
    assert_eq!(
        claims["exp"].as_u64().unwrap() - claims["iat"].as_u64().unwrap(),
        300
    );
}

// ---- 9.9: the kept tokens --------------------------------------------------------------------------------------

fn token_of(rig: &Rig, index: usize) -> String {
    rig.service.requests()[index]
        .header(HEADER)
        .unwrap()
        .to_owned()
}

#[test]
fn p_9_9_with_no_table_each_request_gets_a_new_token() {
    let rig = rig();
    rig.with_key("/a");
    rig.clock.advance_millis(1000);
    rig.with_key("/b");
    assert_ne!(token_of(&rig, 0), token_of(&rig, 1));
    assert_eq!(rig.inner.kept_tokens(), 0);
}

#[test]
fn p_9_9_a_kept_token_is_given_again_to_the_same_subject_until_its_margin() {
    let rig = rig_with(
        Service::echo(),
        |c| c["token_cache_max_entries"] = json!(10),
        ED25519_PEM,
    );
    rig.with_key("/a");
    rig.clock.advance_millis(10_000);
    rig.with_key("/b");
    assert_eq!(token_of(&rig, 0), token_of(&rig, 1));
    // The life is 60 s. The margin is 15 s. At 45 s the edge signs a new token.
    rig.clock.advance_millis(40_000);
    rig.with_key("/c");
    assert_ne!(token_of(&rig, 1), token_of(&rig, 2));
    let (_, claims) = decode_token(&token_of(&rig, 2));
    assert_eq!(claims["iat"].as_u64().unwrap(), NOW + 50);
    assert_eq!(rig.inner.kept_tokens(), 1);
}

#[test]
fn p_9_9_a_kept_token_never_goes_to_a_client_that_the_edge_did_not_authenticate() {
    let rig = rig_with(
        Service::echo(),
        |c| c["token_cache_max_entries"] = json!(10),
        ED25519_PEM,
    );
    assert_eq!(rig.with_key("/a").status, 200);
    assert_eq!(rig.get("/a", &[]).status, 401);
    assert_eq!(
        rig.get("/a", &[("Authorization", &auth(KEY_UNKNOWN))])
            .status,
        401
    );
    assert_eq!(
        rig.get("/a", &[("Authorization", &auth(KEY_NO_ACCESS))])
            .status,
        401
    );
    assert_eq!(rig.service.count(), 1);
}

#[test]
fn p_9_9_a_kept_token_is_for_one_subject_and_the_table_has_a_bound() {
    let rig = rig_with(
        Service::echo(),
        |c| c["token_cache_max_entries"] = json!(1),
        ED25519_PEM,
    );
    rig.with_key("/a");
    rig.get("/a", &[("Authorization", &auth(PERSON_TEXT))]);
    assert_eq!(rig.inner.kept_tokens(), 1);
    let (_, first) = decode_token(&token_of(&rig, 0));
    let (_, second) = decode_token(&token_of(&rig, 1));
    assert_eq!(first["sub"], "key:ann-k1");
    assert_eq!(second["sub"], "ann");
}

#[test]
fn p_9_9_a_subject_that_lost_access_gets_no_kept_token() {
    let rig = rig_with(
        Service::echo(),
        |c| c["token_cache_max_entries"] = json!(10),
        ED25519_PEM,
    );
    assert_eq!(rig.with_key("/a").status, 200);
    // The PDP loads data in which the key has no access. The edge asks again.
    let mut data = pdp_data();
    data["subjects"]
        .as_array_mut()
        .unwrap()
        .retain(|s| s["id"] != "key:ann-k1");
    let pdp = start_pdp_with(&data);
    let rig2 = rig_on(
        pdp,
        Service::echo(),
        |c| c["token_cache_max_entries"] = json!(10),
        ED25519_PEM,
    );
    assert_eq!(rig2.with_key("/a").status, 401);
    assert_eq!(rig2.service.count(), 0);
}

// ---- MCP binding 6: the refusals for MCP ---------------------------------------------------------------------

fn mcp_headers(key: Option<&str>) -> Vec<(&'static str, &str)> {
    let mut headers = vec![
        ("Content-Type", "application/json"),
        ("Accept", "application/json, text/event-stream"),
        ("MCP-Protocol-Version", "2026-07-28"),
    ];
    if let Some(key) = key {
        headers.push(("Authorization", key));
    }
    headers
}

const PING: &[u8] = br#"{"jsonrpc":"2.0","id":7,"method":"ping","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}"#;

#[test]
fn mcp_6_1_a_refused_mcp_request_has_an_empty_body_for_each_method_of_http() {
    let rig = rig();
    let unknown = auth(KEY_UNKNOWN);
    for (method, body) in [
        ("POST", Some(PING)),
        ("POST", Some(&b"{not json"[..])),
        ("GET", None),
        ("DELETE", None),
        ("PUT", None),
    ] {
        let reply = send(
            rig.addr(),
            method,
            "/mcp",
            &mcp_headers(Some(&unknown)),
            body,
        );
        assert_eq!(reply.status, 401, "{method}");
        assert_eq!(reply.header("www-authenticate"), Some(INVALID), "{method}");
        assert!(reply.body.is_empty(), "{method}");
    }
    assert_eq!(rig.service.count(), 0);
}

#[test]
fn mcp_6_3_the_challenge_has_no_resource_metadata() {
    let rig = rig();
    let none = send(rig.addr(), "POST", "/mcp", &mcp_headers(None), Some(PING));
    assert_eq!(none.status, 401);
    assert_eq!(none.header("www-authenticate"), Some("Bearer"));
    let unknown = auth(KEY_UNKNOWN);
    let bad = send(
        rig.addr(),
        "POST",
        "/mcp",
        &mcp_headers(Some(&unknown)),
        Some(PING),
    );
    assert!(
        !bad.header("www-authenticate")
            .unwrap()
            .contains("resource_metadata")
    );
    let denied = auth(KEY_NO_ACCESS);
    let reply = send(
        rig.addr(),
        "POST",
        "/mcp",
        &mcp_headers(Some(&denied)),
        Some(PING),
    );
    assert_eq!(reply.status, 401);
    assert!(reply.body.is_empty());
}

#[test]
fn mcp_6_2_the_edge_sends_each_method_with_a_good_key_to_the_service_and_answers_no_mcp_method() {
    let service = Service::start(|request, stream| {
        // The service answers 404, 405 and 200 by itself. The edge must not change them.
        let (status, text) = match request.method.as_str() {
            "GET" => (405, "Method Not Allowed"),
            "DELETE" => (404, "Not Found"),
            _ => (200, "OK"),
        };
        let _ = stream.write_all(
            format!(
                "HTTP/1.1 {status} {text}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}"
            )
            .as_bytes(),
        );
    });
    let rig = rig_with(service, |_| {}, ED25519_PEM);
    let key = auth(KEY_OK);
    for (method, status) in [("POST", 200), ("GET", 405), ("DELETE", 404)] {
        let body = (method == "POST").then_some(PING);
        let reply = send(rig.addr(), method, "/mcp", &mcp_headers(Some(&key)), body);
        assert_eq!(reply.status, status, "{method}");
        assert_eq!(reply.text(), "{}");
    }
    assert_eq!(rig.service.count(), 3);
    let seen = rig.service.requests();
    assert_eq!(seen[0].body, PING);
    assert_eq!(seen[0].header("mcp-protocol-version"), Some("2026-07-28"));
    let (_, claims) = decode_token(seen[0].header(HEADER).unwrap());
    assert_eq!(claims["sub"], "key:ann-k1");
}

// ---- The relay of the answer -----------------------------------------------------------------------------------

#[test]
fn a_stream_of_events_goes_to_the_client_chunk_by_chunk() {
    let service = Service::start(|_, stream| {
        let _ = stream.write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        );
        let _ = stream.write_all(b"b\r\ndata: one\n\n\r\n");
        let _ = stream.flush();
        std::thread::sleep(Duration::from_millis(1500));
        let _ = stream.write_all(b"b\r\ndata: two\n\n\r\n0\r\n\r\n");
    });
    let rig = rig_with(service, |_| {}, ED25519_PEM);
    let started = Instant::now();
    let mut stream = TcpStream::connect(rig.addr()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let head = format!(
        "GET /mcp HTTP/1.1\r\nHost: x\r\nAccept: text/event-stream\r\nAuthorization: {}\r\nConnection: close\r\n\r\n",
        auth(KEY_OK)
    );
    stream.write_all(head.as_bytes()).unwrap();
    let mut got = Vec::new();
    let mut chunk = [0_u8; 1024];
    // The first event must arrive before the service ends the stream.
    while !String::from_utf8_lossy(&got).contains("data: one") {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0, "the stream ended before the first event");
        got.extend_from_slice(&chunk[..n]);
    }
    assert!(
        started.elapsed() < Duration::from_millis(1200),
        "{:?}",
        started.elapsed()
    );
    while !String::from_utf8_lossy(&got).contains("0\r\n\r\n") {
        let n = stream.read(&mut chunk).unwrap();
        assert!(n > 0);
        got.extend_from_slice(&chunk[..n]);
    }
    assert!(String::from_utf8_lossy(&got).contains("data: two"));
}

#[test]
fn a_service_that_is_absent_gives_502_with_an_empty_body() {
    let mut rig = rig();
    // Stop the service. Its port is closed, and a new service has another port.
    drop(std::mem::replace(&mut rig.service, Service::echo()));
    let reply = rig.with_key("/probe");
    assert_eq!(reply.status, 502);
    assert!(reply.body.is_empty());
    assert_eq!(rig.service.count(), 0);
}

#[test]
fn two_requests_use_one_connection_of_the_client() {
    let rig = rig();
    let mut stream = TcpStream::connect(rig.addr()).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    for target in ["/one", "/two"] {
        let request = format!(
            "GET {target} HTTP/1.1\r\nHost: x\r\nAuthorization: {}\r\n\r\n",
            auth(KEY_OK)
        );
        stream.write_all(request.as_bytes()).unwrap();
        let reply = read_reply(&mut stream, false);
        assert_eq!(reply.status, 200);
        assert_eq!(reply.header("connection"), Some("keep-alive"));
        assert_eq!(reply.json()["target"], target);
    }
}

#[test]
fn a_bad_http_request_gets_400_and_the_connection_closes() {
    let rig = rig();
    let mut stream = TcpStream::connect(rig.addr()).unwrap();
    stream.write_all(b"GARBAGE\r\n\r\n").unwrap();
    let reply = read_reply(&mut stream, false);
    assert_eq!(reply.status, 400);
    assert!(reply.body.is_empty());
}

// ---- The log ---------------------------------------------------------------------------------------------------

#[test]
fn the_log_has_the_method_the_path_and_the_status_and_never_a_key_a_token_or_a_query() {
    let rig = rig();
    rig.get(
        "/probe?secret=1",
        &[("Authorization", &auth(KEY_OK)), ("Cookie", "c=1")],
    );
    rig.get("/probe", &[("Authorization", &auth(KEY_UNKNOWN))]);
    rig.get("/probe", &[]);
    rig.get("/other", &[("Authorization", &auth(KEY_NO_ACCESS))]);
    let log = rig.log.text();
    assert!(log.contains("GET /probe 200 (subject key:ann-k1)"), "{log}");
    assert!(log.contains("GET /probe 401 (unknown_key)"), "{log}");
    assert!(log.contains("GET /probe 401 (no_authorization)"), "{log}");
    assert!(log.contains("GET /other 401 (no_access)"), "{log}");
    for secret in ["pk_live_", "secret=1", "c=1", "eyJ", CREDENTIAL] {
        assert!(!log.contains(secret), "{secret} in {log}");
    }
}

#[test]
fn the_edge_stops_on_request() {
    let rig = rig();
    let addr = rig.addr();
    rig.edge.shutdown();
    assert!(TcpStream::connect_timeout(&addr, Duration::from_millis(300)).is_err());
}

#[test]
fn a_set_of_keys_that_the_service_trusts_can_be_built_from_the_signing_key() {
    // The public key of the test edge is in the example JWK Set of the conformance data.
    let text = include_str!("../../access-conformance/examples/edge-jwks.json");
    let keys = KeySet::from_jwks_str(text).unwrap();
    let rig = rig();
    rig.with_key("/probe");
    let token = token_of(&rig, 0);
    assert!(verify(&token, &keys, &policy(), NOW + 1).is_ok());
}
