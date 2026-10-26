//! The credential of the PEP (protocol 10.0 step 4, 12): `Authorization: Bearer`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use common::*;
use fake_pdp::{Credential, Options};
use serde_json::json;
use sha2::{Digest, Sha256};

const SECRET: &str = "s3cret-pep-credential-0123456789";

fn hex(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn with_credential(capture: &Capture) -> fake_pdp::RunningServer {
    start_with(
        &datastore(),
        Options {
            credential: Some(
                Credential::from_file_text(&format!("{SECRET}\n"), "file:/run/pep").unwrap(),
            ),
            admin: true,
            log: Some(Box::new(capture.clone())),
            diagnostics: Some(Box::new(capture.clone())),
            ..Options::default()
        },
    )
}

#[test]
fn a_question_without_the_credential_gets_http_401() {
    let capture = Capture::default();
    let server = with_credential(&capture);
    let q = question("alice", "data.read", TEST1, false);
    let reply = once_json(server.local_addr(), EVALUATION, &q);
    assert_eq!(reply.status, 401);
    assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
    assert_eq!(reply.text(), r#"{"error":"Unauthorized"}"#);
    for header in [
        "Bearer wrong",
        "Bearer ",
        "Bearer",
        "Basic czNjcmV0",
        SECRET,
        &format!("Bearer {SECRET}x"),
        &format!("Bearer {}", SECRET.to_uppercase()),
    ] {
        let reply = Client::connect(server.local_addr()).post_json_with(
            EVALUATION,
            &[("Authorization", header)],
            &q,
        );
        assert_eq!(reply.status, 401, "{header}");
    }
    assert!(server.log().is_empty());
}

#[test]
fn a_question_with_the_credential_gets_its_answer() {
    let capture = Capture::default();
    let server = with_credential(&capture);
    let q = question("alice", "data.read", TEST1, false);
    for header in [format!("Bearer {SECRET}"), format!("bearer {SECRET}")] {
        let reply = Client::connect(server.local_addr()).post_json_with(
            EVALUATION,
            &[("Authorization", &header)],
            &q,
        );
        assert_eq!(reply.status, 200, "{header}");
        assert_eq!(reply.json()["decision"], true);
    }
    let reply = Client::connect(server.local_addr()).post_json_with(
        EVALUATIONS,
        &[("Authorization", &format!("Bearer {SECRET}"))],
        &json!({"evaluations": [q]}),
    );
    assert_eq!(reply.status, 200);
}

#[test]
fn the_metadata_needs_no_credential() {
    let capture = Capture::default();
    let server = with_credential(&capture);
    let reply = once(
        server.local_addr(),
        "GET",
        "/.well-known/authzen-configuration",
        &[],
        None,
    );
    assert_eq!(reply.status, 200);
}

#[test]
fn the_admin_endpoints_need_the_credential_too() {
    let capture = Capture::default();
    let server = with_credential(&capture);
    let addr = server.local_addr();
    assert_eq!(once(addr, "GET", "/__fake/clock", &[], None).status, 401);
    let reply = once(
        addr,
        "GET",
        "/__fake/clock",
        &[("Authorization", &format!("Bearer {SECRET}"))],
        None,
    );
    assert_eq!(reply.status, 200);
}

#[test]
fn the_credential_never_goes_to_the_log_or_to_the_diagnostics() {
    let capture = Capture::default();
    let server = with_credential(&capture);
    let q = question("alice", "data.read", TEST1, true);
    let header = format!("Bearer {SECRET}");
    for _ in 0..3 {
        Client::connect(server.local_addr()).post_json_with(
            EVALUATION,
            &[("Authorization", &header)],
            &q,
        );
    }
    Client::connect(server.local_addr()).post_json_with(
        EVALUATION,
        &[("Authorization", "Bearer another-secret-value")],
        &q,
    );
    let text = capture.text();
    assert!(text.contains("q1  alice"), "{text}");
    assert!(text.contains("rejected 401"), "{text}");
    assert!(!text.contains(SECRET));
    assert!(!text.contains("another-secret-value"));
    let entries = serde_json::to_string(
        &server
            .log()
            .iter()
            .map(|e| e.to_value())
            .collect::<Vec<_>>(),
    )
    .unwrap();
    assert!(!entries.contains(SECRET));
    assert!(
        !format!(
            "{:?}",
            Credential::from_file_text(SECRET, "file:/x").unwrap()
        )
        .contains(SECRET)
    );
}

#[test]
fn p_12_each_service_has_its_own_credential_by_digest() {
    let mut data = datastore();
    data["services"][0]["credential_sha256"] = json!(hex("datastore-token"));
    data["services"].as_array_mut().unwrap().push(json!({
        "id": "other",
        "credential_sha256": hex("other-token")
    }));
    let server = start(&data);
    let q = question("alice", "data.read", TEST1, false);
    let try_with = |token: Option<&str>| {
        let header = token.map(|t| format!("Bearer {t}"));
        let headers: Vec<(&str, &str)> = header
            .iter()
            .map(|h| ("Authorization", h.as_str()))
            .collect();
        Client::connect(server.local_addr()).post_json_with(EVALUATION, &headers, &q)
    };
    assert_eq!(try_with(None).status, 401);
    assert_eq!(try_with(Some("nope")).status, 401);
    let own = try_with(Some("datastore-token"));
    assert_eq!(own.status, 200);
    assert_eq!(own.json()["decision"], true);
    // The PDP answers each PEP only for its own service (12).
    let foreign = try_with(Some("other-token"));
    assert_eq!(foreign.status, 200);
    assert_eq!(
        foreign.json(),
        json!({"decision": false, "context": {"reason": "invalid_resource"}})
    );
}

#[test]
fn p_12_the_global_credential_reaches_each_service() {
    let mut data = datastore();
    data["services"][0]["credential_sha256"] = json!(hex("datastore-token"));
    let server = start_with(
        &data,
        Options {
            credential: Some(Credential::from_file_text("global", "file:/g").unwrap()),
            ..Options::default()
        },
    );
    let q = question("alice", "data.read", TEST1, false);
    for token in ["global", "datastore-token"] {
        let reply = Client::connect(server.local_addr()).post_json_with(
            EVALUATION,
            &[("Authorization", &format!("Bearer {token}"))],
            &q,
        );
        assert_eq!(reply.json()["decision"], true, "{token}");
    }
}
